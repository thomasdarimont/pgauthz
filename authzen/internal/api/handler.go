package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"thomasdarimont.de/authz/authzen/internal/authz"
	"thomasdarimont.de/authz/authzen/internal/config"
)

const defaultPageSize = 100

// Handler wires all AuthZEN endpoints to a backend.
type Handler struct {
	backend authz.Backend
	cfg     *config.Config
}

func NewHandler(backend authz.Backend, cfg *config.Config) *Handler {
	return &Handler{backend: backend, cfg: cfg}
}

// NewRouter returns a fully configured HTTP handler with middleware.
func NewRouter(backend authz.Backend, cfg *config.Config, jwtMW *JWTMiddleware) http.Handler {
	h := NewHandler(backend, cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /access/v1/evaluation", h.Evaluation)
	mux.HandleFunc("POST /access/v1/evaluations", h.Evaluations)
	mux.HandleFunc("POST /access/v1/search/subject", h.SearchSubject)
	mux.HandleFunc("POST /access/v1/search/resource", h.SearchResource)
	mux.HandleFunc("POST /access/v1/search/action", h.SearchAction)
	mux.HandleFunc("GET /.well-known/authzen-configuration", h.WellKnown)
	mux.HandleFunc("GET /healthz", h.Healthz)

	var handler http.Handler = mux
	handler = jwtMW.Middleware(handler)
	handler = RequestID(handler)
	handler = Logging(handler)
	handler = Recovery(handler)

	return handler
}

func (h *Handler) store(r *http.Request) string {
	if s := r.Header.Get(h.cfg.StoreHeader); s != "" {
		return s
	}
	return h.cfg.DefaultStore
}

// resolveSubject merges JWT-derived subject with request body subject.
// Body subject takes precedence (AuthZEN requires explicit subject).
func resolveSubject(r *http.Request, body Subject) (subjectType, subjectID string, err error) {
	if body.Type != "" && body.ID != "" {
		return body.Type, body.ID, nil
	}
	// Fall back to JWT-derived subject
	jwtType, jwtID := SubjectFromContext(r.Context())
	subjectType = body.Type
	if subjectType == "" {
		subjectType = jwtType
	}
	subjectID = body.ID
	if subjectID == "" {
		subjectID = jwtID
	}
	if subjectType == "" || subjectID == "" {
		return "", "", fmt.Errorf("subject.type and subject.id are required")
	}
	return subjectType, subjectID, nil
}

// Evaluation handles POST /access/v1/evaluation
func (h *Handler) Evaluation(w http.ResponseWriter, r *http.Request) {
	var req EvalRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	subjectType, subjectID, err := resolveSubject(r, req.Subject)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	if req.Action.Name == "" {
		writeBadRequest(w, "action.name is required")
		return
	}
	if req.Resource.Type == "" || req.Resource.ID == "" {
		writeBadRequest(w, "resource.type and resource.id are required")
		return
	}

	decision, err := h.backend.CheckAccess(r.Context(), authz.EvalRequest{
		Store:       h.store(r),
		SubjectType: subjectType,
		SubjectID:   subjectID,
		Action:      req.Action.Name,
		ObjectType:  req.Resource.Type,
		ObjectID:    req.Resource.ID,
		Context:     req.Context,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, EvalResponseBody{Decision: decision})
}

// Evaluations handles POST /access/v1/evaluations
func (h *Handler) Evaluations(w http.ResponseWriter, r *http.Request) {
	var req EvalsBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	if len(req.Evaluations) == 0 {
		writeBadRequest(w, "evaluations array is required and must not be empty")
		return
	}

	semantic := req.Semantic
	if semantic == "" {
		semantic = "execute_all"
	}
	switch semantic {
	case "execute_all", "deny_on_first_deny", "permit_on_first_permit":
	default:
		writeBadRequest(w, "invalid semantic: "+semantic)
		return
	}

	store := h.store(r)
	jwtType, jwtID := SubjectFromContext(r.Context())

	// Build individual eval requests, merging shared subject/action/resource
	evals := make([]authz.EvalRequest, len(req.Evaluations))
	for i, e := range req.Evaluations {
		subType := e.Subject.Type
		if subType == "" && req.Subject != nil {
			subType = req.Subject.Type
		}
		if subType == "" {
			subType = jwtType
		}

		subID := e.Subject.ID
		if subID == "" && req.Subject != nil {
			subID = req.Subject.ID
		}
		if subID == "" {
			subID = jwtID
		}

		if subType == "" || subID == "" {
			writeBadRequest(w, fmt.Sprintf("evaluation[%d]: subject.type and subject.id are required", i))
			return
		}

		action := e.Action.Name
		if action == "" && req.Action != nil {
			action = req.Action.Name
		}
		if action == "" {
			writeBadRequest(w, fmt.Sprintf("evaluation[%d]: action.name is required", i))
			return
		}

		resType := e.Resource.Type
		if resType == "" && req.Resource != nil {
			resType = req.Resource.Type
		}
		resID := e.Resource.ID
		if resID == "" && req.Resource != nil {
			resID = req.Resource.ID
		}
		if resType == "" || resID == "" {
			writeBadRequest(w, fmt.Sprintf("evaluation[%d]: resource.type and resource.id are required", i))
			return
		}

		evals[i] = authz.EvalRequest{
			Store:       store,
			SubjectType: subType,
			SubjectID:   subID,
			Action:      action,
			ObjectType:  resType,
			ObjectID:    resID,
		}
	}

	results, err := h.backend.CheckAccessBatch(r.Context(), store, evals, req.Context, semantic)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	resp := EvalsBatchResponse{Evaluations: make([]EvalResponseBody, len(results))}
	for i, res := range results {
		resp.Evaluations[i] = EvalResponseBody{Decision: res.Decision}
	}

	writeJSON(w, http.StatusOK, resp)
}

// SearchSubject handles POST /access/v1/search/subject
func (h *Handler) SearchSubject(w http.ResponseWriter, r *http.Request) {
	var req SearchSubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	if req.Subject.Type == "" {
		writeBadRequest(w, "subject.type is required for subject search")
		return
	}
	if req.Action.Name == "" {
		writeBadRequest(w, "action.name is required")
		return
	}
	if req.Resource.Type == "" || req.Resource.ID == "" {
		writeBadRequest(w, "resource.type and resource.id are required")
		return
	}

	page := decodePage(req.Page)

	subjects, pageResp, err := h.backend.ListSubjects(r.Context(), h.store(r),
		req.Subject.Type, req.Action.Name, req.Resource.Type, req.Resource.ID,
		req.Context, page)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	resp := SearchSubjectResponse{
		Results: make([]SubjectResult, len(subjects)),
	}
	for i, id := range subjects {
		resp.Results[i] = SubjectResult{Subject: Subject{Type: req.Subject.Type, ID: id}}
	}
	if pageResp != nil && pageResp.HasMore {
		resp.Page = &PageResult{NextToken: pageResp.NextToken}
	}

	writeJSON(w, http.StatusOK, resp)
}

// SearchResource handles POST /access/v1/search/resource
func (h *Handler) SearchResource(w http.ResponseWriter, r *http.Request) {
	var req SearchResourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	subjectType, subjectID, err := resolveSubject(r, req.Subject)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	if req.Action.Name == "" {
		writeBadRequest(w, "action.name is required")
		return
	}
	if req.Resource.Type == "" {
		writeBadRequest(w, "resource.type is required")
		return
	}

	page := decodePage(req.Page)

	resources, pageResp, err := h.backend.ListResources(r.Context(), h.store(r),
		subjectType, subjectID, req.Action.Name, req.Resource.Type,
		req.Context, page)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	resp := SearchResourceResponse{
		Results: make([]ResourceResult, len(resources)),
	}
	for i, id := range resources {
		resp.Results[i] = ResourceResult{Resource: Resource{Type: req.Resource.Type, ID: id}}
	}
	if pageResp != nil && pageResp.HasMore {
		resp.Page = &PageResult{NextToken: pageResp.NextToken}
	}

	writeJSON(w, http.StatusOK, resp)
}

// SearchAction handles POST /access/v1/search/action
func (h *Handler) SearchAction(w http.ResponseWriter, r *http.Request) {
	var req SearchActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	subjectType, subjectID, err := resolveSubject(r, req.Subject)
	if err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	if req.Resource.Type == "" || req.Resource.ID == "" {
		writeBadRequest(w, "resource.type and resource.id are required")
		return
	}

	actions, err := h.backend.ListActions(r.Context(), h.store(r),
		subjectType, subjectID, req.Resource.Type, req.Resource.ID,
		req.Context)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	resp := SearchActionResponse{
		Results: make([]ActionResult, len(actions)),
	}
	for i, a := range actions {
		resp.Results[i] = ActionResult{Action: Action{Name: a}}
	}

	writeJSON(w, http.StatusOK, resp)
}

// WellKnown handles GET /.well-known/authzen-configuration
func (h *Handler) WellKnown(w http.ResponseWriter, r *http.Request) {
	base := h.cfg.BaseURL
	if base == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}

	writeJSON(w, http.StatusOK, WellKnownResponse{
		EvaluationEndpoint:     base + "/access/v1/evaluation",
		EvaluationsEndpoint:    base + "/access/v1/evaluations",
		SubjectSearchEndpoint:  base + "/access/v1/search/subject",
		ResourceSearchEndpoint: base + "/access/v1/search/resource",
		ActionSearchEndpoint:   base + "/access/v1/search/action",
		APIVersion:             "1.0",
		Capabilities:           []string{"evaluation", "evaluations", "subject-search", "resource-search", "action-search"},
	})
}

// Healthz handles GET /healthz
func (h *Handler) Healthz(w http.ResponseWriter, r *http.Request) {
	if err := h.backend.Healthz(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "unhealthy: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Pagination helpers ---

type pageState struct {
	O int `json:"o"`
}

func decodePage(p *PageToken) *authz.PageRequest {
	if p == nil {
		return nil
	}
	size := p.Size
	if size <= 0 {
		size = defaultPageSize
	}
	offset := 0
	if p.Token != "" {
		data, err := base64.RawURLEncoding.DecodeString(p.Token)
		if err == nil {
			var state pageState
			if json.Unmarshal(data, &state) == nil {
				offset = state.O
			}
		}
	}
	return &authz.PageRequest{Limit: size, Offset: offset}
}

func EncodePage(offset int) string {
	data, _ := json.Marshal(pageState{O: offset})
	return base64.RawURLEncoding.EncodeToString(data)
}

// --- JSON helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
