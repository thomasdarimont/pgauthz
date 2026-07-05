package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

var (
	errSubjectRequired  = errors.New("subject.type and subject.id are required")
	errSubjectForbidden = errors.New("request subject does not match the authenticated subject (body-subject override is disabled)")
)

const defaultPageSize = 100

// Handler wires all AuthZEN endpoints to a backend.
type Handler struct {
	// issuerStores maps a verified issuer to the store patterns (anchored
	// regexes) its tokens may access. Only issuers with a non-empty `stores`
	// list appear here; absent = unrestricted.
	issuerStores map[string][]*regexp.Regexp
	backend      authz.Backend
	cfg          *config.Config
}

func NewHandler(backend authz.Backend, cfg *config.Config) *Handler {
	h := &Handler{backend: backend, cfg: cfg, issuerStores: map[string][]*regexp.Regexp{}}
	for _, iss := range cfg.Issuers {
		if iss.Issuer == "" || len(iss.Stores) == 0 {
			continue
		}
		pats := make([]*regexp.Regexp, len(iss.Stores))
		for i, p := range iss.Stores {
			// validated in config.Load — anchored so plain names match exactly
			pats[i] = regexp.MustCompile("^(?:" + p + ")$")
		}
		h.issuerStores[iss.Issuer] = pats
	}
	return h
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

	// Native pgauthz API (vendor-specific, separate from spec-pure AuthZEN).
	// Requires the direct backend (authz.NativeReader); 501 on compat-opa.
	mux.HandleFunc("POST /pgauthz/v1/explain", h.Explain)
	mux.HandleFunc("POST /pgauthz/v1/watch", h.Watch)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/explain", h.Explain)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/watch", h.Watch)

	// Native write path: full profile only (403 on decision-only, which is
	// read-only by DB role; 501 on compat-opa, whose writes go through OPA).
	mux.HandleFunc("POST /pgauthz/v1/write", h.WriteTuples)
	mux.HandleFunc("POST /pgauthz/v1/delete", h.DeleteTuples)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/write", h.WriteTuples)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/delete", h.DeleteTuples)

	// Store-scoped variants (OpenFGA-style): the path segment selects the
	// pgauthz store, so each store presents as its own AuthZEN PDP with its
	// own discovery document. Path beats the store header, which beats
	// DEFAULT_STORE — see store().
	mux.HandleFunc("POST /stores/{store}/access/v1/evaluation", h.Evaluation)
	mux.HandleFunc("POST /stores/{store}/access/v1/evaluations", h.Evaluations)
	mux.HandleFunc("POST /stores/{store}/access/v1/search/subject", h.SearchSubject)
	mux.HandleFunc("POST /stores/{store}/access/v1/search/resource", h.SearchResource)
	mux.HandleFunc("POST /stores/{store}/access/v1/search/action", h.SearchAction)
	mux.HandleFunc("GET /stores/{store}/.well-known/authzen-configuration", h.WellKnown)
	// AuthZEN 1.0 §9.2 tenant model: the well-known URI is INSERTED between
	// host and the tenant path, so discovery for the PDP identified by
	// .../stores/{store} lives at /.well-known/authzen-configuration/stores/{store}.
	mux.HandleFunc("GET /.well-known/authzen-configuration/stores/{store}", h.WellKnown)

	var handler http.Handler = mux
	handler = jwtMW.Middleware(handler)
	handler = RequestID(handler)
	handler = Logging(handler)
	handler = Recovery(handler)

	return handler
}

// store resolves the pgauthz store for a request: the /stores/{store} path
// segment wins, then the store header (X-AuthZ-Store), then DEFAULT_STORE.
// NOTE: store selection is caller-controlled — per-store access control (who
// may query which store) is a policy concern; SEARCH_REQUIRED_ROLE gates the
// search endpoints globally, not per store.
// storeChecked resolves the request's store AND enforces the per-issuer store
// binding (Issuer.Stores): tokens from an issuer with a configured store list
// may only access those stores (multi-tenant isolation). Issuers without a
// list — and the legacy unpinned validator — are unrestricted. Writes a 403
// and returns ok=false on a violation.
func (h *Handler) storeChecked(w http.ResponseWriter, r *http.Request) (string, bool) {
	store := h.store(r)
	allowed, restricted := h.issuerStores[IssuerFromContext(r.Context())]
	if !restricted {
		return store, true
	}
	for _, p := range allowed {
		if p.MatchString(store) {
			return store, true
		}
	}
	writeForbidden(w, "issuer is not allowed to access store '"+store+"'")
	return "", false
}

func (h *Handler) store(r *http.Request) string {
	if s := r.PathValue("store"); s != "" {
		return s
	}
	if s := r.Header.Get(h.cfg.StoreHeader); s != "" {
		return s
	}
	return h.cfg.DefaultStore
}

// resolveSubjectPair applies the subject-override policy to a body-supplied
// subject and the JWT-derived subject.
//
//   - Secure default (AllowSubjectOverride=false): the authenticated JWT
//     subject is authoritative. A body subject is accepted only if it matches
//     the token; a differing one is rejected (errSubjectForbidden) — it would
//     be an impersonation attempt. When no JWT subject is present (e.g. a
//     no-auth/system deployment), the body subject is the only source.
//   - Override (AllowSubjectOverride=true): the trusted-PEP/PDP mode — the
//     body subject wins, with the JWT subject as a fallback.
func (h *Handler) resolveSubjectPair(bodyType, bodyID, jwtType, jwtID string) (subjectType, subjectID string, err error) {
	if h.cfg.AllowSubjectOverride {
		subjectType, subjectID = bodyType, bodyID
		if subjectType == "" {
			subjectType = jwtType
		}
		if subjectID == "" {
			subjectID = jwtID
		}
		if subjectType == "" || subjectID == "" {
			return "", "", errSubjectRequired
		}
		return subjectType, subjectID, nil
	}

	// Secure default: the JWT subject is authoritative when present.
	if jwtType != "" && jwtID != "" {
		if (bodyType != "" && bodyType != jwtType) || (bodyID != "" && bodyID != jwtID) {
			return "", "", errSubjectForbidden
		}
		return jwtType, jwtID, nil
	}

	// No authenticated subject: the body is the only available source.
	if bodyType == "" || bodyID == "" {
		return "", "", errSubjectRequired
	}
	return bodyType, bodyID, nil
}

// resolveSubject resolves the effective subject for single-subject endpoints,
// applying the override policy against the JWT-derived subject.
func (h *Handler) resolveSubject(r *http.Request, body Subject) (subjectType, subjectID string, err error) {
	jwtType, jwtID := SubjectFromContext(r.Context())
	return h.resolveSubjectPair(body.Type, body.ID, jwtType, jwtID)
}

// requireSearchRole gates the reverse-search endpoints: if SearchRequiredRole is
// configured, the caller must hold it (these queries enumerate the access graph).
// Returns false and writes 403 when the caller lacks it; true when allowed or when
// no role is required.
func (h *Handler) requireSearchRole(w http.ResponseWriter, r *http.Request) bool {
	if h.cfg.SearchRequiredRole == "" {
		return true
	}
	for _, role := range RolesFromContext(r.Context()) {
		if role == h.cfg.SearchRequiredRole {
			return true
		}
	}
	writeForbidden(w, "search requires the '"+h.cfg.SearchRequiredRole+"' role")
	return false
}

// writeSubjectError maps a subject-resolution error to the right HTTP status:
// 403 for a rejected override attempt, 400 for a missing subject.
func writeSubjectError(w http.ResponseWriter, err error) {
	if errors.Is(err, errSubjectForbidden) {
		writeForbidden(w, err.Error())
		return
	}
	writeBadRequest(w, err.Error())
}

// Evaluation handles POST /access/v1/evaluation
func (h *Handler) Evaluation(w http.ResponseWriter, r *http.Request) {
	var req EvalRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	subjectType, subjectID, err := h.resolveSubject(r, req.Subject)
	if err != nil {
		writeSubjectError(w, err)
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

	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	evalReq := authz.EvalRequest{
		Store:       store,
		SubjectType: subjectType,
		SubjectID:   subjectID,
		Action:      req.Action.Name,
		ObjectType:  req.Resource.Type,
		ObjectID:    req.Resource.ID,
		Context:     req.Context,
	}

	// Opt-in rich result (X-Authz-Detail): backends that support it return
	// state/missing_context/model for the AuthZEN response context field.
	if dc, ok := h.backend.(authz.DetailedChecker); ok && DetailFromContext(r.Context()) {
		decision, detail, err := dc.CheckAccessDetailed(r.Context(), evalReq)
		if err != nil {
			writeInternalError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, EvalResponseBody{Decision: decision, Context: detail})
		return
	}

	decision, err := h.backend.CheckAccess(r.Context(), evalReq)
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

	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	jwtType, jwtID := SubjectFromContext(r.Context())

	// Build individual eval requests, merging shared subject/action/resource
	evals := make([]authz.EvalRequest, len(req.Evaluations))
	for i, e := range req.Evaluations {
		// Effective body subject: per-evaluation, falling back to the
		// batch-level subject. The override policy (vs the JWT subject) is
		// then applied centrally by resolveSubjectPair.
		bodyType := e.Subject.Type
		if bodyType == "" && req.Subject != nil {
			bodyType = req.Subject.Type
		}
		bodyID := e.Subject.ID
		if bodyID == "" && req.Subject != nil {
			bodyID = req.Subject.ID
		}

		subType, subID, serr := h.resolveSubjectPair(bodyType, bodyID, jwtType, jwtID)
		if serr != nil {
			if errors.Is(serr, errSubjectForbidden) {
				writeForbidden(w, fmt.Sprintf("evaluation[%d]: %s", i, serr.Error()))
			} else {
				writeBadRequest(w, fmt.Sprintf("evaluation[%d]: %s", i, serr.Error()))
			}
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
	if !h.requireSearchRole(w, r) {
		return
	}
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

	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	subjects, pageResp, err := h.backend.ListSubjects(r.Context(), store,
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
	if !h.requireSearchRole(w, r) {
		return
	}
	var req SearchResourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	subjectType, subjectID, err := h.resolveSubject(r, req.Subject)
	if err != nil {
		writeSubjectError(w, err)
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

	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	resources, pageResp, err := h.backend.ListResources(r.Context(), store,
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
	if !h.requireSearchRole(w, r) {
		return
	}
	var req SearchActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	subjectType, subjectID, err := h.resolveSubject(r, req.Subject)
	if err != nil {
		writeSubjectError(w, err)
		return
	}
	if req.Resource.Type == "" || req.Resource.ID == "" {
		writeBadRequest(w, "resource.type and resource.id are required")
		return
	}

	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	actions, err := h.backend.ListActions(r.Context(), store,
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

	// Store-scoped (tenant) discovery: the PDP identifier and every endpoint
	// carry the /stores/{store} path, so each store presents as its own
	// AuthZEN PDP (AuthZEN 1.0 §9.2 tenant model). The path-insertion
	// discovery URL is /.well-known/authzen-configuration/stores/{store}
	// (see the route); the store is the same PathValue either way.
	if s := r.PathValue("store"); s != "" {
		base += "/stores/" + s
	}

	writeJSON(w, http.StatusOK, WellKnownResponse{
		PolicyDecisionPoint:    base,
		AccessEvaluationEndpt:  base + "/access/v1/evaluation",
		AccessEvaluationsEndpt: base + "/access/v1/evaluations",
		SearchSubjectEndpoint:  base + "/access/v1/search/subject",
		SearchResourceEndpoint: base + "/access/v1/search/resource",
		SearchActionEndpoint:   base + "/access/v1/search/action",
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

// pageState is the decoded form of the opaque next_token. A is the keyset
// cursor (last id of the previous page); O is the legacy offset, still decoded
// so tokens minted before the keyset switch keep working.
type pageState struct {
	A string `json:"a,omitempty"`
	O int    `json:"o,omitempty"`
}

func decodePage(p *PageToken) *authz.PageRequest {
	if p == nil {
		return nil
	}
	size := p.Size
	if size <= 0 {
		size = defaultPageSize
	}
	var state pageState
	if p.Token != "" {
		data, err := base64.RawURLEncoding.DecodeString(p.Token)
		if err == nil {
			_ = json.Unmarshal(data, &state)
		}
	}
	return &authz.PageRequest{Limit: size, Offset: state.O, After: state.A}
}

// EncodePage mints a legacy offset cursor. Retained for back-compat; new pages
// use EncodePageAfter (keyset).
func EncodePage(offset int) string {
	data, _ := json.Marshal(pageState{O: offset})
	return base64.RawURLEncoding.EncodeToString(data)
}

// EncodePageAfter mints a keyset cursor carrying the last id of the page.
func EncodePageAfter(after string) string {
	data, _ := json.Marshal(pageState{A: after})
	return base64.RawURLEncoding.EncodeToString(data)
}

// --- JSON helpers ---

// writeRawJSON writes pre-serialized JSON (from the engine) verbatim.
func writeRawJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
