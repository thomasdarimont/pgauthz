package api

// Native raw decision + search endpoints (/pgauthz/v1/check, /check-batch,
// /list-objects, /list-subjects, /list-actions). These are policy-FREE by
// construction: they run straight against the direct pgx backend (the ReBAC
// graph answer), NEVER through a policy layer. That is exactly what an external
// OPA sidecar calls back into when a Rego policy delegates to the graph — so a
// compat-opa deployment can front the graph with policy without OPA needing
// PostgREST, and without re-entering its own policy-wrapped /access/v1 surface.
//
// Served by the direct pgx `raw` backend (never OPA): on the direct profiles
// that is the single backend; on compat-opa it is a separate read-only pgx
// backend exposed only on the INTERNAL listener that the OPA sidecar calls back
// into. When no raw backend is configured the gate (authz.NativeReader) returns
// 501. The vocabulary matches the AuthZEN surface (subject/action/resource) so
// the same subject-resolution and store-binding apply; the responses are
// pgauthz-native (allowed / objects / subjects / actions).

import (
	"encoding/json"
	"net/http"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
)

type nativeCheckBody struct {
	Subject  Subject        `json:"subject"`
	Action   Action         `json:"action"`
	Resource Resource       `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
	// Detail opts into the rich result (state/missing_context/conditions/model)
	// when the backend supports it — the native equivalent of X-Authz-Detail.
	Detail bool `json:"detail,omitempty"`
	// ContextualTuples, when present, are evaluated as ephemeral tuples
	// alongside the stored graph (never persisted). JSONB array in the
	// write_tuples_jsonb element shape.
	ContextualTuples json.RawMessage `json:"contextual_tuples,omitempty"`
}

// NativeCheck — POST /pgauthz/v1/check: a single raw access decision.
func (h *Handler) NativeCheck(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.nativeReader(w); !ok {
		return
	}
	var req nativeCheckBody
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
		Store: store, SubjectType: subjectType, SubjectID: subjectID,
		Action: req.Action.Name, ObjectType: req.Resource.Type, ObjectID: req.Resource.ID,
		Context: req.Context,
	}
	if len(req.ContextualTuples) > 0 {
		cc, ok := h.raw.(authz.ContextualChecker)
		if !ok {
			writeError(w, http.StatusNotImplemented, "contextual-tuple checks require the direct backend")
			return
		}
		decision, err := cc.CheckWithContextualTuples(r.Context(), evalReq, req.ContextualTuples)
		if err != nil {
			writeInternalError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"allowed": decision})
		return
	}
	if req.Detail {
		if dc, ok := h.raw.(authz.DetailedChecker); ok {
			decision, detail, err := dc.CheckAccessDetailed(r.Context(), evalReq)
			if err != nil {
				writeInternalError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"allowed": decision, "detail": detail})
			return
		}
		// detail requested but unsupported → fall through to the plain answer
	}
	decision, err := h.raw.CheckAccess(r.Context(), evalReq)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"allowed": decision})
}

type nativeCheckBatchBody struct {
	// Shared subject/action/resource defaults, merged into each check when the
	// per-check field is empty (same convention as AuthZEN /evaluations).
	Subject  *Subject          `json:"subject,omitempty"`
	Action   *Action           `json:"action,omitempty"`
	Resource *Resource         `json:"resource,omitempty"`
	Context  map[string]any    `json:"context,omitempty"`
	Semantic string            `json:"semantic,omitempty"`
	Checks   []nativeCheckBody `json:"checks"`
}

// NativeCheckBatch — POST /pgauthz/v1/check-batch: many raw decisions in one
// round-trip. Returns a boolean per check, in order.
func (h *Handler) NativeCheckBatch(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.nativeReader(w); !ok {
		return
	}
	var req nativeCheckBatchBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	if len(req.Checks) == 0 {
		writeBadRequest(w, "checks array is required and must not be empty")
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

	evals := make([]authz.EvalRequest, len(req.Checks))
	for i, c := range req.Checks {
		st, sid := c.Subject.Type, c.Subject.ID
		if st == "" && req.Subject != nil {
			st = req.Subject.Type
		}
		if sid == "" && req.Subject != nil {
			sid = req.Subject.ID
		}
		subType, subID, serr := h.resolveSubjectPair(st, sid, jwtType, jwtID)
		if serr != nil {
			writeSubjectError(w, serr)
			return
		}
		action := c.Action.Name
		if action == "" && req.Action != nil {
			action = req.Action.Name
		}
		objType, objID := c.Resource.Type, c.Resource.ID
		if objType == "" && req.Resource != nil {
			objType = req.Resource.Type
		}
		if objID == "" && req.Resource != nil {
			objID = req.Resource.ID
		}
		if action == "" || objType == "" || objID == "" {
			writeBadRequest(w, "each check needs action.name and resource.type/id (directly or via the shared defaults)")
			return
		}
		evals[i] = authz.EvalRequest{
			Store: store, SubjectType: subType, SubjectID: subID,
			Action: action, ObjectType: objType, ObjectID: objID, Context: c.Context,
		}
	}
	results, err := h.raw.CheckAccessBatch(r.Context(), store, evals, req.Context, semantic)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]bool, len(results))
	for i, res := range results {
		out[i] = res.Decision
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}

// nativePage carries pagination for a native list call. The raw limit/offset/
// after fields are for the OPA callback (which already holds them, and does its
// own has-more/next-token handling); the opaque page token is for external
// AuthZEN-style callers. Raw fields take precedence when limit is set.
type nativePage struct {
	Limit  int        `json:"limit,omitempty"`
	Offset int        `json:"offset,omitempty"`
	After  string     `json:"after,omitempty"`
	Page   *PageToken `json:"page,omitempty"`
}

func (p nativePage) pageReq() *authz.PageRequest {
	if p.Limit > 0 {
		return &authz.PageRequest{Limit: p.Limit, Offset: p.Offset, After: p.After}
	}
	return decodePage(p.Page)
}

type nativeListObjectsBody struct {
	Subject  Subject        `json:"subject"`
	Action   Action         `json:"action"`
	Resource Resource       `json:"resource"` // only Type is used
	Context  map[string]any `json:"context,omitempty"`
	nativePage
}

// NativeListObjects — POST /pgauthz/v1/list-objects: which objects of a type the
// subject can act on (list_objects). Keyset-paginated.
func (h *Handler) NativeListObjects(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.nativeReader(w); !ok {
		return
	}
	if !h.requireSearchRole(w, r) {
		return
	}
	var req nativeListObjectsBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	subjectType, subjectID, err := h.resolveSubject(r, req.Subject)
	if err != nil {
		writeSubjectError(w, err)
		return
	}
	if req.Action.Name == "" || req.Resource.Type == "" {
		writeBadRequest(w, "action.name and resource.type are required")
		return
	}
	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	objects, pageResp, err := h.raw.ListResources(r.Context(), store,
		subjectType, subjectID, req.Action.Name, req.Resource.Type, req.Context, req.pageReq())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, listResponse("objects", objects, pageResp))
}

type nativeListSubjectsBody struct {
	Subject  Subject        `json:"subject"` // only Type is used
	Action   Action         `json:"action"`
	Resource Resource       `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
	nativePage
}

// NativeListSubjects — POST /pgauthz/v1/list-subjects: which subjects of a type
// can act on the object (list_subjects). Keyset-paginated.
func (h *Handler) NativeListSubjects(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.nativeReader(w); !ok {
		return
	}
	if !h.requireSearchRole(w, r) {
		return
	}
	var req nativeListSubjectsBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	if req.Subject.Type == "" {
		writeBadRequest(w, "subject.type is required for subject search")
		return
	}
	if req.Action.Name == "" || req.Resource.Type == "" || req.Resource.ID == "" {
		writeBadRequest(w, "action.name and resource.type/id are required")
		return
	}
	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	subjects, pageResp, err := h.raw.ListSubjects(r.Context(), store,
		req.Subject.Type, req.Action.Name, req.Resource.Type, req.Resource.ID, req.Context, req.pageReq())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, listResponse("subjects", subjects, pageResp))
}

type nativeListActionsBody struct {
	Subject  Subject        `json:"subject"`
	Resource Resource       `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

// NativeListActions — POST /pgauthz/v1/list-actions: which relations the subject
// holds on the object (list_actions).
func (h *Handler) NativeListActions(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.nativeReader(w); !ok {
		return
	}
	var req nativeListActionsBody
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
	actions, err := h.raw.ListActions(r.Context(), store,
		subjectType, subjectID, req.Resource.Type, req.Resource.ID, req.Context)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

// listResponse builds a native list response: {<key>: [...], next_token?: "..."}.
func listResponse(key string, ids []string, page *authz.PageResponse) map[string]any {
	out := map[string]any{key: ids}
	if page != nil && page.HasMore {
		out["next_token"] = page.NextToken
	}
	return out
}
