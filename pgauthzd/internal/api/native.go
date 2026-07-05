// Native pgauthz API (/pgauthz/v1/*): vendor-specific read operations beyond
// the standards-compliant AuthZEN surface. These require a backend that
// implements authz.NativeReader (the direct pgx backend); on the OPA-compat
// backend they return 501 Not Implemented. Kept deliberately separate from
// /access/v1 so the AuthZEN endpoints stay spec-pure.
package api

import (
	"encoding/json"
	"net/http"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
)

// nativeReader returns the backend as a NativeReader, or writes 501 and false.
func (h *Handler) nativeReader(w http.ResponseWriter) (authz.NativeReader, bool) {
	nr, ok := h.backend.(authz.NativeReader)
	if !ok {
		writeError(w, http.StatusNotImplemented,
			"the pgauthz native API requires the direct backend (profile decision-only|full); "+
				"this instance runs compat-opa")
		return nil, false
	}
	return nr, true
}

type explainRequestBody struct {
	Subject  Subject        `json:"subject"`
	Action   Action         `json:"action"`
	Resource Resource       `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

// Explain — POST /pgauthz/v1/explain: the structured "why" (decision + trace).
// Same subject-resolution and store binding as an AuthZEN evaluation; returns
// explain_access's JSON verbatim.
func (h *Handler) Explain(w http.ResponseWriter, r *http.Request) {
	nr, ok := h.nativeReader(w)
	if !ok {
		return
	}
	var req explainRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	subjectType, subjectID, err := h.resolveSubject(r, req.Subject)
	if err != nil {
		writeSubjectError(w, err)
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
	out, err := nr.Explain(r.Context(), authz.EvalRequest{
		Store: store, SubjectType: subjectType, SubjectID: subjectID,
		Action: req.Action.Name, ObjectType: req.Resource.Type, ObjectID: req.Resource.ID,
		Context: req.Context,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeRawJSON(w, http.StatusOK, out)
}

type watchRequestBody struct {
	AfterAt     string   `json:"after_at,omitempty"`
	AfterSeq    int64    `json:"after_seq,omitempty"`
	Limit       int      `json:"limit,omitempty"`
	Lag         string   `json:"lag,omitempty"`
	ObjectTypes []string `json:"object_types,omitempty"`
	Namespaces  []string `json:"namespaces,omitempty"`
	Relations   []string `json:"relations,omitempty"`
}

// Watch — POST /pgauthz/v1/watch: a cursored page of the store's audit
// changefeed (the HTTP transport over authz.watch_changes). The connection
// role needs auditor privileges; a lacking grant surfaces as 403 from the DB.
func (h *Handler) Watch(w http.ResponseWriter, r *http.Request) {
	nr, ok := h.nativeReader(w)
	if !ok {
		return
	}
	var req watchRequestBody
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBadRequest(w, "invalid JSON: "+err.Error())
			return
		}
	}
	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	out, err := nr.WatchChanges(r.Context(), authz.WatchRequest{
		Store: store, AfterAt: req.AfterAt, AfterSeq: req.AfterSeq, Limit: req.Limit,
		Lag: req.Lag, ObjectTypes: req.ObjectTypes, Namespaces: req.Namespaces, Relations: req.Relations,
	})
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeRawJSON(w, http.StatusOK, out)
}
