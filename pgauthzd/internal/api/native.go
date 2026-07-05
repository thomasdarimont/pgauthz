// Native pgauthz API (/pgauthz/v1/*): vendor-specific read operations beyond
// the standards-compliant AuthZEN surface. These require a backend that
// implements authz.NativeReader (the direct pgx backend); on the OPA-compat
// backend they return 501 Not Implemented. Kept deliberately separate from
// /access/v1 so the AuthZEN endpoints stay spec-pure.
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
)

// writeWriteError maps a native-write backend error to a status: a forbidden
// per-app role (e.g. a reader-only token reaching the write path) is a caller
// authorization error → 403, not a server fault → 500.
func writeWriteError(w http.ResponseWriter, err error) {
	if errors.Is(err, authz.ErrForbiddenRole) {
		writeForbidden(w, err.Error())
		return
	}
	writeInternalError(w, err)
}

// nativeReader returns the backend as a NativeReader, or writes 501 and false.
func (h *Handler) nativeReader(w http.ResponseWriter) (authz.NativeReader, bool) {
	nr, ok := h.raw.(authz.NativeReader)
	if !ok {
		writeError(w, http.StatusNotImplemented,
			"the pgauthz native API requires the direct backend (profile decision-only|full); "+
				"this instance runs compat-opa")
		return nil, false
	}
	return nr, true
}

// nativeWriter returns the backend as a NativeWriter for the write path, or
// writes an error and false. The native write surface exists only on the FULL
// profile — a direct pgx backend on a writer-capable connection. decision-only
// is read-only by DB role (403, not just a flag); compat-opa writes go through
// the OPA front door (501). The profile gate is defense-in-depth; the hard
// guarantee is that a non-full instance connects with a role that cannot write.
func (h *Handler) nativeWriter(w http.ResponseWriter) (authz.NativeWriter, bool) {
	// Capability first: only the direct backend implements native writes, so
	// compat-opa (whose writes go through the OPA front door) gets 501 —
	// consistent with the native read endpoints.
	nw, ok := h.raw.(authz.NativeWriter)
	if !ok {
		writeError(w, http.StatusNotImplemented,
			"the pgauthz native write API requires the direct backend (profile full); "+
				"this instance runs compat-opa (writes go through OPA)")
		return nil, false
	}
	// Then the read-only gate: a decision-only instance runs the direct backend
	// but connects with a role that cannot write, so refuse up front with 403
	// rather than surfacing a DB permission error.
	if !h.cfg.Writable() {
		writeError(w, http.StatusForbidden,
			"this instance is read-only (decision-only profile); "+
				"native tuple writes require the full profile")
		return nil, false
	}
	return nw, true
}

// writeTuplesBody is the native batch write/delete request. Tuples is a JSONB
// array in the write_tuples_jsonb shape (user_type, user_id, relation,
// object_type, object_id, and the optional user_relation/condition/context/
// expires_at). Consistency selects the per-tx synchronous_commit mode.
type writeTuplesBody struct {
	Tuples      json.RawMessage `json:"tuples"`
	Consistency string          `json:"consistency,omitempty"`
}

// WriteTuples — POST /pgauthz/v1/write: batch-upsert tuples. The audit author
// (performed_by) is the authenticated subject; the per-app DB role from the
// token governs namespace scope, same as reads.
func (h *Handler) WriteTuples(w http.ResponseWriter, r *http.Request) {
	nw, ok := h.nativeWriter(w)
	if !ok {
		return
	}
	var req writeTuplesBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	if len(req.Tuples) == 0 {
		writeBadRequest(w, "tuples is required")
		return
	}
	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	_, performedBy := SubjectFromContext(r.Context())
	n, err := nw.WriteTuples(r.Context(), authz.WriteRequest{
		Store: store, Tuples: req.Tuples, PerformedBy: performedBy, Consistency: req.Consistency,
	})
	if err != nil {
		writeWriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": store, "written": n})
}

// DeleteTuples — POST /pgauthz/v1/delete: batch-delete tuples. Same authoring
// and role semantics as WriteTuples.
func (h *Handler) DeleteTuples(w http.ResponseWriter, r *http.Request) {
	nw, ok := h.nativeWriter(w)
	if !ok {
		return
	}
	var req writeTuplesBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	if len(req.Tuples) == 0 {
		writeBadRequest(w, "tuples is required")
		return
	}
	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	_, performedBy := SubjectFromContext(r.Context())
	n, err := nw.DeleteTuples(r.Context(), authz.WriteRequest{
		Store: store, Tuples: req.Tuples, PerformedBy: performedBy, Consistency: req.Consistency,
	})
	if err != nil {
		writeWriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": store, "deleted": n})
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
