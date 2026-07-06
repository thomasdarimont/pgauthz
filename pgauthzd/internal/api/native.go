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
	if errors.Is(err, authz.ErrInvalidConsistency) {
		writeBadRequest(w, err.Error())
		return
	}
	writeInternalError(w, err)
}

// nativeReader returns the backend as a NativeReader, or writes 501 and false.
// The native read surface requires the direct pgx backend (always present on
// both profiles); 501 is a defensive guard only.
func (h *Handler) nativeReader(w http.ResponseWriter) (authz.NativeReader, bool) {
	nr, ok := h.raw.(authz.NativeReader)
	if !ok {
		writeError(w, http.StatusNotImplemented,
			"the pgauthz native API requires the direct pgx backend")
		return nil, false
	}
	return nr, true
}

// nativeWriter returns the backend as a NativeWriter for the write path, or
// writes an error and false. The native write surface exists only on the FULL
// profile — a direct pgx backend on a writer-capable connection; decision-only
// is read-only by DB role (501/403). On the PUBLIC listener the caller must
// also hold the WRITER_ROLE claim (requireWriter) — pgauthzd authorizes writes
// itself. The profile/role gates are defense-in-depth; the hard guarantee is
// that a non-full instance connects with a role that physically cannot write.
func (h *Handler) nativeWriter(w http.ResponseWriter, r *http.Request) (authz.NativeWriter, bool) {
	// Read-only gate first: a decision-only instance is read-only by DB role, so
	// refuse writes with 403 (not 501) even though the native write routes are
	// registered — the profile, not a missing capability, is why.
	if !h.cfg.Writable() {
		writeError(w, http.StatusForbidden,
			"this instance is read-only (decision-only profile); "+
				"native tuple writes require the full profile")
		return nil, false
	}
	// Then capability: only a writer-capable direct backend implements native
	// writes (defensive — a full instance always has one).
	nw, ok := h.rawWrite.(authz.NativeWriter)
	if !ok {
		writeError(w, http.StatusNotImplemented,
			"the pgauthz native write API requires the full profile (writer DB role)")
		return nil, false
	}
	// Finally the writer-role gate on the public listener (no-op on the
	// service-token callback listener, which trusts OPA's asserted role).
	if !h.requireWriter(w, r) {
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
	// PerformedBy is the audit author. On the public (JWT) listener it defaults
	// to the authenticated JWT subject; on the service-token callback listener
	// (no JWT) OPA passes the authenticated subject here explicitly.
	PerformedBy string `json:"performed_by,omitempty"`
}

// performedBy resolves the audit author: an explicit body value (the OPA
// callback path) wins, else the authenticated JWT subject.
func (h *Handler) writePerformedBy(r *http.Request, body writeTuplesBody) string {
	if body.PerformedBy != "" {
		return body.PerformedBy
	}
	_, id := SubjectFromContext(r.Context())
	return id
}

// WriteTuples — POST /pgauthz/v1/write: batch-upsert tuples. The audit author
// (performed_by) is the authenticated subject; the per-app DB role from the
// token governs namespace scope, same as reads.
func (h *Handler) WriteTuples(w http.ResponseWriter, r *http.Request) {
	nw, ok := h.nativeWriter(w, r)
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
	performedBy := h.writePerformedBy(r, req)
	n, err := nw.WriteTuples(r.Context(), authz.WriteRequest{
		Store: store, Tuples: req.Tuples, PerformedBy: performedBy, Consistency: req.Consistency,
	})
	if err != nil {
		writeWriteError(w, err)
		return
	}
	resp := map[string]any{"store": store, "written": n}
	if rev := h.mintRevision(w, r); rev != "" {
		resp["revision"] = rev
	}
	writeJSON(w, http.StatusOK, resp)
}

// DeleteTuples — POST /pgauthz/v1/delete: batch-delete tuples. Same authoring
// and role semantics as WriteTuples.
func (h *Handler) DeleteTuples(w http.ResponseWriter, r *http.Request) {
	nw, ok := h.nativeWriter(w, r)
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
	performedBy := h.writePerformedBy(r, req)
	n, err := nw.DeleteTuples(r.Context(), authz.WriteRequest{
		Store: store, Tuples: req.Tuples, PerformedBy: performedBy, Consistency: req.Consistency,
	})
	if err != nil {
		writeWriteError(w, err)
		return
	}
	resp := map[string]any{"store": store, "deleted": n}
	if rev := h.mintRevision(w, r); rev != "" {
		resp["revision"] = rev
	}
	writeJSON(w, http.StatusOK, resp)
}

type deleteUserBody struct {
	User        Subject `json:"user"` // Type=user_type, ID=user_id
	Consistency string  `json:"consistency,omitempty"`
	PerformedBy string  `json:"performed_by,omitempty"`
}

// DeleteUserTuples — POST /pgauthz/v1/delete-user: offboarding, remove every
// tuple for a subject.
func (h *Handler) DeleteUserTuples(w http.ResponseWriter, r *http.Request) {
	nw, ok := h.nativeWriter(w, r)
	if !ok {
		return
	}
	var req deleteUserBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	if req.User.Type == "" || req.User.ID == "" {
		writeBadRequest(w, "user.type and user.id are required")
		return
	}
	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	performedBy := req.PerformedBy
	if performedBy == "" {
		_, performedBy = SubjectFromContext(r.Context())
	}
	n, err := nw.DeleteUserTuples(r.Context(), authz.DeleteUserRequest{
		Store: store, UserType: req.User.Type, UserID: req.User.ID,
		PerformedBy: performedBy, Consistency: req.Consistency,
	})
	if err != nil {
		writeWriteError(w, err)
		return
	}
	resp := map[string]any{"store": store, "deleted": n}
	if rev := h.mintRevision(w, r); rev != "" {
		resp["revision"] = rev
	}
	writeJSON(w, http.StatusOK, resp)
}

type checkedWriteBody struct {
	Preconditions json.RawMessage `json:"preconditions,omitempty"`
	Deletes       json.RawMessage `json:"deletes,omitempty"`
	Writes        json.RawMessage `json:"writes,omitempty"`
	Consistency   string          `json:"consistency,omitempty"`
	PerformedBy   string          `json:"performed_by,omitempty"`
}

// WriteTuplesChecked — POST /pgauthz/v1/write-checked: conditional/atomic write
// (preconditions gate deletes+writes). Returns the engine's JSONB result.
func (h *Handler) WriteTuplesChecked(w http.ResponseWriter, r *http.Request) {
	nw, ok := h.nativeWriter(w, r)
	if !ok {
		return
	}
	var req checkedWriteBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	performedBy := req.PerformedBy
	if performedBy == "" {
		_, performedBy = SubjectFromContext(r.Context())
	}
	out, err := nw.WriteTuplesChecked(r.Context(), authz.CheckedWriteRequest{
		Store: store, Preconditions: req.Preconditions, Deletes: req.Deletes, Writes: req.Writes,
		PerformedBy: performedBy, Consistency: req.Consistency,
	})
	if err != nil {
		writeWriteError(w, err)
		return
	}
	// Raw engine JSON body → the token rides the X-PGAuthz-Revision header only.
	h.mintRevision(w, r)
	writeRawJSON(w, http.StatusOK, out)
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
