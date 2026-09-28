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
	"strings"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
)

// writeWriteError maps a native-write backend error to a status: a forbidden
// per-app role (e.g. a reader-only token reaching the write path) is a caller
// authorization error → 403, not a server fault → 500.
func writeWriteError(w http.ResponseWriter, err error) {
	if errors.Is(err, authz.ErrForbiddenRole) {
		writeForbidden(w, err.Error())
		return
	}
	if errors.Is(err, authz.ErrInvalidConsistency) || errors.Is(err, authz.ErrInvalidRequest) {
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

// resolvePerformedBy resolves the audit author for a native write, protecting
// the audit trail from caller-controlled attribution (review #7):
//
//   - service-token CALLBACK listener (requireWriterRole == false): the body
//     value IS the trusted upstream's (OPA's) assertion of the subject it
//     authenticated — that is the field's purpose there; body wins.
//   - PUBLIC (JWT) listener: the authenticated subject is authoritative. A
//     body value equal to it is harmless; a DIFFERING value is rejected (403)
//     unless ALLOW_SUBJECT_OVERRIDE — the flag that already means "callers are
//     trusted PEPs asserting other subjects" on the decision path. Without the
//     guard, any authorized writer could stamp another user into the immutable
//     audit trail.
//
// maxPerformedByLen bounds the audit-actor string: long enough for any real
// subject identifier (UUIDs, emails, SPIFFE IDs), short enough that the
// immutable audit trail can't be stuffed with junk (review #9).
const maxPerformedByLen = 256

// Returns ok=false with the 403/400 already written.
func (h *Handler) resolvePerformedBy(w http.ResponseWriter, r *http.Request, bodyValue string) (string, bool) {
	return h.resolveActor(w, r, bodyValue, "performed_by")
}

// resolveActor is resolvePerformedBy parameterized by the body field name, so
// the action log's recorded_by (ADR 0012) shares the exact same trust rules —
// the recorder's identity is as audit-critical as a tuple write's author.
func (h *Handler) resolveActor(w http.ResponseWriter, r *http.Request, bodyValue, field string) (string, bool) {
	// A whitespace-only value must not satisfy the non-empty requirement — it
	// would be an operationally useless audit attribution (review #9).
	bodyValue = strings.TrimSpace(bodyValue)
	if len(bodyValue) > maxPerformedByLen {
		writeBadRequest(w, field+" exceeds the maximum length")
		return "", false
	}
	_, jwtSubject := SubjectFromContext(r.Context())
	switch {
	case bodyValue == "":
		// The callback listener has NO JWT subject to fall back to — an omitted
		// performed_by would store an EMPTY audit attribution (review #8).
		// Require the upstream to assert the actor it authenticated.
		if jwtSubject == "" {
			writeBadRequest(w, field+" is required: this listener has no authenticated subject to attribute the write to")
			return "", false
		}
		return jwtSubject, true
	case !h.requireWriterRole: // internal callback listener (trusted PEP upstream)
		return bodyValue, true
	case bodyValue == jwtSubject || h.cfg.AllowSubjectOverride:
		return bodyValue, true
	default:
		writeForbidden(w, field+" differs from the authenticated subject; "+
			"audit attribution is token-derived (ALLOW_SUBJECT_OVERRIDE enables trusted-PEP assertion)")
		return "", false
	}
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
	performedBy, ok := h.resolvePerformedBy(w, r, req.PerformedBy)
	if !ok {
		return
	}
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
	performedBy, ok := h.resolvePerformedBy(w, r, req.PerformedBy)
	if !ok {
		return
	}
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
	performedBy, ok := h.resolvePerformedBy(w, r, req.PerformedBy)
	if !ok {
		return
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
	performedBy, ok := h.resolvePerformedBy(w, r, req.PerformedBy)
	if !ok {
		return
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

// nativeRecorder is nativeWriter for the action log (ADR 0012): the same
// read-only/capability gates, then the RECORDER_ROLE gate (writer passes too)
// instead of the writer gate.
func (h *Handler) nativeRecorder(w http.ResponseWriter, r *http.Request) (authz.EventRecorder, bool) {
	if !h.cfg.Writable() {
		writeError(w, http.StatusForbidden,
			"this instance is read-only (decision-only profile); "+
				"recording events requires the full profile")
		return nil, false
	}
	er, ok := h.rawWrite.(authz.EventRecorder)
	if !ok {
		writeError(w, http.StatusNotImplemented,
			"the pgauthz events API requires the full profile (writer DB role)")
		return nil, false
	}
	if !h.requireRecorder(w, r) {
		return nil, false
	}
	return er, true
}

// recordEventsBody is the native action-log request. Events is a JSONB array
// in the record_events_jsonb shape (flat keys, like tuples on /write).
type recordEventsBody struct {
	Events      json.RawMessage `json:"events"`
	Consistency string          `json:"consistency,omitempty"`
	// RecordedBy is the asserting actor — same trust rules as performed_by on
	// the write endpoints (token-derived on the public listener, required and
	// trusted on the callback listener).
	RecordedBy string `json:"recorded_by,omitempty"`
}

// RecordEvents — POST /pgauthz/v1/events: record what principals actually did
// (the action log, ADR 0012). Atomic per batch; duplicate event_ids are
// reported, not re-inserted. The engine result is returned with the store
// added; the freshness token rides along like any write so a follow-up
// at_least_as_fresh check on a replica sees the recorded events.
func (h *Handler) RecordEvents(w http.ResponseWriter, r *http.Request) {
	er, ok := h.nativeRecorder(w, r)
	if !ok {
		return
	}
	var req recordEventsBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	if len(req.Events) == 0 {
		writeBadRequest(w, "events is required")
		return
	}
	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	recordedBy, ok := h.resolveActor(w, r, req.RecordedBy, "recorded_by")
	if !ok {
		return
	}
	out, err := er.RecordEvents(r.Context(), authz.RecordEventsRequest{
		Store: store, Events: req.Events, RecordedBy: recordedBy, Consistency: req.Consistency,
	})
	if err != nil {
		metrics.EventsRejected.WithLabelValues(rejectReason(err)).Inc()
		writeWriteError(w, err)
		return
	}
	observeEventLags(req.Events)
	resp := map[string]any{"store": store}
	if err := json.Unmarshal(out, &resp); err != nil {
		writeInternalError(w, err)
		return
	}
	resp["store"] = store
	if n, ok := resp["recorded"].(float64); ok {
		metrics.EventsRecorded.WithLabelValues("recorded").Add(n)
	}
	if n, ok := resp["duplicates"].(float64); ok {
		metrics.EventsRecorded.WithLabelValues("duplicate").Add(n)
	}
	if rev := h.mintRevision(w, r); rev != "" {
		resp["revision"] = rev
	}
	writeJSON(w, http.StatusOK, resp)
}

// reserveEventBody: the subject is ABOUT TO perform action on resource. Subject,
// action and resource follow the check/explain shape (a reserve replaces the
// check the PEP would otherwise make); the rest is the record.
type reserveEventBody struct {
	Subject      Subject         `json:"subject"`
	Action       Action          `json:"action"`
	Resource     Resource        `json:"resource"`
	Context      map[string]any  `json:"context,omitempty"`
	Payload      json.RawMessage `json:"payload,omitempty"`
	EventID      string          `json:"event_id,omitempty"`
	OccurredAt   string          `json:"occurred_at,omitempty"`
	RecordDenied *bool           `json:"record_denied,omitempty"`
	Consistency  string          `json:"consistency,omitempty"`
	RecordedBy   string          `json:"recorded_by,omitempty"`
}

// ReserveEvent — POST /pgauthz/v1/events/reserve: the strict tier (ADR 0012
// phase 3). Under the engine's per-(store, subject) lock: full decision, then
// the `request` event is recorded if allowed (else a `denied` event). N
// parallel reserves against a cap of K yield exactly K allows. Consistency
// defaults to `applied` (a no-op without synchronous standbys) so a follow-up
// check on a replica sees the reservation.
func (h *Handler) ReserveEvent(w http.ResponseWriter, r *http.Request) {
	er, ok := h.nativeRecorder(w, r)
	if !ok {
		return
	}
	var req reserveEventBody
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
	recordedBy, ok := h.resolveActor(w, r, req.RecordedBy, "recorded_by")
	if !ok {
		return
	}
	consistency := req.Consistency
	if consistency == "" {
		consistency = "applied"
	}
	out, err := er.ReserveEvent(r.Context(), authz.ReserveEventRequest{
		Store: store, SubjectType: subjectType, SubjectID: subjectID,
		Action: req.Action.Name, ObjectType: req.Resource.Type, ObjectID: req.Resource.ID,
		Context: req.Context, Payload: req.Payload, EventID: req.EventID, OccurredAt: req.OccurredAt,
		RecordedBy: recordedBy, RecordDenied: req.RecordDenied, Consistency: consistency,
	})
	if err != nil {
		metrics.EventsRejected.WithLabelValues(rejectReason(err)).Inc()
		writeWriteError(w, err)
		return
	}
	resp := map[string]any{}
	if err := json.Unmarshal(out, &resp); err != nil {
		writeInternalError(w, err)
		return
	}
	resp["store"] = store
	if seq, ok := resp["seq"].(float64); ok && seq > 0 {
		metrics.EventsRecorded.WithLabelValues("recorded").Inc()
	}
	recordReserveOutcome(resp)
	if rev := h.mintRevision(w, r); rev != "" {
		resp["revision"] = rev
	}
	writeJSON(w, http.StatusOK, resp)
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
	if !h.requireExplainRole(w, r) {
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
	recordExplainGateClauses(out)
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
	if !h.requireWatchRole(w, r) {
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
