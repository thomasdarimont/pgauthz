package server

// Data subject requests (GDPR) on Store → Data subject: everything the store
// holds about one subject as one document (authz.export_subject, plus the
// subject's lines of the decision log from the console's own database),
// and its erasure (authz.erase_subject as the person, plus the decision-log
// lines). Reads need can_view_audit; the erasure can_manage_access and is
// recorded in the console's action log like every other change.

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// parseSubject splits "type:id" (the id may itself contain colons).
func parseSubject(s string) (typ, id string, ok bool) {
	typ, id, ok = strings.Cut(strings.TrimSpace(s), ":")
	typ, id = strings.TrimSpace(typ), strings.TrimSpace(id)
	return typ, id, ok && typ != "" && id != ""
}

// handleSubject — GET /api/stores/{store}/subject?subject=type:id
// [&relations=a,b&limit=N&download=1&format=json|csv]: the export
// document (json), or — the takeout hand-over for the application teams —
// the objects the subject relates to as rows (csv: store, subject, object
// type, relation, object id, wildcard, direct; one row per reachable object
// and relation, list_subject_objects). With download as an attachment.
func (s *Server) handleSubject(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view_audit")
	if p == nil {
		return
	}
	q := r.URL.Query()
	typ, id, ok := parseSubject(q.Get("subject"))
	if !ok {
		writeError(w, http.StatusBadRequest, "subject must be type:id")
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 100000 {
		limit = 10000
	}
	var relations []string
	for rel := range strings.SplitSeq(q.Get("relations"), ",") {
		if rel = strings.TrimSpace(rel); rel != "" {
			relations = append(relations, rel)
		}
	}
	ctx := r.Context()
	if q.Get("format") == "csv" {
		s.subjectObjectsCSV(w, r, store, typ, id, relations, limit)
		return
	}
	var doc json.RawMessage
	if err := s.engine.QueryRow(ctx, `SELECT authz.export_subject($1, $2, $3, $4, true, true, true, $5)`,
		store, typ, id, relations, limit).Scan(&doc); err != nil {
		writeEngineError(w, err)
		return
	}
	out := map[string]any{}
	if err := json.Unmarshal(doc, &out); err != nil {
		writeError(w, http.StatusBadGateway, "export did not decode: "+err.Error())
		return
	}
	decisions, truncated, err := s.subjectDecisions(ctx, store, typ, id, limit, false)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	out["decisions"] = decisions
	out["decisions_truncated"] = truncated
	// decisions OTHER subjects asked for ON the person (the resource side — review #20)
	about, aboutTruncated, err := s.subjectDecisions(ctx, store, typ, id, limit, true)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	out["decisions_about"] = about
	out["decisions_about_truncated"] = aboutTruncated
	out["exported_by"] = p.typ + ":" + p.id
	if q.Get("download") != "" {
		name := fmt.Sprintf("subject-%s-%s-%s.json", store, typ, id)
		name = strings.Map(func(c rune) rune {
			if c == '/' || c == '\\' || c == '"' || c < 0x20 {
				return '_'
			}
			return c
		}, name)
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	}
	writeJSON(w, http.StatusOK, out)
}

// subjectObjectsCSV writes list_subject_objects as CSV: what the application
// teams take to select the person's records in their own systems.
func (s *Server) subjectObjectsCSV(w http.ResponseWriter, r *http.Request, store, typ, id string, relations []string, limit int) {
	rows, err := s.engine.Query(r.Context(), `SELECT object_type, relation, object_id, is_wildcard, direct, truncated
		  FROM authz.list_subject_objects($1, $2, $3, $4, NULL, $5)`, store, typ, id, relations, limit)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	defer rows.Close()
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	_ = cw.Write([]string{"store", "subject_type", "subject_id", "object_type", "relation", "object_id", "is_wildcard", "direct", "truncated"})
	for rows.Next() {
		var ot, rel, oid string
		var wild, direct, trunc bool
		if err := rows.Scan(&ot, &rel, &oid, &wild, &direct, &trunc); err != nil {
			writeEngineError(w, err)
			return
		}
		_ = cw.Write([]string{store, typ, id, ot, rel, oid, strconv.FormatBool(wild), strconv.FormatBool(direct), strconv.FormatBool(trunc)})
	}
	if err := rows.Err(); err != nil {
		writeEngineError(w, err)
		return
	}
	cw.Flush()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	if r.URL.Query().Get("download") != "" {
		name := strings.Map(func(c rune) rune {
			if c == '/' || c == '\\' || c == '"' || c < 0x20 {
				return '_'
			}
			return c
		}, fmt.Sprintf("subject-%s-%s-%s-objects.csv", store, typ, id))
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	}
	_, _ = w.Write(buf.Bytes())
}

// subjectDecisions: the subject's lines of the decision log, newest first,
// when the sink lives in the console's database — the decisions it asked
// for, or (asResource) the decisions others asked for on it. Nil when not
// configured.
func (s *Server) subjectDecisions(ctx context.Context, store, typ, id string, limit int, asResource bool) ([]json.RawMessage, bool, error) {
	ok, err := s.decisionsConfigured(ctx)
	if err != nil || !ok {
		return nil, false, err
	}
	where := `subject_type = $2 AND subject_id = $3`
	if asResource {
		// IS DISTINCT FROM: a line without a subject (nullable) is still about the person (review #21)
		where = `resource_type = $2 AND resource_id = $3 AND (subject_type, subject_id) IS DISTINCT FROM ($2, $3)`
	}
	rows, err := s.decisionsDB().Query(ctx, `
		SELECT line FROM decisionlog.decisions
		 WHERE store = $1 AND `+where+`
		 ORDER BY ts DESC, id DESC LIMIT $4`, store, typ, id, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var line json.RawMessage
		if err := rows.Scan(&line); err != nil {
			return nil, false, err
		}
		out = append(out, line)
	}
	truncated := len(out) > limit
	if truncated {
		out = out[:limit]
	}
	return out, truncated, rows.Err()
}

type eraseSubjectReq struct {
	Subject        string `json:"subject"`
	PurgeEvents    *bool  `json:"purge_events"`    // default true
	PurgeAudit     bool   `json:"purge_audit"`     // default false
	PurgeDecisions *bool  `json:"purge_decisions"` // default true
}

// handleSubjectErase — POST /api/stores/{store}/subject/erase.
//
// Behind SUBJECT_ERASURE_ENABLED (default off) and for PLATFORM admins
// (platform#can_manage_access), not store owners: erasure comes last in a
// data-subject request, after the applications deleted their records by
// the takeout's references, and it is the one operation here that destroys
// the index of what remains to be deleted. The takeout and the export stay
// open to the store's auditors regardless.
func (s *Server) handleSubjectErase(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.SubjectErasureEnabled {
		writeError(w, http.StatusNotFound, "subject erasure is off on this console (SUBJECT_ERASURE_ENABLED=false); the takeout and the export are available, erase_subject in SQL for the DPO")
		return
	}
	store := r.PathValue("store")
	if !validName.MatchString(store) {
		writeError(w, http.StatusBadRequest, "invalid store name")
		return
	}
	p := s.require(w, r, "can_manage_access", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	var req eraseSubjectReq
	if !decodeJSON(w, r, &req) {
		return
	}
	typ, id, ok := parseSubject(req.Subject)
	if !ok {
		writeError(w, http.StatusBadRequest, "subject must be type:id")
		return
	}
	purgeEvents := req.PurgeEvents == nil || *req.PurgeEvents
	purgeDecisions := req.PurgeDecisions == nil || *req.PurgeDecisions
	ctx := r.Context()

	// Two databases, no shared transaction (reviews #20, #21). The ENGINE
	// goes first: it re-authorizes inside its transaction and records the
	// erasure in the console's action log — the durable administrative
	// record — so nothing is deleted before the authoritative check. Then
	// the decision log, in one transaction: a tombstone
	// (decisionlog.erasures) and the delete of the persisted lines on
	// either side. The tombstone is what makes the 200 mean something: a
	// line about the person that an instance accepted before the erasure
	// and flushes afterwards is dropped by the sink on insert. If the
	// decision-log step fails the answer is 502 `partial`; the engine part
	// is done and on record, and a retry completes the rest (idempotent).
	var res json.RawMessage
	payload := map[string]any{"op": "erase_subject", "store": store, "subject": typ + ":" + id, "purge_events": purgeEvents, "purge_audit": req.PurgeAudit, "purge_decisions": purgeDecisions}
	err := s.asPerson(ctx, p, "can_manage_access", "platform", s.cfg.PlatformID, payload, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT authz.erase_subject($1, $2, $3, $4, $5, $6)`,
			store, typ, id, purgeEvents, req.PurgeAudit, p.typ+":"+p.id).Scan(&res)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	out := map[string]any{}
	_ = json.Unmarshal(res, &out)
	out["decisions"] = 0
	if purgeDecisions {
		n, err := s.eraseDecisions(ctx, store, typ, id, p.typ+":"+p.id)
		if err != nil {
			out["partial"] = true
			out["error"] = "the engine erased the subject (recorded in the action log) but the decision log could not be: retry to complete it: " + err.Error()
			writeJSON(w, http.StatusBadGateway, out)
			return
		}
		out["decisions"] = n
	}
	writeJSON(w, http.StatusOK, out)
}

// purgeStoreDecisions removes a deleted store's lines and tombstones from
// the decision log behind the store fence (pgauthzd's decisionlog package,
// PurgeStore — the same protocol, mirrored here): the fence row
// (decisionlog.store_purges, purged_at = now) and the exclusive erasure
// lock in one small transaction, committed, so a batch in flight has
// committed first and a later batch drops its lines about the store itself;
// then the lines and tombstones in one transaction, no lock held. Without
// the fence, deleting the tombstones would let a buffered line about an
// erased subject come back (review #27). Idempotent.
func (s *Server) purgeStoreDecisions(ctx context.Context, store, by string) (int64, error) {
	db := s.decisionsDB()
	tx, err := db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO decisionlog.store_purges (store, purged_at, purged_by) VALUES ($1, now(), $2)
	                            ON CONFLICT (store) DO UPDATE SET purged_at = EXCLUDED.purged_at, purged_by = EXCLUDED.purged_by`, store, by); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '10s'`); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('decisionlog.erasures'))`); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	tx2, err := db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx2.Rollback(ctx) }()
	tag, err := tx2.Exec(ctx, `DELETE FROM decisionlog.decisions WHERE store = $1`, store)
	if err != nil {
		return 0, err
	}
	if _, err := tx2.Exec(ctx, `DELETE FROM decisionlog.erasures WHERE store = $1`, store); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), tx2.Commit(ctx)
}

// eraseDecisions writes the erasure tombstone and removes the subject's
// persisted lines on either side; 0 without a sink.
//
// Two transactions, ordered against the sinks' batches (pgauthzd's
// decisionlog package, "Ordering"): the first writes the tombstone and
// takes the erasure advisory lock EXCLUSIVE right before committing — the
// sinks hold it SHARED for every batch transaction, so this waits for the
// batches in flight (they filtered before the tombstone existed) and is
// released the instant the tombstone is committed; a batch that starts
// after that filters against the committed tombstone. The delete over the
// persisted lines then runs in its own transaction with no lock held, so a
// large log never stalls the sinks. The lock key is hashtext of the
// tombstone table's name, the same expression the sink uses. A batch stuck
// longer than lock_timeout fails this step (502 partial, retried), it does
// not hang the request.
func (s *Server) eraseDecisions(ctx context.Context, store, typ, id, by string) (int64, error) {
	ok, err := s.decisionsConfigured(ctx)
	if err != nil || !ok {
		return 0, err
	}
	db := s.decisionsDB()
	tx, err := db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO decisionlog.erasures (store, subject_type, subject_id, erased_at, erased_by) VALUES ($1, $2, $3, now(), $4)`, store, typ, id, by); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '10s'`); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('decisionlog.erasures'))`); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	tag, err := db.Exec(ctx, `DELETE FROM decisionlog.decisions
		 WHERE store = $1 AND ((subject_type = $2 AND subject_id = $3) OR (resource_type = $2 AND resource_id = $3))`, store, typ, id)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
