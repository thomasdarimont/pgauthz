package server

// Data subject requests (GDPR) on Store → Operations: everything the store
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

// handleOpsSubject — GET /api/stores/{store}/ops/subject?subject=type:id
// [&relations=a,b&limit=N&download=1&format=json|csv]: the export
// document (json), or — the takeout hand-over for the application teams —
// the objects the subject relates to as rows (csv: store, subject, object
// type, relation, object id, wildcard, direct; one row per reachable object
// and relation, list_subject_objects). With download as an attachment.
func (s *Server) handleOpsSubject(w http.ResponseWriter, r *http.Request) {
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
	for _, rel := range strings.Split(q.Get("relations"), ",") {
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
	decisions, truncated, err := s.subjectDecisions(ctx, store, typ, id, limit)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	out["decisions"] = decisions
	out["decisions_truncated"] = truncated
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
// when the sink lives in the console's database. Nil when not configured.
func (s *Server) subjectDecisions(ctx context.Context, store, typ, id string, limit int) ([]json.RawMessage, bool, error) {
	ok, err := s.decisionsConfigured(ctx)
	if err != nil || !ok {
		return nil, false, err
	}
	rows, err := s.decisionsDB().Query(ctx, `
		SELECT line FROM decisionlog.decisions
		 WHERE store = $1 AND subject_type = $2 AND subject_id = $3
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

// handleOpsSubjectErase — POST /api/stores/{store}/ops/subject/erase.
func (s *Server) handleOpsSubjectErase(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_manage_access")
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
	var res json.RawMessage
	payload := map[string]any{"op": "erase_subject", "subject": typ + ":" + id, "purge_events": purgeEvents, "purge_audit": req.PurgeAudit, "purge_decisions": purgeDecisions}
	err := s.asPerson(ctx, p, "can_manage_access", "store", store, payload, func(tx pgx.Tx) error {
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
		if ok, err := s.decisionsConfigured(ctx); err == nil && ok {
			tag, err := s.decisionsDB().Exec(ctx, `DELETE FROM decisionlog.decisions WHERE store = $1 AND subject_type = $2 AND subject_id = $3`, store, typ, id)
			if err != nil {
				out["decisions_error"] = err.Error()
			} else {
				out["decisions"] = tag.RowsAffected()
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}
