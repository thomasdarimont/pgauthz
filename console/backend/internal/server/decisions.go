package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The Decisions tab reads pgauthzd's decision log from the postgres sink
// (ADR 0015): the table decisionlog.decisions in the console's own
// database (PG_DSN) — pgauthzd's DECISION_LOG=postgres points its
// DECISION_LOG_DSN there. The console never writes it; without the table
// the tab says the sink is not configured. Gated by can_view_decisions.

// decisionRow is one logged decision, the indexed columns plus the full line.
type decisionRow struct {
	ID           int64           `json:"id"`
	TS           time.Time       `json:"ts"`
	RequestID    string          `json:"request_id,omitempty"`
	TraceID      string          `json:"trace_id,omitempty"`
	SpanID       string          `json:"span_id,omitempty"`
	Listener     string          `json:"listener"`
	Endpoint     string          `json:"endpoint"`
	Via          string          `json:"via,omitempty"`
	SubjectType  string          `json:"subject_type,omitempty"`
	SubjectID    string          `json:"subject_id,omitempty"`
	Action       string          `json:"action,omitempty"`
	ResourceType string          `json:"resource_type,omitempty"`
	ResourceID   string          `json:"resource_id,omitempty"`
	Decision     *bool           `json:"decision,omitempty"`
	State        string          `json:"state,omitempty"`
	Reason       string          `json:"reason,omitempty"`
	Actor        string          `json:"actor,omitempty"`
	Client       string          `json:"client,omitempty"`
	Issuer       string          `json:"issuer,omitempty"`
	LatencyMS    float64         `json:"latency_ms"`
	Error        string          `json:"error,omitempty"`
	Line         json.RawMessage `json:"line"`
}

// decisionsDB is where the sink table lives: the console's own database.
func (s *Server) decisionsDB() *pgxpool.Pool { return s.db }

// decisionsConfigured reports whether the sink table exists.
func (s *Server) decisionsConfigured(ctx context.Context) (bool, error) {
	db := s.decisionsDB()
	if db == nil {
		return false, nil
	}
	var ok bool
	err := db.QueryRow(ctx, `SELECT to_regclass('decisionlog.decisions') IS NOT NULL`).Scan(&ok)
	return ok, err
}

// decisionFilter is the query a list or a summary runs: the store always,
// the rest when given. outcome: allow | deny | conditional | error.
type decisionFilter struct {
	store                   string
	subject, resource       string // type:id, or a bare id
	action, outcome, listen string
	endpoint, actor, client string
	trace                   string // OpenTelemetry trace id
	from, to                time.Time
}

func parseDecisionFilter(r *http.Request, store string) (decisionFilter, error) {
	q := r.URL.Query()
	f := decisionFilter{store: store, subject: strings.TrimSpace(q.Get("subject")), resource: strings.TrimSpace(q.Get("resource")),
		action: strings.TrimSpace(q.Get("action")), outcome: q.Get("outcome"), listen: q.Get("listener"),
		endpoint: q.Get("endpoint"), actor: strings.TrimSpace(q.Get("actor")), client: strings.TrimSpace(q.Get("client")),
		trace: strings.ToLower(strings.TrimSpace(q.Get("trace")))}
	switch f.outcome {
	case "", "allow", "deny", "conditional", "error":
	default:
		return f, fmt.Errorf("outcome must be allow, deny, conditional or error")
	}
	for name, dst := range map[string]*time.Time{"from": &f.from, "to": &f.to} {
		if v := q.Get(name); v != "" {
			ts, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return f, fmt.Errorf("%s must be an RFC 3339 timestamp", name)
			}
			*dst = ts
		}
	}
	return f, nil
}

// where renders the filter as SQL conditions with positional arguments.
func (f decisionFilter) where() (string, []any) {
	conds := []string{"store = $1"}
	args := []any{f.store}
	add := func(c string, v any) {
		args = append(args, v)
		conds = append(conds, strings.ReplaceAll(c, "?", "$"+strconv.Itoa(len(args))))
	}
	ref := func(col, v string) {
		if typ, id, ok := strings.Cut(v, ":"); ok && typ != "" {
			add(col+"_type = ?", typ)
			if id != "" {
				add(col+"_id = ?", id)
			}
		} else {
			add(col+"_id = ?", v)
		}
	}
	if f.subject != "" {
		ref("subject", f.subject)
	}
	if f.resource != "" {
		ref("resource", f.resource)
	}
	if f.action != "" {
		add("action = ?", f.action)
	}
	if f.listen != "" {
		add("listener = ?", f.listen)
	}
	if f.endpoint != "" {
		add("endpoint = ?", f.endpoint)
	}
	if f.actor != "" {
		add("actor = ?", f.actor)
	}
	if f.client != "" {
		add("client = ?", f.client)
	}
	if f.trace != "" {
		add("trace_id = ?", f.trace)
	}
	switch f.outcome {
	case "allow":
		conds = append(conds, "decision = true AND coalesce(state, '') <> 'conditional'")
	case "deny":
		conds = append(conds, "decision = false AND coalesce(state, '') <> 'conditional'")
	case "conditional":
		conds = append(conds, "state = 'conditional'")
	case "error":
		conds = append(conds, "error IS NOT NULL")
	}
	if !f.from.IsZero() {
		add("ts >= ?", f.from)
	}
	if !f.to.IsZero() {
		add("ts < ?", f.to)
	}
	return strings.Join(conds, " AND "), args
}

const decisionColumns = `id, ts, coalesce(request_id,''), coalesce(trace_id,''), coalesce(span_id,''), listener, endpoint, coalesce(via,''),
	coalesce(subject_type,''), coalesce(subject_id,''), coalesce(action,''), coalesce(resource_type,''), coalesce(resource_id,''),
	decision, coalesce(state,''), coalesce(reason,''), coalesce(actor,''), coalesce(client,''), coalesce(issuer,''),
	coalesce(latency_ms, 0), coalesce(error,''), line`

// handleDecisions — GET .../decisions?subject=&resource=&action=&outcome=
// &listener=&endpoint=&actor=&client=&from=&to=&limit=&before=<ts>,<id>:
// the newest decisions first, paged by keyset.
func (s *Server) handleDecisions(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view_decisions")
	if p == nil {
		return
	}
	ctx := r.Context()
	ok, err := s.decisionsConfigured(ctx)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"configured": false, "rows": []decisionRow{}})
		return
	}
	f, err := parseDecisionFilter(r, store)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	cond, args := f.where()
	if before := r.URL.Query().Get("before"); before != "" {
		tsText, idText, ok := strings.Cut(before, ",")
		ts, err := time.Parse(time.RFC3339Nano, tsText)
		id, err2 := strconv.ParseInt(idText, 10, 64)
		if !ok || err != nil || err2 != nil {
			writeError(w, http.StatusBadRequest, "before must be <RFC 3339 timestamp>,<id> from the previous page")
			return
		}
		args = append(args, ts, id)
		cond += fmt.Sprintf(" AND (ts, id) < ($%d, $%d)", len(args)-1, len(args))
	}
	args = append(args, limit)
	rows, err := s.decisionsDB().Query(ctx, `SELECT `+decisionColumns+` FROM decisionlog.decisions WHERE `+cond+
		fmt.Sprintf(` ORDER BY ts DESC, id DESC LIMIT $%d`, len(args)), args...)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	defer rows.Close()
	out := []decisionRow{}
	for rows.Next() {
		var d decisionRow
		if err := rows.Scan(&d.ID, &d.TS, &d.RequestID, &d.TraceID, &d.SpanID, &d.Listener, &d.Endpoint, &d.Via,
			&d.SubjectType, &d.SubjectID, &d.Action, &d.ResourceType, &d.ResourceID,
			&d.Decision, &d.State, &d.Reason, &d.Actor, &d.Client, &d.Issuer, &d.LatencyMS, &d.Error, &d.Line); err != nil {
			writeEngineError(w, err)
			return
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		writeEngineError(w, err)
		return
	}
	next := ""
	if len(out) == limit {
		last := out[len(out)-1]
		next = last.TS.UTC().Format(time.RFC3339Nano) + "," + strconv.FormatInt(last.ID, 10)
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "rows": out, "next": next, "limit": limit})
}

// bucket is one row of a summary top list.
type bucket struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// handleDecisionsSummary — GET .../decisions/summary?from=&to=&... (the
// list's filters): how the decisions of the window divide by outcome, and
// the top reasons, actions and subjects among the denials — the
// intent-versus-behaviour view of ADR 0013.
func (s *Server) handleDecisionsSummary(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view_decisions")
	if p == nil {
		return
	}
	ctx := r.Context()
	ok, err := s.decisionsConfigured(ctx)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"configured": false})
		return
	}
	f, err := parseDecisionFilter(r, store)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if f.to.IsZero() {
		f.to = time.Now().UTC()
	}
	if f.from.IsZero() {
		f.from = f.to.Add(-24 * time.Hour)
	}
	cond, args := f.where()
	db := s.decisionsDB()
	var total, allow, deny, conditional, errs int64
	if err := db.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE decision = true AND coalesce(state,'') <> 'conditional'),
		       count(*) FILTER (WHERE decision = false AND coalesce(state,'') <> 'conditional'),
		       count(*) FILTER (WHERE state = 'conditional'),
		       count(*) FILTER (WHERE error IS NOT NULL)
		  FROM decisionlog.decisions WHERE `+cond, args...).Scan(&total, &allow, &deny, &conditional, &errs); err != nil {
		writeEngineError(w, err)
		return
	}
	top := func(expr, extra string) ([]bucket, error) {
		rows, err := db.Query(ctx, `SELECT `+expr+` AS k, count(*) FROM decisionlog.decisions WHERE `+cond+extra+
			` GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10`, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []bucket{}
		for rows.Next() {
			var c bucket
			if err := rows.Scan(&c.Key, &c.Count); err != nil {
				return nil, err
			}
			out = append(out, c)
		}
		return out, rows.Err()
	}
	denied := " AND decision = false"
	reasons, err := top(`coalesce(reason, '')`, denied)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	actions, err := top(`coalesce(action, '')`, denied)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	subjects, err := top(`coalesce(subject_type,'') || ':' || coalesce(subject_id,'')`, denied)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	allowedReasons, err := top(`coalesce(reason, '')`, " AND decision = true")
	if err != nil {
		writeEngineError(w, err)
		return
	}
	clients, err := top(`coalesce(client, '')`, denied)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": true, "from": f.from, "to": f.to,
		"total": total, "allow": allow, "deny": deny, "conditional": conditional, "error": errs,
		"denied_reasons": reasons, "denied_actions": actions, "denied_subjects": subjects,
		"allowed_reasons": allowedReasons, "denied_clients": clients,
	})
}
