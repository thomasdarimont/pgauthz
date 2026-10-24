package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The sink table as pgauthzd creates it (pgauthzd/internal/decisionlog
// DDL) — the console only reads it; a test creates the same shape.
const decisionsDDL = `
CREATE SCHEMA IF NOT EXISTS decisionlog;
CREATE TABLE IF NOT EXISTS decisionlog.decisions (
    id bigint GENERATED ALWAYS AS IDENTITY, ts timestamptz NOT NULL, request_id text, trace_id text, span_id text, listener text NOT NULL,
    endpoint text NOT NULL, via text, store text NOT NULL, subject_type text, subject_id text, action text,
    resource_type text, resource_id text, decision boolean, state text, reason text, actor text, client text,
    issuer text, latency_ms real, error text, line jsonb NOT NULL
) PARTITION BY RANGE (ts);
CREATE TABLE IF NOT EXISTS decisionlog.decisions_default PARTITION OF decisionlog.decisions DEFAULT;
CREATE TABLE IF NOT EXISTS decisionlog.erasures (
    store text NOT NULL, subject_type text NOT NULL, subject_id text NOT NULL,
    erased_at timestamptz NOT NULL DEFAULT now(), erased_by text,
    PRIMARY KEY (store, subject_type, subject_id, erased_at));`

// The Decisions tab: not configured without the sink table; then the
// list (newest first, filters, keyset paging) and the summary (outcomes
// and the denied top lists) for the store, under can_view_decisions.
func TestDecisionsHTTP(t *testing.T) {
	s, pool, ctx := testServer(t)
	cs := s.cfg.ConsoleStore
	const store = "console_gotest_decisions"
	_, _ = pool.Exec(ctx, `SELECT authz.delete_store($1, p_purge_audit => true)`, store)
	if _, err := pool.Exec(ctx, `SELECT authz.create_store($1, 'decisions test')`, store); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `SELECT authz.delete_store($1, p_purge_audit => true)`, store)
	}()
	for _, tu := range [][]string{{"dec_owner", "owner"}, {"dec_tester", "tester"}} {
		if _, err := pool.Exec(ctx, `SELECT authz.write_tuple($1, 'user', $2, $3, 'store', $4)`, cs, tu[0], tu[1], store); err != nil {
			t.Fatal(err)
		}
		defer func(tu []string) {
			_, _ = pool.Exec(context.Background(), `SELECT authz.delete_tuple($1, 'user', $2, $3, 'store', $4)`, cs, tu[0], tu[1], store)
		}(tu)
	}
	owner, tester := httpSession(t, s, "dec_owner"), httpSession(t, s, "dec_tester")
	h := s.Routes()
	get := func(target string, c *http.Cookie) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/stores/"+store+"/decisions"+target, nil)
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m
	}

	// a tester holds no can_view_decisions
	if code, m := get("", tester); code != 403 {
		t.Fatalf("tester: %d %v, want 403", code, m)
	}
	// no sink table: not configured, not an error
	var existed bool
	_ = s.db.QueryRow(ctx, `SELECT to_regclass('decisionlog.decisions') IS NOT NULL`).Scan(&existed)
	if !existed {
		if code, m := get("", owner); code != 200 || m["configured"] != false {
			t.Fatalf("without the table: %d %v, want configured=false", code, m)
		}
		if _, err := s.db.Exec(ctx, decisionsDDL); err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = s.db.Exec(context.Background(), `DROP SCHEMA decisionlog CASCADE`) }()
	}
	defer func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM decisionlog.decisions WHERE store = $1`, store)
	}()

	base := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	ins := func(i int, subject, action, resource string, decision any, state, reason, errText string) {
		t.Helper()
		st, sid, _ := splitRef(subject)
		rt, rid, _ := splitRef(resource)
		line, _ := json.Marshal(map[string]any{"ts": base.Add(time.Duration(i) * time.Minute), "store": store, "endpoint": "check", "subject": map[string]string{"type": st, "id": sid}, "context_keys": []string{"ip"}})
		if _, err := s.db.Exec(ctx, `INSERT INTO decisionlog.decisions (ts, request_id, trace_id, span_id, listener, endpoint, via, store, subject_type, subject_id, action, resource_type, resource_id, decision, state, reason, actor, client, latency_ms, error, line)
			VALUES ($1, $2, $14, 'aaaaaaaaaaaaaaaa', 'public', 'check', 'engine', $3, $4, $5, $6, $7, $8, $9, nullif($10,''), nullif($11,''), 'service:pep', $15, 0.7, nullif($12,''), $13)`,
			base.Add(time.Duration(i)*time.Minute), "req-"+subject, store, st, sid, action, rt, rid, decision, state, reason, errText, line,
			fmt.Sprintf("%032x", i), map[bool]string{true: "docs-app", false: "mail-app"}[i%2 == 1]); err != nil {
			t.Fatal(err)
		}
	}
	ins(1, "user:alice", "can_read", "doc:a", true, "allow", "direct_tuple", "")
	ins(2, "user:bob", "can_read", "doc:a", false, "deny", "no_matching_rule", "")
	ins(3, "user:bob", "can_write", "doc:b", false, "deny", "no_matching_rule", "")
	ins(4, "user:carol", "can_read", "doc:b", false, "conditional", "condition_denied", "")
	ins(5, "user:dave", "can_read", "doc:c", nil, "", "", "engine: timeout")
	// another store's lines never show
	if _, err := s.db.Exec(ctx, `INSERT INTO decisionlog.decisions (ts, listener, endpoint, store, subject_type, subject_id, decision, line) VALUES ($1, 'public', 'check', 'other_store', 'user', 'zed', true, '{}')`, base); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM decisionlog.decisions WHERE store = 'other_store'`)
	}()

	rowsOf := func(m map[string]any) []map[string]any {
		var out []map[string]any
		for _, r := range m["rows"].([]any) {
			out = append(out, r.(map[string]any))
		}
		return out
	}
	// newest first, this store only
	code, m := get("", owner)
	rows := rowsOf(m)
	if code != 200 || m["configured"] != true || len(rows) != 5 || rows[0]["subject_id"] != "dave" || rows[4]["subject_id"] != "alice" {
		t.Fatalf("list: %d %v", code, m)
	}
	if rows[0]["error"] != "engine: timeout" || rows[0]["decision"] != nil {
		t.Errorf("error row: %v", rows[0])
	}
	// filters
	if _, m := get("?subject=user:bob", owner); len(rowsOf(m)) != 2 {
		t.Errorf("subject filter: %v", m)
	}
	if _, m := get("?subject=bob&action=can_write", owner); len(rowsOf(m)) != 1 {
		t.Errorf("bare id + action: %v", m)
	}
	if _, m := get("?resource=doc:a&outcome=deny", owner); len(rowsOf(m)) != 1 || rowsOf(m)[0]["subject_id"] != "bob" {
		t.Errorf("resource + deny: %v", m)
	}
	if _, m := get("?outcome=conditional", owner); len(rowsOf(m)) != 1 || rowsOf(m)[0]["reason"] != "condition_denied" {
		t.Errorf("conditional: %v", m)
	}
	if _, m := get("?outcome=error", owner); len(rowsOf(m)) != 1 {
		t.Errorf("error: %v", m)
	}
	if _, m := get("?from="+base.Add(3*time.Minute).Format(time.RFC3339)+"&to="+base.Add(5*time.Minute).Format(time.RFC3339), owner); len(rowsOf(m)) != 2 {
		t.Errorf("window [3,5): %v", m)
	}
	if code, _ := get("?outcome=maybe", owner); code != 400 {
		t.Errorf("bad outcome: %d", code)
	}
	// the trace id joins a line to the application's request; the client says which app asked
	if _, m := get("?trace="+fmt.Sprintf("%032X", 2), owner); len(rowsOf(m)) != 1 || rowsOf(m)[0]["subject_id"] != "bob" || rowsOf(m)[0]["trace_id"] != fmt.Sprintf("%032x", 2) {
		t.Errorf("trace filter (case-insensitive): %v", m)
	}
	if _, m := get("?client=mail-app", owner); len(rowsOf(m)) != 2 {
		t.Errorf("client filter: %v", m)
	}
	if _, m := get("?reason=no_matching_rule", owner); len(rowsOf(m)) == 0 {
		t.Errorf("reason filter: %v", m)
	}
	if _, m := get("?reason=nope", owner); len(rowsOf(m)) != 0 {
		t.Errorf("reason filter (no match): %v", m)
	}
	// keyset paging: 2 + 2 + 1
	_, m = get("?limit=2", owner)
	if len(rowsOf(m)) != 2 || m["next"] == "" {
		t.Fatalf("page 1: %v", m)
	}
	_, m2 := get("?limit=2&before="+m["next"].(string), owner)
	if len(rowsOf(m2)) != 2 || rowsOf(m2)[0]["subject_id"] != "bob" || rowsOf(m2)[1]["subject_id"] != "bob" {
		t.Fatalf("page 2: %v", m2)
	}
	_, m3 := get("?limit=2&before="+m2["next"].(string), owner)
	if len(rowsOf(m3)) != 1 || rowsOf(m3)[0]["subject_id"] != "alice" || m3["next"] != "" {
		t.Fatalf("page 3: %v", m3)
	}

	// the summary over the window
	code, sm := get("/summary?from="+base.Format(time.RFC3339)+"&to="+base.Add(time.Hour).Format(time.RFC3339), owner)
	if code != 200 || sm["total"] != float64(5) || sm["allow"] != float64(1) || sm["deny"] != float64(2) || sm["conditional"] != float64(1) || sm["error"] != float64(1) {
		t.Fatalf("summary: %d %v", code, sm)
	}
	top := func(k string) []any { return sm[k].([]any) }
	if r := top("denied_subjects"); len(r) == 0 || r[0].(map[string]any)["key"] != "user:bob" || r[0].(map[string]any)["count"] != float64(2) {
		t.Errorf("denied subjects: %v", sm["denied_subjects"])
	}
	if r := top("denied_reasons"); len(r) == 0 || r[0].(map[string]any)["key"] != "no_matching_rule" {
		t.Errorf("denied reasons: %v", sm["denied_reasons"])
	}
	if r := top("denied_clients"); len(r) != 2 {
		t.Errorf("denied clients: %v", sm["denied_clients"])
	}
	if code, _ := get("/summary", tester); code != 403 {
		t.Errorf("tester summary: %d", code)
	}
}

// The decision filters reach the SQL as bound arguments only: a value
// shaped like an injection matches nothing and breaks nothing, and the
// rendered text carries no request value.
func TestDecisionsFilterIsParameterised(t *testing.T) {
	hostile := "' OR 1=1 -- "
	q := url.Values{}
	for _, k := range []string{"subject", "resource", "action", "client", "reason", "actor", "listener", "endpoint", "trace"} {
		q.Set(k, hostile)
	}
	f, err := parseDecisionFilter(httptest.NewRequest("GET", "/?"+q.Encode(), nil), "s\"; DROP TABLE x; --")
	if err != nil {
		t.Fatal(err)
	}
	cond, args := f.where()
	if strings.Contains(cond, "OR 1=1") || strings.Contains(cond, "DROP") || strings.Contains(cond, hostile) {
		t.Fatalf("a request value reached the SQL text: %s", cond)
	}
	if n := strings.Count(cond, "$"); n != len(args) {
		t.Fatalf("%d placeholders for %d arguments: %s", n, len(args), cond)
	}
	for i := range args {
		if !strings.Contains(cond, "$"+strconv.Itoa(i+1)) {
			t.Fatalf("argument %d is not referenced: %s", i+1, cond)
		}
	}
}
