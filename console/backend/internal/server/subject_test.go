package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Store → Data subject through the router: the gate, the
// export document (engine parts and the decision-log part), the erasure
// as the person with its counts, and that another subject is untouched.
func TestSubjectHTTP(t *testing.T) {
	s, pool, ctx := testServer(t)
	cs := s.cfg.ConsoleStore
	const store = "console_gotest_subject"
	_, _ = pool.Exec(ctx, `SELECT authz.delete_store($1, p_purge_audit => true)`, store)
	for _, stmt := range []string{
		`SELECT authz.create_store($1, 'subject test')`,
		`SELECT authz.model_register_type($1, 'user')`,
		`SELECT authz.model_register_type($1, 'doc')`,
		`SELECT authz.model_register_relation($1, 'owner')`,
		`SELECT authz.model_register_relation($1, 'viewer')`,
		`SELECT authz.model_register_relation($1, 'can_view')`,
		`SELECT authz.model_add_rule($1, 'doc', 'owner', 'direct')`,
		`SELECT authz.model_add_rule($1, 'doc', 'viewer', 'direct')`,
		`SELECT authz.model_add_rule($1, 'doc', 'can_view', 'computed', 'owner')`,
		`SELECT authz.write_tuple($1, 'user', 'alice', 'owner', 'doc', 'a')`,
		`SELECT authz.write_tuple($1, 'user', 'alice', 'viewer', 'doc', 'b')`,
		`SELECT authz.write_tuple($1, 'user', 'bob', 'owner', 'doc', 'z')`,
		`SELECT authz.record_event($1, 'user', 'alice', 'viewer', 'doc', 'b')`,
	} {
		if _, err := pool.Exec(ctx, stmt, store); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `SELECT authz.delete_store($1, p_purge_audit => true)`, store)
	}()
	for _, tu := range [][]string{{"subj_owner", "owner"}, {"subj_viewer", "viewer"}} {
		if _, err := pool.Exec(ctx, `SELECT authz.write_tuple($1, 'user', $2, $3, 'store', $4)`, cs, tu[0], tu[1], store); err != nil {
			t.Fatal(err)
		}
		defer func(tu []string) {
			_, _ = pool.Exec(context.Background(), `SELECT authz.delete_tuple($1, 'user', $2, $3, 'store', $4)`, cs, tu[0], tu[1], store)
		}(tu)
	}
	owner, viewer := httpSession(t, s, "subj_owner"), httpSession(t, s, "subj_viewer")
	h := s.Routes()
	do := func(method, target, body string, c *http.Cookie) (int, map[string]any, http.Header) {
		t.Helper()
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m, rec.Header()
	}
	base := "/api/stores/" + store + "/subject"

	if code, _, _ := do("GET", base+"?subject=user:alice", "", viewer); code != 403 {
		t.Fatalf("a viewer may not export: %d", code)
	}
	if code, _, _ := do("GET", base+"?subject=alice", "", owner); code != 400 {
		t.Fatalf("subject without a type: %d", code)
	}
	code, m, hdr := do("GET", base+"?subject=user:alice&download=1", "", owner)
	if code != 200 || !strings.Contains(hdr.Get("Content-Disposition"), "subject-"+store+"-user-alice.json") {
		t.Fatalf("export: %d %v %q", code, m, hdr.Get("Content-Disposition"))
	}
	if n := len(m["direct"].([]any)); n != 2 {
		t.Fatalf("direct tuples: %d", n)
	}
	if n := len(m["events"].([]any)); n != 1 {
		t.Fatalf("events: %d", n)
	}
	if m["exported_by"] != "user:subj_owner" || m["decisions_truncated"] != false {
		t.Fatalf("meta: %v %v", m["exported_by"], m["decisions_truncated"])
	}
	// the takeout rows as CSV, narrowed to a relation
	req := httptest.NewRequest("GET", base+"?subject=user:alice&format=csv&relations=can_view&download=1", nil)
	req.AddCookie(owner)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") || !strings.Contains(rec.Header().Get("Content-Disposition"), "objects.csv") {
		t.Fatalf("csv: %d %q %q", rec.Code, rec.Header().Get("Content-Type"), rec.Header().Get("Content-Disposition"))
	}
	if body := rec.Body.String(); !strings.HasPrefix(body, "store,subject_type,subject_id,object_type,relation,object_id,is_wildcard,direct,truncated\n") ||
		!strings.Contains(body, store+",user,alice,doc,can_view,a,false,false,false\n") || strings.Contains(body, ",viewer,") {
		t.Fatalf("csv body: %s", body)
	}
	// the decision-log part: a line of the subject when the sink exists
	var existed bool
	_ = s.db.QueryRow(ctx, `SELECT to_regclass('decisionlog.decisions') IS NOT NULL`).Scan(&existed)
	if !existed {
		if _, err := s.db.Exec(ctx, decisionsDDL); err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = s.db.Exec(context.Background(), `DROP SCHEMA decisionlog CASCADE`) }()
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO decisionlog.decisions (ts, listener, endpoint, store, subject_type, subject_id, action, decision, line)
		VALUES (now(), 'public', 'check', $1, 'user', 'alice', 'can_view', true, '{"subject_id":"alice"}')`, store); err != nil {
		t.Fatal(err)
	}
	// bob asked about alice as the RESOURCE: part of her data too (review #20)
	if _, err := s.db.Exec(ctx, `INSERT INTO decisionlog.decisions (ts, listener, endpoint, store, subject_type, subject_id, action, resource_type, resource_id, decision, line)
		VALUES (now(), 'public', 'check', $1, 'user', 'bob', 'can_read_user', 'user', 'alice', true, '{"subject_id":"bob","resource_id":"alice"}')`, store); err != nil {
		t.Fatal(err)
	}
	_, m, _ = do("GET", base+"?subject=user:alice", "", owner)
	if n := len(m["decisions"].([]any)); n != 1 {
		t.Fatalf("decision-log lines: %d (%v)", n, m["decisions"])
	}
	if n := len(m["decisions_about"].([]any)); n != 1 {
		t.Fatalf("decision-log lines about the subject: %d (%v)", n, m["decisions_about"])
	}
	// and an action bob recorded ON alice is in events_about
	if _, err := pool.Exec(ctx, `SELECT authz.model_register_relation($1, 'can_read_user')`, store); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `SELECT authz.record_event($1, 'user', 'bob', 'can_read_user', 'user', 'alice')`, store); err != nil {
		t.Fatal(err)
	}
	_, m, _ = do("GET", base+"?subject=user:alice", "", owner)
	if n := len(m["events_about"].([]any)); n != 1 {
		t.Fatalf("events about the subject: %d (%v)", n, m["events_about"])
	}

	// erase: viewers may not; the owner may, and the counts come back
	if code, _, _ := do("POST", base+"/erase", `{"subject":"user:alice"}`, viewer); code != 403 {
		t.Fatalf("a viewer may not erase: %d", code)
	}
	code, m, _ = do("POST", base+"/erase", `{"subject":"user:alice","purge_audit":true}`, owner)
	if code != 200 || m["tuples_as_subject"].(float64) != 2 || m["events"].(float64) != 2 || m["decisions"].(float64) != 2 || m["audit"].(float64) < 2 {
		t.Fatalf("erase (own + about): %d %v", code, m)
	}
	_, m, _ = do("GET", base+"?subject=user:alice", "", owner)
	if len(m["direct"].([]any)) != 0 || len(m["events"].([]any)) != 0 || len(m["events_about"].([]any)) != 0 || len(m["decisions"].([]any)) != 0 || len(m["decisions_about"].([]any)) != 0 || len(m["audit"].([]any)) != 0 {
		t.Fatalf("after the erasure: %v", m)
	}
	_, m, _ = do("GET", base+"?subject=user:bob", "", owner)
	if len(m["direct"].([]any)) != 1 {
		t.Fatalf("bob untouched: %v", m["direct"])
	}
	// recorded in the console's action log as the person
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.list_events($1, p_subject_type => 'user', p_subject_id => 'subj_owner', p_action => 'can_manage_access', p_object_id => $2, p_limit => 10)`, cs, store).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatal("the erasure is not in the action log")
	}
}
