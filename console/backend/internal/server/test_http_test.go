package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Contextual tuples through the Test tab's endpoints: a single check, its
// resolution tree, the matrix, both enumerating searches and the actions
// — each decided with the ephemeral tuples of the request and nothing
// written; the test policy unchanged (another subject still needs
// can_test_others); a point-in-time check refuses them; a malformed tuple
// is a 400.
func TestContextualTuplesHTTP(t *testing.T) {
	s, pool, ctx := testServer(t)
	cs := s.cfg.ConsoleStore
	const store = "console_gotest_ctx"
	_, _ = pool.Exec(ctx, `SELECT authz.delete_store($1, p_purge_audit => true)`, store)
	for _, stmt := range []string{
		`SELECT authz.create_store($1, 'contextual tuples test')`,
		`SELECT authz.model_register_type($1, 'user')`,
		`SELECT authz.model_register_type($1, 'team')`,
		`SELECT authz.model_register_type($1, 'doc')`,
		`SELECT authz.model_register_relation($1, 'member')`,
		`SELECT authz.model_register_relation($1, 'viewer')`,
		`SELECT authz.model_register_relation($1, 'can_read', NULL, '{"kind": "permission"}'::jsonb)`,
		`SELECT authz.model_add_rule($1, 'team', 'member', 'direct')`,
		`SELECT authz.model_add_rule($1, 'doc', 'viewer', 'direct')`,
		`SELECT authz.model_add_rule($1, 'doc', 'can_read', 'computed', 'viewer')`,
		// stored: only alice views doc:x; frank has nothing, doc:y has no tuples
		`SELECT authz.write_tuple($1, 'user', 'alice', 'viewer', 'doc', 'x')`,
	} {
		if _, err := pool.Exec(ctx, stmt, store); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `SELECT authz.delete_store($1, p_purge_audit => true)`, store)
	}()
	for _, tu := range [][]string{{"ctx_owner", "owner"}, {"ctx_tester", "tester"}} {
		if _, err := pool.Exec(ctx, `SELECT authz.write_tuple($1, 'user', $2, $3, 'store', $4)`, cs, tu[0], tu[1], store); err != nil {
			t.Fatal(err)
		}
		defer func(tu []string) {
			_, _ = pool.Exec(context.Background(), `SELECT authz.delete_tuple($1, 'user', $2, $3, 'store', $4)`, cs, tu[0], tu[1], store)
		}(tu)
	}
	owner, tester := httpSession(t, s, "ctx_owner"), httpSession(t, s, "ctx_tester")

	h := s.Routes()
	do := func(target, body string, c *http.Cookie) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest("POST", "/api/stores/"+store+"/"+target, strings.NewReader(body))
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m
	}
	const frankViewsY = `"contextual_tuples":[{"user":"user:frank","relation":"viewer","object":"doc:y"}]`

	// the single check: denied as stored, allowed with the hypothetical grant
	if code, m := do("check", `{"subject":"user:frank","action":"can_read","resource":"doc:y"}`, owner); code != 200 || m["allowed"] != false {
		t.Fatalf("stored check: %d %v, want denied", code, m)
	}
	if code, m := do("check", `{"subject":"user:frank","action":"can_read","resource":"doc:y",`+frankViewsY+`}`, owner); code != 200 || m["allowed"] != true {
		t.Fatalf("contextual check: %d %v, want allowed", code, m)
	}
	// a userset tuple works too: frank as a member of a team that views
	if code, m := do("check", `{"subject":"user:frank","action":"can_read","resource":"doc:y","contextual_tuples":[
		{"user":"user:frank","relation":"member","object":"team:eng"},
		{"user":"team:eng#member","relation":"viewer","object":"doc:y"}]}`, owner); code != 200 || m["allowed"] != true {
		t.Fatalf("userset contextual check: %d %v, want allowed", code, m)
	}
	// nothing was written
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.tuples t JOIN authz.stores s ON s.id = t.store_id WHERE s.name = $1`, store).Scan(&n); err != nil || n != 1 {
		t.Fatalf("stored tuples after contextual checks: %d %v, want 1", n, err)
	}

	// the resolution tree names the contextual step
	if code, m := do("explain", `{"subject":"user:frank","action":"can_read","resource":"doc:y",`+frankViewsY+`}`, owner); code != 200 {
		t.Fatalf("contextual explain: %d %v", code, m)
	} else {
		trace, _ := m["trace"].([]any)
		found := false
		for _, st := range trace {
			if sm, _ := st.(map[string]any); sm["reason"] == "contextual_tuple" && sm["result"] == true {
				found = true
			}
		}
		if dec, _ := m["decision"].(map[string]any); !found || dec["allowed"] != true {
			t.Errorf("contextual explain: no contextual_tuple step or not allowed: %v", m)
		}
	}

	// the matrix: the tuples are shared by every cell
	if code, m := do("check/batch", `{"subjects":["user:frank","user:alice"],"actions":["can_read"],"resources":["doc:y"],`+frankViewsY+`}`, owner); code != 200 {
		t.Fatalf("contextual matrix: %d %v", code, m)
	} else {
		got := map[string]any{}
		for _, c := range m["cells"].([]any) {
			cm := c.(map[string]any)
			got[cm["subject"].(string)] = cm["allowed"]
		}
		if got["user:frank"] != true || got["user:alice"] != false {
			t.Errorf("contextual matrix cells: %v, want frank allowed, alice denied", got)
		}
	}

	// both searches walk the contextual tuple: doc:y has no stored tuples at all
	hits := func(m map[string]any) []string {
		var ids []string
		for _, x := range m["hits"].([]any) {
			ids = append(ids, x.(map[string]any)["id"].(string))
		}
		return ids
	}
	if code, m := do("search", `{"mode":"objects","subject":"user:frank","action":"can_read","resource":"doc",`+frankViewsY+`}`, owner); code != 200 || strings.Join(hits(m), ",") != "y" {
		t.Errorf("contextual list_objects: %d %v, want [y]", code, m)
	}
	if code, m := do("search", `{"mode":"objects","subject":"user:frank","action":"can_read","resource":"doc"}`, owner); code != 200 || len(hits(m)) != 0 {
		t.Errorf("stored list_objects: %d %v, want none", code, m)
	}
	if code, m := do("search", `{"mode":"subjects","subject":"user","action":"can_read","resource":"doc:y",`+frankViewsY+`}`, owner); code != 200 || strings.Join(hits(m), ",") != "frank" {
		t.Errorf("contextual list_subjects: %d %v, want [frank]", code, m)
	}
	if code, m := do("actions", `{"subject":"user:frank","resource":"doc:y",`+frankViewsY+`}`, owner); code != 200 {
		t.Errorf("contextual actions: %d %v", code, m)
	} else if acts, _ := m["actions"].([]any); len(acts) != 2 || acts[0] != "can_read" || acts[1] != "viewer" {
		t.Errorf("contextual actions: %v, want [can_read viewer]", m)
	}

	// the policy is unchanged: a plain tester may not ask about frank, tuples or not
	if code, m := do("check", `{"subject":"user:frank","action":"can_read","resource":"doc:y",`+frankViewsY+`}`, tester); code != 403 || m["required"] != "can_test_others" {
		t.Errorf("tester with contextual tuples about another: %d %v, want 403", code, m)
	}
	// ... but may ask about themselves with a hypothetical grant
	if code, m := do("check", `{"subject":"user:ctx_tester","action":"can_read","resource":"doc:y","contextual_tuples":[{"user":"user:ctx_tester","relation":"viewer","object":"doc:y"}]}`, tester); code != 200 || m["allowed"] != true {
		t.Errorf("tester's own hypothetical: %d %v, want allowed", code, m)
	}

	// live only: a point-in-time check replays the audit trail
	if code, _ := do("check", `{"subject":"user:frank","action":"can_read","resource":"doc:y","at":"2026-01-01T00:00:00Z",`+frankViewsY+`}`, owner); code != 400 {
		t.Errorf("contextual check at an instant: %d, want 400", code)
	}
	// malformed tuples are refused before anything runs
	for _, bad := range []string{
		`[{"user":"frank","relation":"viewer","object":"doc:y"}]`,
		`[{"user":"user:frank","object":"doc:y"}]`,
	} {
		for _, ep := range []string{"check", "explain", "check/batch", "search", "actions"} {
			body := `{"subject":"user:frank","action":"can_read","resource":"doc:y","subjects":["user:frank"],"actions":["can_read"],"resources":["doc:y"],"mode":"objects","contextual_tuples":` + bad + `}`
			if ep == "search" {
				body = `{"mode":"objects","subject":"user:frank","action":"can_read","resource":"doc","contextual_tuples":` + bad + `}`
			}
			if code, m := do(ep, body, owner); code != 400 {
				t.Errorf("%s with malformed contextual tuple %s: %d %v, want 400", ep, bad, code, m)
			}
		}
	}
}
