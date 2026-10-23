package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The scenarios endpoints through the router: save (validated, as the
// person), load, run against the store's current model in an ephemeral
// store (a failing assertion is a result, not an error), the test policy's
// gate for a plain tester, and the export for pgauthzctl.
func TestScenariosHTTP(t *testing.T) {
	s, pool, ctx := testServer(t)
	cs := s.cfg.ConsoleStore
	const store = "console_gotest_scenarios"
	_, _ = pool.Exec(ctx, `SELECT authz.delete_store($1, p_purge_audit => true)`, store)
	for _, stmt := range []string{
		`SELECT authz.create_store($1, 'scenarios test')`,
		`SELECT authz.model_register_type($1, 'user')`,
		`SELECT authz.model_register_type($1, 'doc')`,
		`SELECT authz.model_register_relation($1, 'owner')`,
		`SELECT authz.model_register_relation($1, 'viewer')`,
		`SELECT authz.model_register_relation($1, 'can_read', NULL, '{"kind": "permission"}'::jsonb)`,
		`SELECT authz.model_add_rule($1, 'doc', 'owner', 'direct')`,
		`SELECT authz.model_add_rule($1, 'doc', 'viewer', 'direct')`,
		`SELECT authz.model_add_rule($1, 'doc', 'can_read', 'computed', 'viewer')`,
		`SELECT authz.model_add_rule($1, 'doc', 'can_read', 'computed', 'owner')`,
		// the store's own data must NOT leak into a run: alice owns doc:x here
		`SELECT authz.write_tuple($1, 'user', 'alice', 'owner', 'doc', 'x')`,
	} {
		if _, err := pool.Exec(ctx, stmt, store); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `SELECT authz.delete_store($1, p_purge_audit => true)`, store)
	}()
	for _, tu := range [][]string{
		{"scn_owner", "owner"}, {"scn_tester", "tester"},
	} {
		if _, err := pool.Exec(ctx, `SELECT authz.write_tuple($1, 'user', $2, $3, 'store', $4)`, cs, tu[0], tu[1], store); err != nil {
			t.Fatal(err)
		}
		defer func(tu []string) {
			_, _ = pool.Exec(context.Background(), `SELECT authz.delete_tuple($1, 'user', $2, $3, 'store', $4)`, cs, tu[0], tu[1], store)
		}(tu)
	}
	owner, tester := httpSession(t, s, "scn_owner"), httpSession(t, s, "scn_tester")
	defer func() { _, _ = s.db.Exec(context.Background(), `DELETE FROM scenarios WHERE store = $1`, store) }()

	h := s.Routes()
	do := func(method, target, body string, c *http.Cookie) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m
	}
	base := "/api/stores/" + store + "/scenarios"
	body := func(yml string) string {
		b, _ := json.Marshal(map[string]string{"yaml": yml})
		return string(b)
	}

	// nothing saved yet; the owner may edit
	if code, m := do("GET", base, "", owner); code != 200 || m["yaml"] != "" || m["can_edit"] != true {
		t.Fatalf("empty scenarios: %d %v", code, m)
	}
	// model_file is refused, a bad reference too
	if code, m := do("PUT", base, body("model_file: ./m.fga\ntests: []\n"), owner); code != 400 {
		t.Errorf("model_file accepted: %d %v", code, m)
	}
	if code, m := do("PUT", base, body("tuples:\n  - user: alice\n    relation: viewer\n    object: doc:a\n"), owner); code != 400 {
		t.Errorf("bad reference accepted: %d %v", code, m)
	}
	if code, m := do("PUT", base, body("store: gdrive\ntests: []\n"), owner); code != 400 {
		t.Errorf("another store's model accepted: %d %v", code, m)
	}
	// the editor's validation: a YAML error names its line, a semantic one does not
	if code, m := do("POST", base+"/validate", body("tests:\n  - name: x: y\n"), owner); code != 200 || m["ok"] != false || m["line"] != float64(2) {
		t.Errorf("validate yaml error: %d %v, want ok=false line=2", code, m)
	}
	if code, m := do("POST", base+"/validate", body("tuples:\n  - user: alice\n    relation: viewer\n    object: doc:a\n"), owner); code != 200 || m["ok"] != false || m["line"] != nil {
		t.Errorf("validate reference error: %d %v, want ok=false without a line", code, m)
	}
	if code, m := do("POST", base+"/validate", body("tests:\n  - name: t\n    check:\n      - user: user:bob\n        object: doc:a\n        assertions: { can_read: true }\n"), owner); code != 200 || m["ok"] != true || m["cases"] != float64(1) {
		t.Errorf("validate ok: %d %v, want ok=true cases=1", code, m)
	} else if fx, _ := m["fixture"].(map[string]any); fx["store"] != nil || len(fx["tests"].([]any)) != 1 {
		t.Errorf("validate fixture: %v, want the parsed tests without the implied store", fx)
	}
	// a tester may not save
	const fixture = `tuples:
  - user: user:bob
    relation: viewer
    object: doc:a
tests:
  - name: bob reads a
    check:
      - user: user:bob
        object: doc:a
        assertions: { can_read: true, owner: false }
  - name: alice owns nothing here
    check:
      - user: user:alice
        object: doc:x
        assertions: { can_read: false }
  - name: sets
    list_actions:
      - user: user:bob
        object: doc:a
        expect: [viewer, can_read]
    list_subjects:
      - object: doc:a
        type: user
        assertions: { can_read: [user:bob] }
`
	if code, m := do("PUT", base, body(fixture), tester); code != 403 {
		t.Errorf("tester saved scenarios: %d %v", code, m)
	}
	if code, m := do("PUT", base, body(fixture), owner); code != 200 || m["cases"] != float64(5) {
		t.Fatalf("save: %d %v", code, m)
	}
	if code, m := do("GET", base, "", owner); code != 200 || m["yaml"] != fixture || m["updated_by"] != "user:scn_owner" || m["cases"] != float64(5) {
		t.Errorf("load after save: %d %v", code, m)
	}

	// run the saved fixture: hermetic (alice's ownership in the store does not
	// reach the ephemeral one), all three pass
	code, m := do("POST", base+"/run", body(""), owner)
	if code != 200 || m["passed"] != float64(5) || m["failed"] != float64(0) {
		t.Fatalf("run: %d %v", code, m)
	}
	if prov, _ := m["model"].(map[string]any); prov["store"] != store || prov["checksum"] == "" || prov["checksum"] == nil {
		t.Errorf("run provenance: %v, want the store and its live model's checksum", m["model"])
	}
	// only the second test: its result keeps index 1
	code, m = do("POST", base+"/run", `{"yaml":"","only":[1]}`, owner)
	if res, _ := m["results"].([]any); code != 200 || len(res) != 1 || res[0].(map[string]any)["test"] != float64(1) {
		t.Errorf("run only [1]: %d %v", code, m)
	}
	if code, m := do("POST", base+"/run", `{"yaml":"","only":[7]}`, owner); code != 400 {
		t.Errorf("run only [7]: %d %v, want 400", code, m)
	}
	// explain one assertion inside the fixture: a tree, from the ephemeral store
	code, m = do("POST", base+"/explain", `{"yaml":"","test":0,"user":"user:bob","relation":"can_read","object":"doc:a"}`, owner)
	if tree, _ := m["tree"].(map[string]any); code != 200 || tree == nil {
		t.Errorf("explain: %d %v", code, m)
	}
	if code, m := do("POST", base+"/explain", `{"yaml":"","test":0,"user":"user:bob","relation":"can_read","object":"doc:a","successful_only":true,"redact":true}`, owner); code != 200 || m["redacted"] != true || m["successful_only"] != true {
		t.Errorf("explain with options: %d %v", code, m)
	}
	if code, m := do("POST", base+"/explain", `{"yaml":"","test":0,"user":"user:bob","relation":"owner","object":"doc:zzz"}`, owner); code != 404 {
		t.Errorf("explain of a missing assertion: %d %v, want 404", code, m)
	}
	if code, m := do("POST", base+"/explain", `{"yaml":"","test":0,"user":"user:bob","relation":"can_read","object":"doc:a"}`, tester); code != 403 {
		t.Errorf("tester explained: %d %v, want 403", code, m)
	}
	// a draft with a wrong expectation: a failed result, not an error
	code, m = do("POST", base+"/run", body(strings.Replace(fixture, "can_read: true, owner: false", "can_read: false, owner: false", 1)), owner)
	if code != 200 || m["failed"] != float64(1) || m["passed"] != float64(4) {
		t.Errorf("failing draft: %d %v", code, m)
	}
	// no ephemeral store survives a run
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.stores WHERE name LIKE 'console_scenarios_%'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("ephemeral stores left: %v %d", err, n)
	}
	// the test policy: a plain tester decides only for themself
	if code, m := do("POST", base+"/run", body(""), tester); code != 403 || m["required"] != "can_test_others" {
		t.Errorf("tester ran scenarios: %d %v", code, m)
	}

	// export for pgauthzctl: model_file filled in, the model as DSL beside it
	code, m = do("GET", base+"/export", "", owner)
	yml, _ := m["yaml"].(string)
	dsl, _ := m["model_fga"].(string)
	if code != 200 || !strings.HasPrefix(yml, "model_file: ./model.fga\n") || !strings.Contains(dsl, "type doc") {
		t.Errorf("export: %d yaml=%q dsl=%q", code, yml, dsl)
	}

	// the Test tab's actions mode on the same store: what alice holds and may do
	code, m = do("POST", "/api/stores/"+store+"/actions", `{"subject":"user:alice","resource":"doc:x"}`, owner)
	if acts, _ := m["actions"].([]any); code != 200 || len(acts) != 2 || acts[0] != "can_read" || acts[1] != "owner" {
		t.Errorf("actions: %d %v, want [can_read owner]", code, m)
	}
	if code, m := do("POST", "/api/stores/"+store+"/actions", `{"subject":"user:alice","resource":"doc:x"}`, tester); code != 403 || m["required"] != "can_test_others" {
		t.Errorf("tester asked for another's actions: %d %v, want 403", code, m)
	}
	if code, m := do("POST", "/api/stores/"+store+"/actions", `{"subject":"alice","resource":"doc:x"}`, owner); code != 400 {
		t.Errorf("bad subject: %d %v, want 400", code, m)
	}

	// deleting: an empty save
	if code, m := do("PUT", base, body(""), owner); code != 200 {
		t.Errorf("clear: %d %v", code, m)
	}
	if code, m := do("GET", base+"/export", "", owner); code != 404 {
		t.Errorf("export after clear: %d %v", code, m)
	}
}
