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
`
	if code, m := do("PUT", base, body(fixture), tester); code != 403 {
		t.Errorf("tester saved scenarios: %d %v", code, m)
	}
	if code, m := do("PUT", base, body(fixture), owner); code != 200 || m["cases"] != float64(3) {
		t.Fatalf("save: %d %v", code, m)
	}
	if code, m := do("GET", base, "", owner); code != 200 || m["yaml"] != fixture || m["updated_by"] != "user:scn_owner" || m["cases"] != float64(3) {
		t.Errorf("load after save: %d %v", code, m)
	}

	// run the saved fixture: hermetic (alice's ownership in the store does not
	// reach the ephemeral one), all three pass
	code, m := do("POST", base+"/run", body(""), owner)
	if code != 200 || m["passed"] != float64(3) || m["failed"] != float64(0) {
		t.Fatalf("run: %d %v", code, m)
	}
	// a draft with a wrong expectation: a failed result, not an error
	code, m = do("POST", base+"/run", body(strings.Replace(fixture, "can_read: true, owner: false", "can_read: false, owner: false", 1)), owner)
	if code != 200 || m["failed"] != float64(1) || m["passed"] != float64(2) {
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

	// deleting: an empty save
	if code, m := do("PUT", base, body(""), owner); code != 200 {
		t.Errorf("clear: %d %v", code, m)
	}
	if code, m := do("GET", base+"/export", "", owner); code != 404 {
		t.Errorf("export after clear: %d %v", code, m)
	}
}
