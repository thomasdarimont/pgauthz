package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// httpSession opens a signed-in session for username the way the OIDC
// callback does — a row in the sessions table holding an (unverified, as
// in production) JWT whose claims the principal is built from — and returns
// the cookie a browser would send. The sessions table lives in the BFF's
// own database; here that is the test database, created on demand.
func httpSession(t *testing.T, s *Server, username string) *http.Cookie {
	t.Helper()
	ctx := context.Background()
	if s.db == nil {
		s.db = s.engine
		// InitSchema's tables (sessions, scenarios): created here, dropped
		// afterwards when this test created them.
		for _, table := range []string{"sessions", "scenarios"} {
			var existed bool
			if err := s.db.QueryRow(ctx, `SELECT to_regclass('public.'||$1) IS NOT NULL`, table).Scan(&existed); err != nil {
				t.Fatal(err)
			}
			if !existed {
				t.Cleanup(func() { _, _ = s.engine.Exec(context.Background(), `DROP TABLE IF EXISTS public.`+table) })
			}
		}
		if err := InitSchema(ctx, s.db); err != nil {
			t.Fatal(err)
		}
	}
	claims, _ := json.Marshal(map[string]any{"preferred_username": username, "name": "Test " + username})
	jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims) + ".x"
	id := "test-" + randToken(8)
	if _, err := s.db.Exec(ctx, `INSERT INTO sessions (id, access_token, username, expires_at) VALUES ($1, $2, $3, $4)`,
		id, jwt, username, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.db.Exec(context.Background(), `DELETE FROM sessions WHERE id = $1`, id) })
	return &http.Cookie{Name: sessionCookie, Value: id}
}

// The share endpoints through the router, as the browser reaches them:
// the console gate (401 / 403 for a viewer / namespace-scoped for a
// namespace author), malformed payloads, the holders listing (offered
// relations only, live tuples only, capped per relation with the full
// count), and the actor contract — a sharer acts as a chosen subject, and
// the engine's grant rules decide for THAT subject, while the console's
// action log names who acted as whom.
func TestShareHTTP(t *testing.T) {
	s, pool, ctx := testServer(t)
	cs := s.cfg.ConsoleStore
	const store = "console_gotest_share_http"
	_, _ = pool.Exec(ctx, `SELECT authz.delete_store($1, p_purge_audit => true)`, store)
	for _, stmt := range []string{
		`SELECT authz.create_store($1, 'share http test')`,
		`SELECT authz.model_register_type($1, 'user')`,
		`SELECT authz.model_register_type($1, 'doc', 0, 'docs')`,
		`SELECT authz.model_register_type($1, 'file', 0, 'files')`,
		// the fixture's own writes: the test's database role may write both namespaces
		`SELECT authz.grant_namespace_access($1, 'docs', current_user::text, true, true)`,
		`SELECT authz.grant_namespace_access($1, 'files', current_user::text, true, true)`,
		`SELECT authz.model_register_relation($1, 'owner')`,
		`SELECT authz.model_register_relation($1, 'viewer')`,
		`SELECT authz.model_register_relation($1, 'can_share', NULL, '{"kind": "permission"}'::jsonb)`,
		`SELECT authz.model_add_rule($1, 'doc', 'owner', 'direct')`,
		`SELECT authz.model_add_rule($1, 'doc', 'viewer', 'direct')`,
		`SELECT authz.model_add_type_restriction($1, 'doc', 'viewer', 'user')`,
		`SELECT authz.model_add_rule($1, 'doc', 'can_share', 'computed', 'owner')`,
		`SELECT authz.model_add_grant_rule($1, 'doc', 'viewer', 'can_share')`,
		`SELECT authz.model_add_rule($1, 'file', 'owner', 'direct')`,
		`SELECT authz.model_add_rule($1, 'file', 'viewer', 'direct')`,
		`SELECT authz.model_add_rule($1, 'file', 'can_share', 'computed', 'owner')`,
		`SELECT authz.model_add_grant_rule($1, 'file', 'viewer', 'can_share')`,
		`SELECT authz.write_tuple($1, 'user', 'alice', 'owner', 'doc', 'plan')`,
		`SELECT authz.write_tuple($1, 'user', 'bob', 'viewer', 'doc', 'plan')`,
		`SELECT authz.write_tuple($1, 'user', 'dave', 'viewer', 'doc', 'plan', p_expires_at => now() + interval '1 hour')`,
		`SELECT authz.write_tuple($1, 'user', 'alice', 'owner', 'file', 'x')`,
		`SELECT authz.write_tuple($1, 'user', 'alice', 'owner', 'doc', 'big')`,
		`SELECT authz.write_tuples_jsonb($1, (SELECT jsonb_agg(jsonb_build_object('user_type', 'user', 'user_id', 'v' || i, 'relation', 'viewer', 'object_type', 'doc', 'object_id', 'big')) FROM generate_series(1, 201) i))`,
	} {
		if _, err := pool.Exec(ctx, stmt, store); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `SELECT authz.delete_store($1, p_purge_audit => true)`, store)
	}()
	// dave's grant ran out (written live — the engine refuses dead-on-arrival grants)
	if _, err := pool.Exec(ctx, `UPDATE authz.tuples t SET expires_at = now() - interval '1 day' FROM authz.stores s WHERE s.id = t.store_id AND s.name = $1 AND t.user_id = 'dave'`, store); err != nil {
		t.Fatal(err)
	}
	// the people: a store owner, a store viewer, an author of the docs namespace
	ns := nsObject(store, "docs")
	for _, tu := range [][]string{
		{"user", "share_http_owner", "owner", "store", store},
		{"user", "share_http_viewer", "viewer", "store", store},
		{"store", store, "store", "namespace", ns},
		{"namespace", ns, "namespace", "store", store},
		{"user", "share_http_nsauthor", "author", "namespace", ns},
	} {
		if _, err := pool.Exec(ctx, `SELECT authz.write_tuple($1, $2, $3, $4, $5, $6)`, cs, tu[0], tu[1], tu[2], tu[3], tu[4]); err != nil {
			t.Fatal(err)
		}
		defer func(tu []string) {
			_, _ = pool.Exec(context.Background(), `SELECT authz.delete_tuple($1, $2, $3, $4, $5, $6)`, cs, tu[0], tu[1], tu[2], tu[3], tu[4])
		}(tu)
	}
	owner, viewer, nsauthor := httpSession(t, s, "share_http_owner"), httpSession(t, s, "share_http_viewer"), httpSession(t, s, "share_http_nsauthor")

	h := s.Routes()
	do := func(method, target string, body string, c *http.Cookie) (int, map[string]any) {
		t.Helper()
		var rd *strings.Reader
		if body != "" {
			rd = strings.NewReader(body)
		} else {
			rd = strings.NewReader("")
		}
		req := httptest.NewRequest(method, target, rd)
		if c != nil {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m
	}
	options := func(objectType, objectID, actor string) string {
		return fmt.Sprintf("/api/stores/%s/share?object_type=%s&object_id=%s&actor_type=user&actor_id=%s", store, objectType, objectID, actor)
	}
	apply := "/api/stores/" + store + "/share"
	grantCarol := func(actor string) string {
		return fmt.Sprintf(`{"object_type":"doc","object_id":"plan","actor_type":"user","actor_id":"%s","grants":[{"user_type":"user","user_id":"carol","relation":"viewer"}],"revokes":[]}`, actor)
	}

	// the console gate
	if code, _ := do("GET", options("doc", "plan", "alice"), "", nil); code != 401 {
		t.Errorf("no session: %d, want 401", code)
	}
	if code, m := do("GET", options("doc", "plan", "alice"), "", viewer); code != 403 || m["required"] != "can_grant" {
		t.Errorf("viewer options: %d %v, want 403 can_grant", code, m)
	}
	if code, m := do("POST", apply, grantCarol("alice"), viewer); code != 403 || m["required"] != "can_grant" {
		t.Errorf("viewer save: %d %v, want 403 can_grant", code, m)
	}
	if code, m := do("GET", options("doc", "plan", "alice"), "", nsauthor); code != 200 {
		t.Errorf("docs author on a doc: %d %v, want 200", code, m)
	}
	if code, m := do("GET", options("file", "x", "alice"), "", nsauthor); code != 403 || m["object"] != "namespace:"+nsObject(store, "files") {
		t.Errorf("docs author on a file: %d %v, want 403 on the files namespace", code, m)
	}
	if code, m := do("POST", apply, `{"object_type":"file","object_id":"x","actor_type":"user","actor_id":"alice","grants":[{"user_type":"user","user_id":"carol","relation":"viewer"}]}`, nsauthor); code != 403 || m["object"] != "namespace:"+nsObject(store, "files") {
		t.Errorf("docs author saving on a file: %d %v, want 403 on the files namespace", code, m)
	}

	// malformed
	for name, body := range map[string]string{
		"bad json":      `{`,
		"unknown field": `{"object_type":"doc","object_id":"plan","actor_type":"user","actor_id":"alice","grants":[],"revokes":[],"bogus":1}`,
		"no actor":      `{"object_type":"doc","object_id":"plan","grants":[{"user_type":"user","user_id":"carol","relation":"viewer"}]}`,
		"nothing to do": `{"object_type":"doc","object_id":"plan","actor_type":"user","actor_id":"alice","grants":[],"revokes":[]}`,
		"grant no id":   `{"object_type":"doc","object_id":"plan","actor_type":"user","actor_id":"alice","grants":[{"user_type":"user","relation":"viewer"}]}`,
		"revoke no rel": `{"object_type":"doc","object_id":"plan","actor_type":"user","actor_id":"alice","revokes":[{"user_type":"user","user_id":"bob"}]}`,
	} {
		if code, m := do("POST", apply, body, owner); code != 400 {
			t.Errorf("%s: %d %v, want 400", name, code, m)
		}
	}
	if code, m := do("GET", "/api/stores/"+store+"/share?object_type=doc&object_id=plan", "", owner); code != 400 {
		t.Errorf("options without an actor: %d %v, want 400", code, m)
	}

	// the listing: offered relations only (owner has no grant rule), live
	// tuples only (dave's ran out), expiry reported when set
	code, m := do("GET", options("doc", "plan", "alice"), "", owner)
	if code != 200 {
		t.Fatalf("owner options: %d %v", code, m)
	}
	holders, _ := m["holders"].([]any)
	var ids []string
	for _, x := range holders {
		hm := x.(map[string]any)
		ids = append(ids, hm["relation"].(string)+"/"+hm["user_id"].(string))
	}
	if strings.Join(ids, ",") != "viewer/bob" {
		t.Errorf("holders of doc:plan = %v, want only viewer/bob (owner has no grant rule, dave expired)", ids)
	}
	if totals, _ := m["holder_totals"].(map[string]any); totals["viewer"] != float64(1) {
		t.Errorf("holder_totals = %v, want viewer: 1", totals)
	}
	if opts, _ := m["options"].([]any); len(opts) != 1 || opts[0].(map[string]any)["relation"] != "viewer" || opts[0].(map[string]any)["can_grant"] != true {
		t.Errorf("options for alice = %v, want viewer grantable", opts)
	}
	// the cap: 201 viewers, 200 listed, the count says so
	code, m = do("GET", options("doc", "big", "alice"), "", owner)
	holders, _ = m["holders"].([]any)
	totals, _ := m["holder_totals"].(map[string]any)
	if code != 200 || len(holders) != shareHoldersPerRelation || totals["viewer"] != float64(201) || m["holders_limit"] != float64(shareHoldersPerRelation) {
		t.Errorf("doc:big: %d, %d holders, totals %v, limit %v; want %d listed of 201", code, len(holders), totals, m["holders_limit"], shareHoldersPerRelation)
	}

	// the actor contract: the sharer chooses the actor, the engine's grant
	// rules decide for that actor — bob (viewer) may not, alice (owner) may
	if code, m := do("POST", apply, grantCarol("bob"), owner); code != 403 || m["code"] != "42501" {
		t.Errorf("acting as bob: %d %v, want the engine's refusal (403, insufficient_privilege)", code, m)
	}
	var ok bool
	if err := pool.QueryRow(ctx, `SELECT authz.check_access($1, 'user', 'carol', 'viewer', 'doc', 'plan')`, store).Scan(&ok); err != nil || ok {
		t.Errorf("carol became a viewer through bob: %v %v", err, ok)
	}
	var since time.Time // the database's clock: the console's action log keeps earlier runs' events
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&since); err != nil {
		t.Fatal(err)
	}
	code, m = do("POST", apply, grantCarol("alice"), owner)
	if code != 200 {
		t.Fatalf("acting as alice: %d %v", code, m)
	}
	if res, _ := m["result"].(map[string]any); res["granted"] != float64(1) {
		t.Errorf("result = %v, want granted 1", m["result"])
	}
	if err := pool.QueryRow(ctx, `SELECT authz.check_access($1, 'user', 'carol', 'viewer', 'doc', 'plan')`, store).Scan(&ok); err != nil || !ok {
		t.Errorf("carol is not a viewer after alice's grant: %v %v", err, ok)
	}
	// recorded as the person, naming the actor
	var n int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM authz.list_events($1, p_object_type => 'store', p_object_id => $2)
		 WHERE subject_id = 'share_http_owner' AND action = 'can_grant' AND occurred_at >= $3
		   AND payload->>'op' = 'share' AND payload->>'actor' = 'user:alice' AND payload->>'object' = 'doc:plan'`, cs, store, since).Scan(&n); err != nil || n != 1 {
		t.Errorf("console action log: %v, %d share events by the owner acting as alice, want 1", err, n)
	}
	// a revoke, as alice, of what alice can revoke — sent WITHOUT a grants
	// key, as a client that only revokes would; the tuple is gone
	if code, m := do("POST", apply, `{"object_type":"doc","object_id":"plan","actor_type":"user","actor_id":"alice","revokes":[{"user_type":"user","user_id":"carol","relation":"viewer"}]}`, owner); code != 200 {
		t.Errorf("revoke as alice: %d %v", code, m)
	}
	if err := pool.QueryRow(ctx, `SELECT authz.check_access($1, 'user', 'carol', 'viewer', 'doc', 'plan')`, store).Scan(&ok); err != nil || ok {
		t.Errorf("carol still a viewer after the revoke: %v %v", err, ok)
	}
}
