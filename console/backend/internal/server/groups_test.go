package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Store groups (ADR 0017) through the BFF: a platform admin creates a
// group, a store moves into it (the console's link tuple follows, so a
// group admin then sees and administers the store), the group's admins are
// managed one level below the platform, a non-empty group is not deleted,
// and a person without roles sees nothing.
func TestGroupsHTTP(t *testing.T) {
	s, pool, ctx := testServer(t)
	cs := s.cfg.ConsoleStore
	cleanup := func() {
		_, _ = pool.Exec(context.Background(), `SELECT authz.set_store_group('grp_test_store', NULL)`)
		_, _ = pool.Exec(context.Background(), `DO $$ BEGIN PERFORM authz.delete_store('grp_test_store', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END $$`)
		_, _ = pool.Exec(context.Background(), `DO $$ BEGIN PERFORM authz.delete_store_group('grp_test'); EXCEPTION WHEN OTHERS THEN NULL; END $$`)
		for _, q := range []string{
			`SELECT authz.delete_tuple($1, 'user', 'grp_admin', 'admin', 'platform', $2)`,
			`SELECT authz.delete_tuple($1, 'user', 'grp_tenant', 'admin', 'group', 'grp_test')`,
			`SELECT authz.delete_tuple($1, 'group', 'grp_test', 'group', 'store', 'grp_test_store')`,
			`SELECT authz.delete_tuple($1, 'platform', $2, 'platform', 'group', 'grp_test')`,
		} {
			_, _ = pool.Exec(context.Background(), q, cs, s.cfg.PlatformID)
		}
	}
	cleanup()
	defer cleanup()
	if _, err := pool.Exec(ctx, `SELECT authz.write_tuple($1, 'user', 'grp_admin', 'admin', 'platform', $2)`, cs, s.cfg.PlatformID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `SELECT authz.create_store('grp_test_store', 'group test')`); err != nil {
		t.Fatal(err)
	}
	admin, tenant, nobody := httpSession(t, s, "grp_admin"), httpSession(t, s, "grp_tenant"), httpSession(t, s, "grp_nobody")
	h := s.Routes()
	do := func(method, target, body string, c *http.Cookie) (int, map[string]any) {
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
		return rec.Code, m
	}
	names := func(m map[string]any) []string {
		var out []string
		for _, g := range m["groups"].([]any) {
			out = append(out, g.(map[string]any)["name"].(string))
		}
		return out
	}

	// the default group exists for everyone who may see the platform; nobody sees none
	if code, m := do("GET", "/api/platform/groups", "", admin); code != 200 || len(names(m)) == 0 || names(m)[0] != "default" || m["can_manage"] != true {
		t.Fatalf("admin lists groups: %d %v", code, m)
	}
	if code, m := do("GET", "/api/platform/groups", "", nobody); code != 200 || len(names(m)) != 0 || m["can_manage"] != false {
		t.Fatalf("nobody lists groups: %d %v", code, m)
	}
	// create; a tenant cannot
	if code, _ := do("POST", "/api/platform/groups", `{"name":"grp_test","description":"Tenant"}`, tenant); code != 403 {
		t.Fatalf("tenant creates: %d", code)
	}
	if code, m := do("POST", "/api/platform/groups", `{"name":"grp_test","description":"Tenant"}`, admin); code != 201 {
		t.Fatalf("create: %d %v", code, m)
	}
	// the store moves in; the group lists it and a group admin reaches it
	if code, m := do("PUT", "/api/stores/grp_test_store/group", `{"group":"grp_test"}`, admin); code != 200 {
		t.Fatalf("move: %d %v", code, m)
	}
	if code, m := do("POST", "/api/platform/groups/grp_test/access", `{"subject_type":"user","subject_id":"grp_tenant","role":"admin"}`, admin); code != 200 {
		t.Fatalf("grant group admin: %d %v", code, m)
	}
	code, m := do("GET", "/api/platform/groups", "", tenant)
	if code != 200 || len(names(m)) != 1 || names(m)[0] != "grp_test" || m["ungrouped"] != nil {
		t.Fatalf("tenant sees its group only: %d %v", code, m)
	}
	if code, m := do("GET", "/api/stores/grp_test_store", "", tenant); code != 200 || m["capabilities"].(map[string]any)["can_manage_access"] != true {
		t.Fatalf("group admin administers the store: %d %v", code, m)
	}
	if code, _ := do("GET", "/api/stores/grp_test_store", "", nobody); code != 403 {
		t.Fatalf("nobody on the store: %d", code)
	}
	// the group admin manages the group's admins but cannot move stores or delete the group
	if code, _ := do("PUT", "/api/platform/groups/grp_test", `{"description":"Tenant A"}`, tenant); code != 200 {
		t.Fatalf("tenant describes its group: %d", code)
	}
	if code, _ := do("PUT", "/api/stores/grp_test_store/group", `{"group":""}`, tenant); code != 403 {
		t.Fatalf("tenant detaches a store: %d", code)
	}
	if code, m := do("POST", "/api/platform/groups/grp_test/delete", `{}`, admin); code != 400 || !strings.Contains(m["error"].(string), "still holds") {
		t.Fatalf("delete non-empty: %d %v", code, m)
	}
	// detach, delete; the link tuple is gone with it
	if code, _ := do("PUT", "/api/stores/grp_test_store/group", `{"group":""}`, admin); code != 200 {
		t.Fatalf("detach: %d", code)
	}
	if code, _ := do("GET", "/api/stores/grp_test_store", "", tenant); code != 403 {
		t.Fatalf("after the detach the group admin no longer reaches the store: %d", code)
	}
	if code, m := do("POST", "/api/platform/groups/grp_test/delete", `{}`, admin); code != 200 || m["deleted"] != true {
		t.Fatalf("delete: %d %v", code, m)
	}
	var left int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM authz.tuples t JOIN authz.stores s ON s.id = t.store_id JOIN authz.types ot ON ot.id = t.object_type WHERE s.name = $1 AND ot.name = 'group' AND t.object_id = 'grp_test'`, cs).Scan(&left)
	if left != 0 {
		t.Fatalf("the group's console tuples must go with it, %d left", left)
	}
}
