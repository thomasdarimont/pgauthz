package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Platform → Issuers through the router: the gate (can_manage_issuers on
// the platform), a binding saved as the person and read back with who
// created it, the engine's validation surfaced as 400, a replace keeping
// created_by, the audit trail, delete and its 404, and both changes in the
// console's action log.
func TestIssuersHTTP(t *testing.T) {
	s, pool, ctx := testServer(t)
	cs := s.cfg.ConsoleStore
	const iss = "https://console-gotest.example/realm"
	_, _ = pool.Exec(ctx, `DELETE FROM authz.issuer_bindings WHERE issuer = $1`, iss)
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM authz.issuer_bindings WHERE issuer = $1`, iss)
	}()

	if _, err := pool.Exec(ctx, `SELECT authz.write_tuple($1, 'user', 'iss_admin', 'admin', 'platform', $2)`, cs, s.cfg.PlatformID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `SELECT authz.delete_tuple($1, 'user', 'iss_admin', 'admin', 'platform', $2)`, cs, s.cfg.PlatformID)
	}()
	admin, nobody := httpSession(t, s, "iss_admin"), httpSession(t, s, "iss_nobody")
	h := s.Routes()
	do := func(method, target, body string, c *http.Cookie) (int, map[string]any) {
		t.Helper()
		var rd *strings.Reader
		if body != "" {
			rd = strings.NewReader(body)
		} else {
			rd = strings.NewReader("")
		}
		req := httptest.NewRequest(method, target, rd)
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

	if code, _ := do("GET", "/api/platform/issuers", "", nobody); code != 403 {
		t.Fatalf("without can_manage_issuers: %d", code)
	}
	if code, _ := do("PUT", "/api/platform/issuers", `{"issuer":"`+iss+`","stores":["x"],"enabled":true}`, nobody); code != 403 {
		t.Fatalf("save without can_manage_issuers: %d", code)
	}

	code, m := do("GET", "/api/platform/issuers", "", admin)
	if code != 200 || m["bindings"] == nil || m["effective"] == nil {
		t.Fatalf("list: %d %v", code, m)
	}
	if code, _ := do("GET", "/api/platform/issuers/audit", "", nobody); code != 403 {
		t.Fatalf("audit without can_manage_issuers: %d", code)
	}
	if code, _ := do("GET", "/api/platform/issuers/audit?before=x", "", admin); code != 400 {
		t.Fatalf("audit with a bad cursor: %d", code)
	}
	if eff := m["effective"].(map[string]any); eff["available"] != false {
		t.Fatalf("without PGAUTHZD_INTERNAL_URL the effective set is unavailable: %v", eff)
	}

	// validation is the engine's
	if code, m := do("PUT", "/api/platform/issuers", `{"issuer":"`+iss+`","stores":["tenant-("],"enabled":true}`, admin); code != 400 {
		t.Fatalf("bad pattern: %d %v", code, m)
	}
	if code, m := do("PUT", "/api/platform/issuers", `{"issuer":"`+iss+`","stores":["docs"],"pep_clients":{"gw":["mail"]},"enabled":true}`, admin); code != 400 || !strings.Contains(m["error"].(string), "not covered") {
		t.Fatalf("pep client outside stores: %d %v", code, m)
	}
	if code, m := do("PUT", "/api/platform/issuers", `{"issuer":"   ","enabled":true}`, admin); code != 400 {
		t.Fatalf("blank issuer: %d %v", code, m)
	}
	if code, m := do("PUT", "/api/platform/issuers", `{"issuer":"`+iss+`","bogus":1}`, admin); code != 400 {
		t.Fatalf("unknown field: %d %v", code, m)
	}

	// save, read back, replace keeping created_by
	code, m = do("PUT", "/api/platform/issuers", `{"issuer":"`+iss+`","stores":["docs","tenant-.*"],"db_roles":["app_.*"],"client_db_roles":{"svc":"app_svc"},"pep_clients":{"gw":["docs"]},"enabled":true,"description":"first"}`, admin)
	if code != 200 || m["revision"] == nil {
		t.Fatalf("save: %d %v", code, m)
	}
	rev1 := m["revision"].(float64)
	find := func() map[string]any {
		t.Helper()
		code, m := do("GET", "/api/platform/issuers", "", admin)
		if code != 200 {
			t.Fatalf("list: %d %v", code, m)
		}
		for _, b := range m["bindings"].([]any) {
			if bm := b.(map[string]any); bm["issuer"] == iss {
				return bm
			}
		}
		return nil
	}
	b := find()
	if b == nil || b["created_by"] != "user:iss_admin" || b["updated_by"] != "user:iss_admin" || b["description"] != "first" {
		t.Fatalf("read back: %v", b)
	}
	if st := b["stores"].([]any); len(st) != 2 || st[1] != "tenant-.*" {
		t.Fatalf("stores: %v", st)
	}
	if code, m := do("PUT", "/api/platform/issuers", `{"issuer":"`+iss+`","stores":["docs"],"enabled":false,"description":"paused"}`, admin); code != 200 || m["revision"].(float64) <= rev1 {
		t.Fatalf("replace: %d %v", code, m)
	}
	b = find()
	if b["enabled"] != false || b["created_by"] != "user:iss_admin" || b["created_at"] == nil || len(b["pep_clients"].(map[string]any)) != 0 {
		t.Fatalf("after the replace: %v", b)
	}

	// the audit trail names the person, newest first, paged by seq
	_, m = do("GET", "/api/platform/issuers/audit?issuer="+iss+"&limit=1", "", admin)
	audit := m["rows"].([]any)
	if len(audit) != 1 || m["total"].(float64) < 2 || m["next"] == "" { // the audit is append-only: earlier runs' rows stay
		t.Fatalf("audit page 1: %v", m)
	}
	if a := audit[0].(map[string]any); a["issuer"] != iss || a["action"] != "UPDATE" || a["performed_by"] != "user:iss_admin" {
		t.Fatalf("latest audit row: %v", a)
	}
	_, m2 := do("GET", "/api/platform/issuers/audit?issuer="+iss+"&limit=1&before="+m["next"].(string), "", admin)
	if rows := m2["rows"].([]any); len(rows) != 1 || rows[0].(map[string]any)["action"] != "INSERT" || rows[0].(map[string]any)["description"] != "first" {
		t.Fatalf("audit page 2: %v", m2)
	}

	// delete, then 404
	if code, m := do("POST", "/api/platform/issuers/delete", `{"issuer":"`+iss+`"}`, admin); code != 200 || m["deleted"] != true {
		t.Fatalf("delete: %d %v", code, m)
	}
	if find() != nil {
		t.Fatal("still listed after the delete")
	}
	if code, _ := do("POST", "/api/platform/issuers/delete", `{"issuer":"`+iss+`"}`, admin); code != 404 {
		t.Fatalf("delete again: %d", code)
	}

	// the console's own action log has every change by the person
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.list_events($1, p_subject_type => 'user', p_subject_id => 'iss_admin', p_action => 'can_manage_issuers', p_limit => 100)`, cs).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 3 {
		t.Fatalf("action log: %d rows, want the save, the replace and the delete", n)
	}
}
