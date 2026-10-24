package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

// With PGAUTHZD_ADMIN_URL the tab goes through pgauthzd's admin API as the
// signed-in person: their session token is what the fake sees, the rows,
// the history and the effective set come from it, writes are recorded in
// the console's action log and pgauthzd's refusals keep their meaning
// (403 scope, 404 row); the console's own gate still comes first; a
// session without a token and no certificate has no credential (503).
func TestIssuersOverAdminAPI(t *testing.T) {
	s, pool, ctx := testServer(t)
	cs := s.cfg.ConsoleStore
	if _, err := pool.Exec(ctx, `SELECT authz.write_tuple($1, 'user', 'iss_api_admin', 'admin', 'platform', $2)`, cs, s.cfg.PlatformID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `SELECT authz.delete_tuple($1, 'user', 'iss_api_admin', 'admin', 'platform', $2)`, cs, s.cfg.PlatformID)
	}()
	admin, nobody := httpSession(t, s, "iss_api_admin"), httpSession(t, s, "iss_api_nobody")

	var seen []string // "METHOD path" + the Authorization header
	var lastBody string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/pgauthz/v1/admin/issuer-bindings":
			_, _ = w.Write([]byte(`{"bindings":[{"issuer":"https://tenant-a","stores":["a_.*"],"db_roles":[],"client_db_roles":{},"pep_clients":{},"enabled":true,"description":"from the api","created_at":"2026-10-24T10:00:00Z","created_by":"ci","updated_at":"2026-10-24T10:00:00Z","updated_by":"ci"}],"revision":7}`))
		case r.Method == "GET" && r.URL.Path == "/pgauthz/v1/admin/issuers":
			_, _ = w.Write([]byte(`{"source":"env+db","revision":7,"issuers":[{"issuer":"https://tenant-a","binding_source":"db"}]}`))
		case r.Method == "GET" && r.URL.Path == "/pgauthz/v1/admin/issuer-bindings/audit":
			_, _ = w.Write([]byte(`{"rows":[{"seq":9,"action":"set","performed_at":"2026-10-24T10:00:00Z","performed_by":"ci","issuer":"https://tenant-a","stores":["a_.*"],"enabled":true}],"next":"","total":1,"limit":25,"issuer":"https://tenant-a"}`))
		case r.Method == "PUT" && r.URL.Path == "/pgauthz/v1/admin/issuer-bindings":
			b, _ := io.ReadAll(r.Body)
			lastBody = string(b)
			if strings.Contains(lastBody, "tenant-b") {
				w.WriteHeader(403)
				_, _ = w.Write([]byte(`{"status":403,"message":"management refused: this token manages the issuer https://tenant-a only"}`))
				return
			}
			_, _ = w.Write([]byte(`{"issuer":"https://tenant-a","revision":8}`))
		case r.Method == "DELETE" && r.URL.Path == "/pgauthz/v1/admin/issuer-bindings":
			if r.URL.Query().Get("issuer") == "https://nope" {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"status":404,"message":"no binding for issuer https://nope"}`))
				return
			}
			_, _ = w.Write([]byte(`{"issuer":"https://tenant-a","deleted":true}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer fake.Close()
	s.cfg.PgauthzdAdminURL = fake.URL
	defer func() { s.cfg.PgauthzdAdminURL = "" }()
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

	// the console's gate first: no call reaches pgauthzd for a nobody
	if code, _ := do("GET", "/api/platform/issuers", "", nobody); code != 403 || len(seen) != 0 {
		t.Fatalf("nobody: %d, calls %v", code, seen)
	}
	code, m := do("GET", "/api/platform/issuers", "", admin)
	if code != 200 || m["via"] != "admin-api" || m["revision"].(float64) != 7 {
		t.Fatalf("list over the api: %d %v", code, m)
	}
	if b := m["bindings"].([]any); len(b) != 1 || b[0].(map[string]any)["description"] != "from the api" {
		t.Fatalf("bindings: %v", m["bindings"])
	}
	eff := m["effective"].(map[string]any)
	if eff["available"] != true || eff["via"] != "admin-api" || eff["credential"] != "token" || eff["url"] != fake.URL {
		t.Fatalf("effective: %v", eff)
	}
	for _, c := range seen {
		if !strings.Contains(c, " Bearer eyJhbGciOiJub25lIn0.") { // the session's own token
			t.Fatalf("the person's token must be presented: %q", c)
		}
	}
	code, m = do("GET", "/api/platform/issuers/audit?issuer=https://tenant-a&limit=10", "", admin)
	if code != 200 || m["total"].(float64) != 1 || !strings.Contains(seen[len(seen)-1], "issuer=https%3A%2F%2Ftenant-a") || !strings.Contains(seen[len(seen)-1], "limit=10") {
		t.Fatalf("audit passthrough: %d %v %s", code, m, seen[len(seen)-1])
	}
	code, m = do("PUT", "/api/platform/issuers", `{"issuer":"https://tenant-a","stores":["a_mail"],"enabled":true}`, admin)
	if code != 200 || m["revision"].(float64) != 8 || !strings.Contains(lastBody, `"stores":["a_mail"]`) || !strings.Contains(lastBody, `"client_db_roles":{}`) {
		t.Fatalf("save over the api: %d %v body=%s", code, m, lastBody)
	}
	// recorded in the console's action log as the person, marked via the api
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authz.list_events($1, p_subject_type => 'user', p_subject_id => 'iss_api_admin', p_action => 'can_manage_issuers', p_object_type => 'platform', p_object_id => $2, p_limit => 10)`, cs, s.cfg.PlatformID).Scan(&n); err != nil || n < 1 {
		t.Fatalf("the save is not in the action log: %d %v", n, err)
	}
	if code, m = do("PUT", "/api/platform/issuers", `{"issuer":"https://tenant-b","stores":["b"],"enabled":true}`, admin); code != 403 || !strings.Contains(m["error"].(string), "pgauthzd: management refused") {
		t.Fatalf("pgauthzd's scope refusal must come back as 403 with its reason: %d %v", code, m)
	}
	if code, _ = do("POST", "/api/platform/issuers/delete", `{"issuer":"https://nope"}`, admin); code != 404 {
		t.Fatalf("an unknown row over the api: %d", code)
	}
	if code, m = do("POST", "/api/platform/issuers/delete", `{"issuer":"https://tenant-a"}`, admin); code != 200 || m["deleted"] != true {
		t.Fatalf("delete over the api: %d %v", code, m)
	}
	// no session on the request and no certificate: no credential (503)
	err := s.adminCall(ctx, httptest.NewRequest("GET", "/api/platform/issuers", nil), "GET", "/pgauthz/v1/admin/issuers", nil, nil)
	var ue *upstreamError
	if !errors.As(err, &ue) || ue.status != http.StatusServiceUnavailable || !strings.Contains(ue.msg, "no credential") {
		t.Fatalf("no credential: %v", err)
	}
	// the credential by session kind, with a certificate configured: an OIDC
	// session presents its token, the LOCAL admin the certificate, and an
	// OIDC session without a usable token nothing — never the certificate
	s.adminHTTP = &http.Client{}
	defer func() { s.adminHTTP = nil }()
	withCookie := func(c *http.Cookie) *http.Request {
		req := httptest.NewRequest("GET", "/api/platform/issuers", nil)
		req.AddCookie(c)
		return req
	}
	if kind, _ := s.adminCredential(withCookie(admin)); kind != "token" {
		t.Fatalf("oidc session with a token: %q", kind)
	}
	if _, err := s.db.Exec(ctx, `UPDATE sessions SET access_token = '' WHERE id = $1`, admin.Value); err != nil {
		t.Fatal(err)
	}
	if kind, _ := s.adminCredential(withCookie(admin)); kind != "" {
		t.Fatalf("oidc session without a token must fail closed, got %q", kind)
	}
	if _, err := s.db.Exec(ctx, `UPDATE sessions SET local = true WHERE id = $1`, admin.Value); err != nil {
		t.Fatal(err)
	}
	s.cfg.LocalAdminUser, s.cfg.LocalAdminPassword = "iss_api_admin", "x" // a local session is valid only while the local admin is configured
	defer func() { s.cfg.LocalAdminUser, s.cfg.LocalAdminPassword = "", "" }()
	if kind, _ := s.adminCredential(withCookie(admin)); kind != "certificate" {
		t.Fatalf("the local admin presents the certificate, got %q", kind)
	}
}
