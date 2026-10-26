package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Sign-in providers (ADR 0017 phase 4): a registered, reachable provider
// is a button on the sign-in page and the login redirects to its
// authorization endpoint with its client id; an unreachable one is left
// off; the platform's provider stays the default; a disabled row is not
// offered; the callback's cookie carries the provider.
func TestSigninProviders(t *testing.T) {
	s, pool, ctx := testServer(t)
	_ = pool
	_ = httpSession(t, s, "prov_schema") // creates the console's own tables
	cleanup := func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM console_providers WHERE issuer LIKE 'http://127.0.0.1%' OR issuer = 'https://dead.example'`)
	}
	cleanup()
	defer cleanup()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			base := "http://" + r.Host
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": base, "authorization_endpoint": base + "/auth", "token_endpoint": base + "/token", "end_session_endpoint": base + "/logout"})
			return
		}
		http.NotFound(w, r)
	}))
	defer idp.Close()
	if _, err := s.db.Exec(ctx, `INSERT INTO console_providers (issuer, label, store_group, client_id, client_secret, enabled) VALUES ($1, 'Tenant A', 'tenant_a', 'console-a', 's3cr3t', true), ('https://dead.example', 'Dead', 'tenant_b', 'x', 'y', true), ($2, 'Off', 'tenant_c', 'z', 'w', false)`, idp.URL, idp.URL+"/off"); err != nil {
		t.Fatal(err)
	}
	h := s.Routes()
	// the sign-in page: the reachable provider, not the dead or the disabled one
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/providers", nil))
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, `"label":"Tenant A"`) || strings.Contains(body, "Dead") || strings.Contains(body, "Off") {
		t.Fatalf("providers: %d %s", rec.Code, body)
	}
	// login at the registered provider: its authorization endpoint, its client id, the cookie names it
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/login?issuer="+idp.URL, nil))
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, idp.URL+"/auth?") || !strings.Contains(loc, "client_id=console-a") {
		t.Fatalf("login redirect: %d %s", rec.Code, loc)
	}
	cookie := ""
	for _, c := range rec.Result().Cookies() {
		if c.Name == authCookie {
			cookie = c.Value
		}
	}
	if !strings.HasPrefix(cookie, idp.URL+"|") {
		t.Fatalf("auth cookie names the provider: %q", cookie)
	}
	// an unknown or dead provider: back to the sign-in page with the reason
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/login?issuer=https://dead.example", nil))
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "login_error=") {
		t.Fatalf("dead provider: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	// the callback refuses a state that does not match the cookie's
	req := httptest.NewRequest("GET", "/auth/callback?state=other&code=c", nil)
	req.AddCookie(&http.Cookie{Name: authCookie, Value: cookie})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("state mismatch: %d", rec.Code)
	}
}
