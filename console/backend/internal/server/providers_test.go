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

// Auto-login: the provider a row marks (or CONSOLE_AUTO_LOGIN names) is
// reported to the sign-in page, which goes there without the chooser; a
// browser that just signed out sees the chooser once (the signed-out
// cookie); a discovery URL the row names is used, and a document naming
// another issuer takes the provider off the page.
func TestSigninAutoLoginAndDiscoveryURL(t *testing.T) {
	s, _, ctx := testServer(t)
	_ = httpSession(t, s, "prov_schema2")
	cleanup := func() {
		_, _ = s.db.Exec(context.Background(), `DELETE FROM console_providers WHERE issuer LIKE 'http://127.0.0.1%'`)
	}
	cleanup()
	defer cleanup()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		switch r.URL.Path {
		case "/elsewhere/openid-configuration": // the tenant's document, not at the well-known location
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": base + "/tenant", "authorization_endpoint": base + "/auth", "token_endpoint": base + "/token"})
		case "/other/.well-known/openid-configuration": // names a different issuer
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": base + "/someone-else", "authorization_endpoint": base + "/auth", "token_endpoint": base + "/token"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer idp.Close()
	if _, err := s.db.Exec(ctx, `INSERT INTO console_providers (issuer, label, store_group, client_id, client_secret, enabled, auto_login, discovery_url)
		VALUES ($1, 'Tenant', 'tenant_a', 'c', 's', true, true, $2), ($3, 'Other', 'tenant_b', 'c', 's', true, false, NULL)`,
		idp.URL+"/tenant", idp.URL+"/elsewhere/openid-configuration", idp.URL+"/other"); err != nil {
		t.Fatal(err)
	}
	h := s.Routes()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/providers", nil))
	var got struct {
		Providers []map[string]any `json:"providers"`
		AutoLogin string           `json:"auto_login"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.AutoLogin != idp.URL+"/tenant" {
		t.Fatalf("auto_login = %q (%s)", got.AutoLogin, rec.Body.String())
	}
	for _, p := range got.Providers {
		if p["label"] == "Other" {
			t.Fatalf("a document naming another issuer must take the provider off the page: %s", rec.Body.String())
		}
	}
	// just signed out: the chooser once
	req := httptest.NewRequest("GET", "/api/providers", nil)
	req.AddCookie(&http.Cookie{Name: signedOutCookie, Value: "1"})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), `"auto_login":"http`) {
		t.Fatalf("signed out: %s", rec.Body.String())
	}
	// the login at the tenant's provider goes to the endpoint its document names, and clears the mark
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/login?issuer="+idp.URL+"/tenant", nil))
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), idp.URL+"/auth?") {
		t.Fatalf("login: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		cleared = cleared || (c.Name == signedOutCookie && c.MaxAge < 0)
	}
	if !cleared {
		t.Fatal("login must clear the signed-out mark")
	}
	// the platform's provider wins when the environment names it
	s.cfg.AutoLogin = "true"
	defer func() { s.cfg.AutoLogin = "" }()
	if s.oidc != nil {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/providers", nil))
		if !strings.Contains(rec.Body.String(), `"auto_login":"`+s.cfg.Issuer+`"`) {
			t.Fatalf("platform auto-login: %s", rec.Body.String())
		}
	}
}
