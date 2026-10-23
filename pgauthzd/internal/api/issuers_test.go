package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"thomasdarimont.de/authz/pgauthzd/internal/config"
	"thomasdarimont.de/authz/pgauthzd/pkg/issuers"
)

// unverified builds a token with the given claims and a bogus signature —
// enough for pickValidator, which only parses.
func unverified(claims string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"ES256","kid":"k"}`)) + "." + enc([]byte(claims)) + "." + enc([]byte("sig"))
}

// The issuer set is one swappable value: a Replace narrows an issuer's
// store binding for the handler and disables an issuer for the middleware
// at once, with no restart; the validators of unchanged anchors survive.
func TestIssuerSetSwap(t *testing.T) {
	env := []issuers.Issuer{
		{Issuer: "https://corp", Audience: "api", JWKSURL: "https://corp/jwks", Stores: []string{"docs", "tenant-.*"}},
		{Issuer: "https://open", Audience: "api", JWKSFile: "/k.json"},
	}
	set := NewIssuers(IssuerConfigsFrom(env))
	cfg := &config.Config{DefaultStore: "docs", Issuers: env, IssuersSource: "env+db"}
	h := NewHandler(nil, nil, nil, cfg, WithIssuers(set))
	mw := NewJWTMiddleware(JWTConfig{Issuers: IssuerConfigsFrom(env), Set: set})
	corpValidator := set.Current().byIssuer["https://corp"]

	req := func(issuer, store string) *http.Request {
		r := httptest.NewRequest("POST", "/x", nil)
		r.SetPathValue("store", store)
		return r.WithContext(context.WithValue(r.Context(), ctxIssuer, issuer))
	}
	allowed := func(issuer, store string) bool {
		w := httptest.NewRecorder()
		_, ok := h.storeChecked(w, req(issuer, store))
		return ok
	}
	if !allowed("https://corp", "tenant-1") || allowed("https://corp", "hr") || !allowed("https://open", "anything") {
		t.Fatal("environment bindings not in force")
	}
	if _, err := mw.pickValidator(unverified(`{"iss":"https://open"}`)); err != nil {
		t.Fatalf("open issuer must be accepted: %v", err)
	}

	// revision 7 from the database: corp narrowed to docs, open paused
	merged, problems := issuers.Merge(env, []issuers.Binding{
		{Issuer: "https://corp", Stores: []string{"docs"}, Enabled: true},
		{Issuer: "https://open", Stores: []string{"sandbox"}, Enabled: false},
	})
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	set.Replace(IssuerConfigsFrom(merged), 7)
	if set.Revision() != 7 {
		t.Fatalf("revision %d", set.Revision())
	}
	if allowed("https://corp", "tenant-1") || !allowed("https://corp", "docs") {
		t.Fatal("the narrowed store binding is not in force for the handler")
	}
	if _, err := mw.pickValidator(unverified(`{"iss":"https://open"}`)); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("a disabled issuer must be refused by the middleware: %v", err)
	}
	if _, err := mw.pickValidator(unverified(`{"iss":"https://corp"}`)); err != nil {
		t.Fatalf("corp still accepted: %v", err)
	}
	if set.Current().byIssuer["https://corp"] != corpValidator {
		t.Fatal("the validator of an unchanged anchor must be reused (cached keys)")
	}
	// readiness carries the applied revision
	w := httptest.NewRecorder()
	h.Readyz(w, httptest.NewRequest("GET", "/readyz", nil))
	if !strings.Contains(w.Body.String(), `"issuers_revision":7`) {
		t.Fatalf("readyz: %s", w.Body.String())
	}
}

// GET /pgauthz/v1/issuers: redacted anchors, bindings, sources; role-gated
// on the public listener and scoped to the caller's own issuer there (a
// tenant never sees another tenant's identity provider, a platform admin
// every one); open and complete on the callback listener.
func TestIssuersEndpoint(t *testing.T) {
	env := []issuers.Issuer{
		{Issuer: "https://corp", Audience: "api", JWKSFile: "/secret/dir/k.json", Stores: []string{"docs"},
			PEPClients: map[string][]string{"gw": {"docs"}}},
		{Issuer: "https://other-tenant", Audience: "api", JWKSURL: "https://other-tenant/jwks", Stores: []string{"mail"}},
	}
	cfg := &config.Config{DefaultStore: "docs", Issuers: env, IssuersRequiredRole: "authz_auditor", AdminRole: "pgauthz_admin"}
	h := NewHandler(nil, nil, nil, cfg)
	h.gateDiagnostics = true // the public listener
	call := func(iss string, roles ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/pgauthz/v1/issuers", nil)
		ctx := r.Context()
		if iss != "" {
			ctx = context.WithValue(ctx, ctxIssuer, iss)
		}
		if len(roles) > 0 {
			ctx = context.WithValue(ctx, ctxRoles, roles)
		}
		w := httptest.NewRecorder()
		h.Issuers(w, r.WithContext(ctx))
		return w
	}
	if w := call("https://corp"); w.Code != http.StatusForbidden {
		t.Fatalf("without the role: %d", w.Code)
	}
	w := call("https://corp", "authz_auditor")
	if w.Code != 200 {
		t.Fatalf("with the role: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"jwks":"file"`) || !strings.Contains(body, `"jwks_file":"k.json"`) || strings.Contains(body, "/secret/dir") {
		t.Fatalf("the key source must be redacted to its base name: %s", body)
	}
	if !strings.Contains(body, `"binding_source":"env"`) || !strings.Contains(body, `"pep_clients":{"gw":["docs"]}`) || !strings.Contains(body, `"source":"env"`) {
		t.Fatalf("bindings missing: %s", body)
	}
	// own issuer only: the other tenant's identity provider stays invisible
	if strings.Contains(body, "other-tenant") {
		t.Fatalf("a tenant must not see another tenant's issuer: %s", body)
	}
	if w := call("https://other-tenant", "authz_auditor"); !strings.Contains(w.Body.String(), "other-tenant") || strings.Contains(w.Body.String(), "https://corp") {
		t.Fatalf("the other tenant sees its own issuer only: %s", w.Body.String())
	}
	// a platform admin (ADMIN_ROLE) sees every issuer
	if w := call("https://corp", "authz_auditor", "pgauthz_admin"); !strings.Contains(w.Body.String(), "other-tenant") || !strings.Contains(w.Body.String(), "https://corp") {
		t.Fatalf("a platform admin sees the whole set: %s", w.Body.String())
	}
	// the callback listener serves the whole set without a role or a token
	h.gateDiagnostics = false
	if w := call(""); w.Code != 200 || !strings.Contains(w.Body.String(), "other-tenant") || !strings.Contains(w.Body.String(), "https://corp") {
		t.Fatalf("callback listener: %d %s", w.Code, w.Body.String())
	}
	// the public listener without ISSUERS_REQUIRED_ROLE: never
	h.gateDiagnostics = true
	cfg.IssuersRequiredRole = ""
	if w := call("https://corp", "authz_auditor"); w.Code != http.StatusForbidden {
		t.Fatalf("public listener without a configured role: %d", w.Code)
	}
}
