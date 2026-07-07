package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

func TestExtractRoles(t *testing.T) {
	// Keycloak-shaped claims: realm roles + a client's roles.
	claims := jwt.MapClaims{
		"realm_access": map[string]any{"roles": []any{"authzen_auditor", "offline_access"}},
		"resource_access": map[string]any{
			"authz-api": map[string]any{"roles": []any{"authz_writer", "authzen_auditor"}},
		},
	}
	paths := "realm_access.roles,resource_access.authz-api.roles"
	got := extractRoles(claims, paths)

	want := map[string]bool{"authzen_auditor": true, "offline_access": true, "authz_writer": true}
	if len(got) != len(want) { // deduped across both paths (authzen_auditor appears twice)
		t.Fatalf("extractRoles = %v, want %d distinct roles", got, len(want))
	}
	for _, r := range got {
		if !want[r] {
			t.Errorf("unexpected role %q", r)
		}
	}

	// Missing / ill-typed paths are skipped, not fatal.
	if r := extractRoles(claims, "nope.roles, ,realm_access.roles"); len(r) != 2 {
		t.Errorf("expected 2 realm roles from tolerant parse, got %v", r)
	}
	if r := extractRoles(jwt.MapClaims{}, "realm_access.roles"); len(r) != 0 {
		t.Errorf("expected no roles from empty claims, got %v", r)
	}
}

func TestRequireSearchRole(t *testing.T) {
	withRoles := func(roles []string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/access/v1/search/subject", nil)
		return r.WithContext(context.WithValue(r.Context(), ctxRoles, roles))
	}

	// No role configured → always allowed (open).
	open := &Handler{cfg: &config.Config{}}
	if !open.requireSearchRole(httptest.NewRecorder(), withRoles(nil)) {
		t.Error("open search should allow when SearchRequiredRole is empty")
	}

	gated := &Handler{cfg: &config.Config{SearchRequiredRole: "authzen_auditor"}}

	// Caller holds the role → allowed.
	if !gated.requireSearchRole(httptest.NewRecorder(), withRoles([]string{"x", "authzen_auditor"})) {
		t.Error("caller with the role should be allowed")
	}

	// Caller lacks the role → 403.
	w := httptest.NewRecorder()
	if gated.requireSearchRole(w, withRoles([]string{"authz_writer"})) {
		t.Error("caller without the role should be denied")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// Watch is DENY BY DEFAULT on the public listener (review #10): the
// changefeed exposes authorization topology, and the DB connection role holds
// authz_auditor to serve it — HTTP decides who may ask.
func TestWatchRoleGate(t *testing.T) {
	withRoles := func(ctx context.Context, roles []string) context.Context {
		return context.WithValue(ctx, ctxRoles, roles)
	}
	// default (unset): 403 regardless of roles
	h := &Handler{cfg: &config.Config{}, gateDiagnostics: true}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/pgauthz/v1/watch", nil)
	if h.requireWatchRole(w, r) || w.Code != http.StatusForbidden {
		t.Fatalf("unset WATCH_REQUIRED_ROLE must 403 on the public listener, got %d", w.Code)
	}

	// configured role: ordinary caller 403, auditor passes
	h = &Handler{cfg: &config.Config{WatchRequiredRole: "authz_auditor"}, gateDiagnostics: true}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/pgauthz/v1/watch", nil)
	r = r.WithContext(withRoles(r.Context(), []string{"viewer"}))
	if h.requireWatchRole(w, r) {
		t.Fatal("ordinary token must not watch")
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/pgauthz/v1/watch", nil)
	r = r.WithContext(withRoles(r.Context(), []string{"authz_auditor"}))
	if !h.requireWatchRole(w, r) {
		t.Fatal("auditor token must watch")
	}

	// "*" opens explicitly
	h = &Handler{cfg: &config.Config{WatchRequiredRole: "*"}, gateDiagnostics: true}
	w = httptest.NewRecorder()
	if !h.requireWatchRole(w, httptest.NewRequest("POST", "/pgauthz/v1/watch", nil)) {
		t.Fatal(`WATCH_REQUIRED_ROLE="*" must open the route`)
	}

	// callback listener (gateDiagnostics=false): unaffected — OPA is a trusted PEP
	h = &Handler{cfg: &config.Config{}, gateDiagnostics: false}
	w = httptest.NewRecorder()
	if !h.requireWatchRole(w, httptest.NewRequest("POST", "/pgauthz/v1/watch", nil)) {
		t.Fatal("callback listener must not be gated")
	}
}

func TestExplainRoleGate(t *testing.T) {
	withRoles := func(ctx context.Context, roles []string) context.Context {
		return context.WithValue(ctx, ctxRoles, roles)
	}
	// empty = open (back-compat)
	h := &Handler{cfg: &config.Config{}, gateDiagnostics: true}
	if !h.requireExplainRole(httptest.NewRecorder(), httptest.NewRequest("POST", "/pgauthz/v1/explain", nil)) {
		t.Fatal("empty EXPLAIN_REQUIRED_ROLE keeps explain open")
	}
	// configured: gate on the JWT role
	h = &Handler{cfg: &config.Config{ExplainRequiredRole: "support"}, gateDiagnostics: true}
	r := httptest.NewRequest("POST", "/pgauthz/v1/explain", nil)
	if h.requireExplainRole(httptest.NewRecorder(), r) {
		t.Fatal("caller without the role must not explain")
	}
	r = r.WithContext(withRoles(r.Context(), []string{"support"}))
	if !h.requireExplainRole(httptest.NewRecorder(), r) {
		t.Fatal("caller with the role must explain")
	}
	// callback unaffected even when configured
	h = &Handler{cfg: &config.Config{ExplainRequiredRole: "support"}, gateDiagnostics: false}
	if !h.requireExplainRole(httptest.NewRecorder(), httptest.NewRequest("POST", "/pgauthz/v1/explain", nil)) {
		t.Fatal("callback explain must stay open (trusted PEP)")
	}
}
