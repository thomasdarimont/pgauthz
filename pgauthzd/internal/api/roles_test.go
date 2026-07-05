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
