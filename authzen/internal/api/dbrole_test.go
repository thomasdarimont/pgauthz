package api

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestClaimStringPath(t *testing.T) {
	claims := jwt.MapClaims{
		"db_role": "app_hr",
		"resource_access": map[string]any{
			"app-dms": map[string]any{"db_role": "app_dms"},
		},
		"azp": "app-hr",
	}
	cases := []struct {
		path string
		want string
	}{
		{"db_role", "app_hr"},
		{"resource_access.app-dms.db_role", "app_dms"},
		{"missing", ""},
		{"resource_access.missing.db_role", ""},
		{"azp.not_a_map", ""},
	}
	for _, tc := range cases {
		if got := claimStringPath(claims, tc.path); got != tc.want {
			t.Errorf("claimStringPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestDBRoleDerivation(t *testing.T) {
	claims := jwt.MapClaims{"azp": "app-dms", "db_role": "app_hr"}

	derive := func(cfg JWTConfig) string {
		// mirrors the middleware's derivation order: claim first, azp map second
		dbRole := ""
		if cfg.DBRoleClaim != "" {
			dbRole = claimStringPath(claims, cfg.DBRoleClaim)
		}
		if dbRole == "" && len(cfg.ClientDBRoles) > 0 {
			dbRole = cfg.ClientDBRoles[claimString(claims, "azp")]
		}
		return dbRole
	}

	// claim wins when configured and present
	if got := derive(JWTConfig{DBRoleClaim: "db_role",
		ClientDBRoles: map[string]string{"app-dms": "app_dms"}}); got != "app_hr" {
		t.Errorf("claim should win, got %q", got)
	}
	// azp map fallback when the claim is absent from the token
	if got := derive(JWTConfig{DBRoleClaim: "other_claim",
		ClientDBRoles: map[string]string{"app-dms": "app_dms"}}); got != "app_dms" {
		t.Errorf("azp fallback, got %q", got)
	}
	// unmapped client → no role
	if got := derive(JWTConfig{ClientDBRoles: map[string]string{"other": "x"}}); got != "" {
		t.Errorf("unmapped client should yield empty, got %q", got)
	}
	// nothing configured → no role
	if got := derive(JWTConfig{}); got != "" {
		t.Errorf("unconfigured should yield empty, got %q", got)
	}
}

func TestIssuerScopedClientRoles(t *testing.T) {
	m := NewJWTMiddleware(JWTConfig{
		ClientDBRoles: map[string]string{"app-hr": "app_global"},
		Issuers: []IssuerConfig{
			{Issuer: "https://tenant-a.idp", JWKSFile: "x",
				ClientDBRoles: map[string]string{"app-hr": "app_hr_a"}},
			{Issuer: "https://tenant-b.idp", JWKSFile: "x"},
		},
	})
	claims := func(iss string) jwt.MapClaims { return jwt.MapClaims{"iss": iss, "azp": "app-hr"} }

	// issuer-scoped map wins over the global map — no cross-tenant azp collision
	if got := m.deriveDBRole(claims("https://tenant-a.idp")); got != "app_hr_a" {
		t.Errorf("tenant-a: got %q, want app_hr_a", got)
	}
	// issuer without its own map falls back to the global map
	if got := m.deriveDBRole(claims("https://tenant-b.idp")); got != "app_global" {
		t.Errorf("tenant-b: got %q, want app_global", got)
	}
}

func TestIssuerDBRoleBinding(t *testing.T) {
	m := NewJWTMiddleware(JWTConfig{Issuers: []IssuerConfig{
		{Issuer: "https://tenant-a.idp", JWKSFile: "x", DBRoles: []string{"app_hr", "app_hr_.*"}},
		{Issuer: "https://open.idp", JWKSFile: "x"}, // no restriction
	}})

	cases := []struct {
		name    string
		issuer  string
		role    string
		allowed bool
	}{
		{"exact match", "https://tenant-a.idp", "app_hr", true},
		{"pattern match", "https://tenant-a.idp", "app_hr_batch", true},
		{"anchored", "https://tenant-a.idp", "xapp_hr", false},
		{"cross-tenant role denied", "https://tenant-a.idp", "app_dms", false},
		{"unrestricted issuer", "https://open.idp", "app_dms", true},
		{"unknown issuer unrestricted", "https://other.idp", "app_dms", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.dbRoleAllowed(tc.issuer, tc.role); got != tc.allowed {
				t.Errorf("dbRoleAllowed(%q, %q) = %v, want %v", tc.issuer, tc.role, got, tc.allowed)
			}
		})
	}
}
