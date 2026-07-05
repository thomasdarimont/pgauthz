package config

import (
	"strings"
	"testing"
)

// setIssuers configures a minimal two-issuer environment via JWT_ISSUERS.
func setIssuers(t *testing.T, issuersJSON string) {
	t.Helper()
	t.Setenv("JWKS_URL", "")
	t.Setenv("JWKS_FILE", "")
	t.Setenv("JWT_ISSUERS", issuersJSON)
}

func TestRequireStoreBindingRejectsUnboundIssuer(t *testing.T) {
	setIssuers(t, `[
		{"issuer":"https://a","jwks_file":"/keys/a.json","stores":["tenant-a-.*"]},
		{"issuer":"https://b","jwks_file":"/keys/b.json"}
	]`)
	t.Setenv("REQUIRE_STORE_BINDING", "true")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), `issuer "https://b" has no stores binding`) {
		t.Fatalf("expected store-binding error for issuer b, got %v", err)
	}
}

func TestRequireStoreBindingAcceptsFullyBound(t *testing.T) {
	setIssuers(t, `[
		{"issuer":"https://a","jwks_file":"/keys/a.json","stores":["tenant-a-.*"]},
		{"issuer":"https://b","jwks_file":"/keys/b.json","stores":["demo"]}
	]`)
	t.Setenv("REQUIRE_STORE_BINDING", "true")
	if _, err := Load(); err != nil {
		t.Fatalf("expected fully bound config to load, got %v", err)
	}
}

func TestStoreBindingNotRequiredByDefault(t *testing.T) {
	setIssuers(t, `[
		{"issuer":"https://a","jwks_file":"/keys/a.json"},
		{"issuer":"https://b","jwks_file":"/keys/b.json"}
	]`)
	if _, err := Load(); err != nil {
		t.Fatalf("unbound issuers must load (warning only) with flags off, got %v", err)
	}
}

func TestRequireDBRoleBindingRejectsUnboundIssuer(t *testing.T) {
	setIssuers(t, `[
		{"issuer":"https://a","jwks_file":"/keys/a.json","db_roles":["app_a_authz"]},
		{"issuer":"https://b","jwks_file":"/keys/b.json"}
	]`)
	t.Setenv("DB_ROLE_CLAIM", "db_role") // role derivation configured
	t.Setenv("REQUIRE_DB_ROLE_BINDING", "true")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), `issuer "https://b" has no db_roles`) {
		t.Fatalf("expected db-role-binding error for issuer b, got %v", err)
	}
}

func TestRequireDBRoleBindingAcceptsClientMapAsBinding(t *testing.T) {
	setIssuers(t, `[
		{"issuer":"https://a","jwks_file":"/keys/a.json","db_roles":["app_a_authz"]},
		{"issuer":"https://b","jwks_file":"/keys/b.json","client_db_roles":{"app-b":"app_b_authz"}}
	]`)
	t.Setenv("DB_ROLE_CLAIM", "db_role")
	t.Setenv("REQUIRE_DB_ROLE_BINDING", "true")
	if _, err := Load(); err != nil {
		t.Fatalf("client_db_roles map should count as a binding, got %v", err)
	}
}

func TestRequireDBRoleBindingNoopWithoutDerivation(t *testing.T) {
	// No DB_ROLE_CLAIM / CLIENT_DB_ROLES anywhere: roles cannot be claimed at
	// all, so the binding requirement has nothing to enforce.
	setIssuers(t, `[
		{"issuer":"https://a","jwks_file":"/keys/a.json"},
		{"issuer":"https://b","jwks_file":"/keys/b.json"}
	]`)
	t.Setenv("DB_ROLE_CLAIM", "")
	t.Setenv("REQUIRE_DB_ROLE_BINDING", "true")
	if _, err := Load(); err != nil {
		t.Fatalf("db-role binding requirement without role derivation must be a no-op, got %v", err)
	}
}

func TestDBRoleCacheTTLDefault(t *testing.T) {
	setIssuers(t, `[{"issuer":"https://a","jwks_file":"/keys/a.json"}]`)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.DBRoleCacheTTLSeconds != 60 {
		t.Fatalf("expected default DB_ROLE_CACHE_TTL_SECONDS=60, got %d", c.DBRoleCacheTTLSeconds)
	}
}
