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

// ── Freshness keyring (FRESHNESS_TOKEN_KEYS / FRESHNESS_TOKEN_KEY) ──────────

func setMinimalIssuer(t *testing.T) {
	t.Helper()
	setIssuers(t, `[{"issuer":"https://a","jwks_file":"/keys/a.json"}]`)
}

func TestFreshnessKeysParsing(t *testing.T) {
	setMinimalIssuer(t)
	t.Setenv("FRESHNESS_TOKEN_KEYS", " new-secret , old-secret ,")
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.FreshnessKeys) != 2 || c.FreshnessKeys[0] != "new-secret" || c.FreshnessKeys[1] != "old-secret" {
		t.Fatalf("expected trimmed ordered keys [new-secret old-secret], got %v", c.FreshnessKeys)
	}
	if !c.FreshnessEnabled() {
		t.Fatal("keys set → freshness enabled")
	}
}

func TestFreshnessSingleKeyAlias(t *testing.T) {
	setMinimalIssuer(t)
	t.Setenv("FRESHNESS_TOKEN_KEY", "solo-secret")
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.FreshnessKeys) != 1 || c.FreshnessKeys[0] != "solo-secret" {
		t.Fatalf("alias should yield a single-entry keyring, got %v", c.FreshnessKeys)
	}
}

func TestFreshnessBothKeyVarsRejected(t *testing.T) {
	setMinimalIssuer(t)
	t.Setenv("FRESHNESS_TOKEN_KEYS", "a,b")
	t.Setenv("FRESHNESS_TOKEN_KEY", "c")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("expected both-set error, got %v", err)
	}
}

func TestFreshnessDuplicateKeysRejected(t *testing.T) {
	setMinimalIssuer(t)
	t.Setenv("FRESHNESS_TOKEN_KEYS", "same,same")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate-key error, got %v", err)
	}
}

func TestFreshnessDisabledByDefault(t *testing.T) {
	setMinimalIssuer(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.FreshnessEnabled() || len(c.FreshnessKeys) != 0 {
		t.Fatalf("no key env → disabled, got %v", c.FreshnessKeys)
	}
}

func TestDeploymentEnvironmentValidated(t *testing.T) {
	setMinimalIssuer(t)
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "prod uction")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DEPLOYMENT_ENVIRONMENT") {
		t.Fatalf("expected format error, got %v", err)
	}
}

func TestDeploymentEnvironmentValidAccepted(t *testing.T) {
	setMinimalIssuer(t)
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "production")
	if c, err := Load(); err != nil || c.DeploymentEnvironment != "production" {
		t.Fatalf("valid env rejected: %v", err)
	}
}

func TestCursorSealKeyRejectsEmptySegments(t *testing.T) {
	setMinimalIssuer(t)
	t.Setenv("CURSOR_SEAL_KEY", "new-key,")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "CURSOR_SEAL_KEY") {
		t.Fatalf("expected empty-segment error, got %v", err)
	}
}

func TestCursorSealKeyringAccepted(t *testing.T) {
	setMinimalIssuer(t)
	t.Setenv("CURSOR_SEAL_KEY", "new-key, old-key")
	if c, err := Load(); err != nil || c.CursorSealKey == "" {
		t.Fatalf("valid keyring rejected: %v", err)
	}
}
