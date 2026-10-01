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
		{"issuer":"https://a","audience":"api","jwks_file":"/keys/a.json","stores":["tenant-a-.*"]},
		{"issuer":"https://b","audience":"api","jwks_file":"/keys/b.json"}
	]`)
	t.Setenv("REQUIRE_STORE_BINDING", "true")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), `issuer "https://b" has no stores binding`) {
		t.Fatalf("expected store-binding error for issuer b, got %v", err)
	}
}

func TestRequireStoreBindingAcceptsFullyBound(t *testing.T) {
	setIssuers(t, `[
		{"issuer":"https://a","audience":"api","jwks_file":"/keys/a.json","stores":["tenant-a-.*"]},
		{"issuer":"https://b","audience":"api","jwks_file":"/keys/b.json","stores":["demo"]}
	]`)
	t.Setenv("REQUIRE_STORE_BINDING", "true")
	if _, err := Load(); err != nil {
		t.Fatalf("expected fully bound config to load, got %v", err)
	}
}

// Review #10 changed this default: unbound MULTI-issuer configurations are
// now fatal (cross-tenant reachability) unless deliberately overridden.
func TestStoreBindingMultiIssuerFailClosed(t *testing.T) {
	setIssuers(t, `[
		{"issuer":"https://a","audience":"api","jwks_file":"/keys/a.json"},
		{"issuer":"https://b","audience":"api","jwks_file":"/keys/b.json"}
	]`)
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ALLOW_UNBOUND_MULTI_ISSUER") {
		t.Fatalf("unbound multi-issuer must fail closed, got %v", err)
	}
	t.Setenv("ALLOW_UNBOUND_MULTI_ISSUER", "true")
	if _, err := Load(); err != nil {
		t.Fatalf("explicit override must load (with warnings), got %v", err)
	}
}

func TestRequireDBRoleBindingRejectsUnboundIssuer(t *testing.T) {
	setIssuers(t, `[
		{"issuer":"https://a","audience":"api","jwks_file":"/keys/a.json","stores":["a_*"],"db_roles":["app_a_authz"]},
		{"issuer":"https://b","audience":"api","jwks_file":"/keys/b.json","stores":["b_*"]}
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
		{"issuer":"https://a","audience":"api","jwks_file":"/keys/a.json","stores":["a_*"],"db_roles":["app_a_authz"]},
		{"issuer":"https://b","audience":"api","jwks_file":"/keys/b.json","stores":["b_*"],"client_db_roles":{"app-b":"app_b_authz"}}
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
		{"issuer":"https://a","audience":"api","jwks_file":"/keys/a.json","stores":["a_*"]},
		{"issuer":"https://b","audience":"api","jwks_file":"/keys/b.json","stores":["b_*"]}
	]`)
	t.Setenv("DB_ROLE_CLAIM", "")
	t.Setenv("REQUIRE_DB_ROLE_BINDING", "true")
	if _, err := Load(); err != nil {
		t.Fatalf("db-role binding requirement without role derivation must be a no-op, got %v", err)
	}
}

func TestDBRoleCacheTTLDefault(t *testing.T) {
	setIssuers(t, `[{"issuer":"https://a","audience":"api","jwks_file":"/keys/a.json"}]`)
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
	setIssuers(t, `[{"issuer":"https://a","audience":"api","jwks_file":"/keys/a.json"}]`)
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
	// "production" selects the production profile: diagnostic surfaces gated.
	t.Setenv("SEARCH_REQUIRED_ROLE", "authz_auditor")
	t.Setenv("EXPLAIN_REQUIRED_ROLE", "authz_auditor")
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

// Invalid env values are STARTUP FAILURES, never silent defaults (review #10):
// REQUIRE_STORE_BINDING=treu must not quietly mean "false".
func TestInvalidEnvValuesAreFatal(t *testing.T) {
	setMinimalIssuer(t)
	t.Setenv("REQUIRE_STORE_BINDING", "treu")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "REQUIRE_STORE_BINDING") {
		t.Fatalf("typo'd boolean must fail startup, got %v", err)
	}
}

func TestInvalidDurationFatal(t *testing.T) {
	setMinimalIssuer(t)
	t.Setenv("OPA_REQUEST_TIMEOUT", "10 seconds")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "OPA_REQUEST_TIMEOUT") {
		t.Fatalf("invalid duration must fail startup, got %v", err)
	}
}

func TestInvalidIntFatal(t *testing.T) {
	setMinimalIssuer(t)
	t.Setenv("DB_POOL_MAX", "many")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DB_POOL_MAX") {
		t.Fatalf("invalid int must fail startup, got %v", err)
	}
}

// Multi-issuer deployments are fail-closed (review #10): a second issuer
// without a stores binding is a cross-tenant hole and must stop startup.
func TestMultiIssuerUnboundFatal(t *testing.T) {
	setMinimalIssuer(t)
	t.Setenv("JWT_ISSUERS", `[
		{"issuer":"https://a.example","jwks_url":"https://a.example/jwks","audience":"x","stores":["tenant_a"]},
		{"issuer":"https://b.example","jwks_url":"https://b.example/jwks","audience":"x"}
	]`)
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ALLOW_UNBOUND_MULTI_ISSUER") {
		t.Fatalf("unbound second issuer must fail startup, got %v", err)
	}

	t.Setenv("ALLOW_UNBOUND_MULTI_ISSUER", "true")
	if _, err := Load(); err != nil {
		t.Fatalf("deliberate override must permit startup, got %v", err)
	}
}

// A single issuer keeps the historical default (no bindings required).
func TestSingleIssuerUnboundOK(t *testing.T) {
	setMinimalIssuer(t)
	if _, err := Load(); err != nil {
		t.Fatalf("single unbound issuer must keep working, got %v", err)
	}
}

// The production profile (DEPLOYMENT_ENVIRONMENT=production) refuses to start
// with open diagnostic surfaces; the override warns and starts; other
// environments keep the open-by-default runtime behaviour.
func TestProductionProfileRequiresGatedDiagnostics(t *testing.T) {
	base := func(t *testing.T) {
		t.Helper()
		t.Setenv("JWKS_FILE", "/keys/a.json")
		t.Setenv("JWT_AUDIENCE", "api")
		t.Setenv("JWT_ISSUERS", "")
		t.Setenv("SEARCH_REQUIRED_ROLE", "")
		t.Setenv("EXPLAIN_REQUIRED_ROLE", "")
		t.Setenv("WATCH_REQUIRED_ROLE", "")
		t.Setenv("ALLOW_OPEN_DIAGNOSTICS", "")
	}

	t.Run("production with everything open fails and names each surface", func(t *testing.T) {
		base(t)
		t.Setenv("DEPLOYMENT_ENVIRONMENT", "production")
		_, err := Load()
		if err == nil {
			t.Fatal("expected startup failure")
		}
		for _, want := range []string{"SEARCH_REQUIRED_ROLE", "EXPLAIN_REQUIRED_ROLE", "ALLOW_OPEN_DIAGNOSTICS"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q lacks %s", err, want)
			}
		}
	})
	t.Run("production with roles set starts (watch unset = disabled, fine)", func(t *testing.T) {
		base(t)
		t.Setenv("DEPLOYMENT_ENVIRONMENT", "prod")
		t.Setenv("SEARCH_REQUIRED_ROLE", "authz_auditor")
		t.Setenv("EXPLAIN_REQUIRED_ROLE", "authz_auditor")
		if _, err := Load(); err != nil {
			t.Fatalf("unexpected: %v", err)
		}
	})
	t.Run(`production with watch "*" fails`, func(t *testing.T) {
		base(t)
		t.Setenv("DEPLOYMENT_ENVIRONMENT", "production")
		t.Setenv("SEARCH_REQUIRED_ROLE", "authz_auditor")
		t.Setenv("EXPLAIN_REQUIRED_ROLE", "authz_auditor")
		t.Setenv("WATCH_REQUIRED_ROLE", "*")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "WATCH_REQUIRED_ROLE") {
			t.Fatalf("expected watch failure, got %v", err)
		}
	})
	t.Run("override starts with open surfaces", func(t *testing.T) {
		base(t)
		t.Setenv("DEPLOYMENT_ENVIRONMENT", "production")
		t.Setenv("ALLOW_OPEN_DIAGNOSTICS", "true")
		if _, err := Load(); err != nil {
			t.Fatalf("unexpected: %v", err)
		}
	})
	t.Run("non-production stays open by default", func(t *testing.T) {
		base(t)
		t.Setenv("DEPLOYMENT_ENVIRONMENT", "staging")
		if _, err := Load(); err != nil {
			t.Fatalf("unexpected: %v", err)
		}
	})
}

// Every trusted issuer must pin an audience (F21): without one, a token the
// IdP minted for any other API is accepted. Fails closed at startup; the
// override starts (with a warning).
func TestAudienceRequiredPerIssuer(t *testing.T) {
	setIssuers(t, `[
		{"issuer":"https://a","audience":"api","jwks_file":"/keys/a.json"},
		{"issuer":"https://b","jwks_file":"/keys/b.json"}
	]`)
	t.Setenv("ALLOW_UNBOUND_MULTI_ISSUER", "true")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), `issuer 1 ("https://b") has no audience`) ||
		!strings.Contains(err.Error(), "ALLOW_MISSING_AUDIENCE") {
		t.Fatalf("issuer without audience must fail startup naming it and the override, got %v", err)
	}
	t.Setenv("ALLOW_MISSING_AUDIENCE", "true")
	if _, err := Load(); err != nil {
		t.Fatalf("deliberate override must permit startup, got %v", err)
	}
}

// Under the production profile the audience override is refused outright:
// an issuer without an audience fails even with ALLOW_MISSING_AUDIENCE=true,
// and the flag alone fails startup even when every issuer pins an audience.
func TestProductionProfileForbidsMissingAudienceOverride(t *testing.T) {
	t.Run("audience-less issuer fails despite the override", func(t *testing.T) {
		setIssuers(t, `[{"issuer":"https://b","jwks_file":"/keys/b.json"}]`)
		t.Setenv("ALLOW_UNBOUND_MULTI_ISSUER", "")
		t.Setenv("ALLOW_MISSING_AUDIENCE", "true")
		t.Setenv("DEPLOYMENT_ENVIRONMENT", "production")
		t.Setenv("SEARCH_REQUIRED_ROLE", "authz_auditor")
		t.Setenv("EXPLAIN_REQUIRED_ROLE", "authz_auditor")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), `issuer 0 ("https://b") has no audience`) ||
			!strings.Contains(err.Error(), "not honoured") {
			t.Fatalf("production must refuse an audience-less issuer regardless of the override, got %v", err)
		}
	})
	t.Run("the flag alone fails startup", func(t *testing.T) {
		setIssuers(t, `[{"issuer":"https://a","audience":"api","jwks_file":"/keys/a.json"}]`)
		t.Setenv("ALLOW_UNBOUND_MULTI_ISSUER", "")
		t.Setenv("ALLOW_MISSING_AUDIENCE", "true")
		t.Setenv("DEPLOYMENT_ENVIRONMENT", "prod")
		t.Setenv("SEARCH_REQUIRED_ROLE", "authz_auditor")
		t.Setenv("EXPLAIN_REQUIRED_ROLE", "authz_auditor")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "ALLOW_MISSING_AUDIENCE=true is forbidden") {
			t.Fatalf("production must refuse the latent override, got %v", err)
		}
		t.Setenv("ALLOW_MISSING_AUDIENCE", "")
		if _, err := Load(); err != nil {
			t.Fatalf("same config without the override must start, got %v", err)
		}
	})
}

// The production profile refuses ALLOW_UNBOUND_MULTI_ISSUER as well: an
// unbound issuer among several fails even with the override, and the flag
// alone fails startup when every issuer is bound.
func TestProductionProfileForbidsUnboundIssuerOverride(t *testing.T) {
	prod := func(t *testing.T) {
		t.Helper()
		t.Setenv("DEPLOYMENT_ENVIRONMENT", "production")
		t.Setenv("SEARCH_REQUIRED_ROLE", "authz_auditor")
		t.Setenv("EXPLAIN_REQUIRED_ROLE", "authz_auditor")
		t.Setenv("ALLOW_UNBOUND_MULTI_ISSUER", "true")
	}
	t.Run("unbound issuer fails despite the override", func(t *testing.T) {
		setIssuers(t, `[
			{"issuer":"https://a","audience":"api","jwks_file":"/keys/a.json","stores":["a"]},
			{"issuer":"https://b","audience":"api","jwks_file":"/keys/b.json"}
		]`)
		prod(t)
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), `issuer "https://b" has no stores binding`) ||
			!strings.Contains(err.Error(), "not honoured") {
			t.Fatalf("production must refuse an unbound issuer regardless of the override, got %v", err)
		}
	})
	t.Run("the flag alone fails startup", func(t *testing.T) {
		setIssuers(t, `[
			{"issuer":"https://a","audience":"api","jwks_file":"/keys/a.json","stores":["a"]},
			{"issuer":"https://b","audience":"api","jwks_file":"/keys/b.json","stores":["b"]}
		]`)
		prod(t)
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "ALLOW_UNBOUND_MULTI_ISSUER=true is forbidden") {
			t.Fatalf("production must refuse the latent override, got %v", err)
		}
		t.Setenv("ALLOW_UNBOUND_MULTI_ISSUER", "")
		if _, err := Load(); err != nil {
			t.Fatalf("same config without the override must start, got %v", err)
		}
	})
}

func TestAudienceRequiredLegacyForm(t *testing.T) {
	t.Setenv("JWT_ISSUERS", "")
	t.Setenv("JWKS_URL", "")
	t.Setenv("JWKS_FILE", "/keys/a.json")
	t.Setenv("JWT_ISSUER", "https://a")
	t.Setenv("JWT_AUDIENCE", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "has no audience") {
		t.Fatalf("legacy issuer without JWT_AUDIENCE must fail startup, got %v", err)
	}
	t.Setenv("JWT_AUDIENCE", "   ")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "has no audience") {
		t.Fatalf("whitespace audience must count as missing, got %v", err)
	}
	t.Setenv("JWT_AUDIENCE", "api")
	if _, err := Load(); err != nil {
		t.Fatalf("legacy issuer with JWT_AUDIENCE must load, got %v", err)
	}
}
