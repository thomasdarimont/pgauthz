package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
)

// Issuer describes one trusted token issuer and where to find its signing keys.
// The service can trust several at once; the token's "iss" claim selects one.
type Issuer struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	JWKSURL  string `json:"jwks_url"`
	JWKSFile string `json:"jwks_file"`
	// Stores restricts which pgauthz stores this issuer's tokens may access
	// (store binding for multi-tenant setups: tenant A's IdP → tenant A's
	// stores). Each entry is an ANCHORED regular expression (^(?:entry)$), so
	// plain store names match exactly and patterns like "tenant-a-.*" cover
	// store families. Empty = no restriction (all stores).
	Stores []string `json:"stores"`
	// DBRoles restricts which per-app DB roles tokens from this issuer may
	// yield (via DB_ROLE_CLAIM or CLIENT_DB_ROLES) — without it, any trusted
	// issuer could claim another tenant's role. Anchored regexes like Stores.
	// Empty = no restriction. A violation is rejected (403), never silently
	// downgraded to the fixed connection role.
	DBRoles []string `json:"db_roles"`
	// ClientDBRoles maps client ids (`azp`) to per-app DB roles, scoped to
	// THIS issuer — azp values are only meaningful within an issuer, so the
	// per-issuer map avoids cross-tenant azp collisions that the global
	// CLIENT_DB_ROLES map (kept for single-issuer setups) cannot.
	ClientDBRoles map[string]string `json:"client_db_roles"`
}

// Profile selects an instance's capability set (PGAUTHORIZER_PROFILE). The
// security guarantee comes from the DB connection ROLE, not this flag — a
// decision-only instance must connect with a role that physically cannot
// write, and asserts so at startup (fail closed). The profile ties together
// the backend, the DB role's expected privilege, and (later) the exposed API
// surface, so a read-only API can never sit on a writable role by accident.
type Profile string

const (
	// ProfileDecisionOnly — AuthZEN eval/search over a direct read-only pgx
	// connection. Asserts its DB role cannot write. Scale near replicas.
	ProfileDecisionOnly Profile = "decision-only"
	// ProfileFull — direct pgx with read AND write capability (the writer role
	// path); near the primary. (Native write API lands in a later increment.)
	ProfileFull Profile = "full"
	// ProfileCompatOPA — the legacy AuthZEN→OPA→PostgREST path (external OPA
	// for policy extension). No direct DB connection.
	ProfileCompatOPA Profile = "compat-opa"
)

type Config struct {
	Profile     Profile
	ListenAddr  string
	BaseURL     string
	JWKSURL     string
	JWKSFile    string
	JWTIssuer   string
	JWTAudience string

	// Issuers is the resolved set of trusted issuers (the legacy single-issuer
	// env vars plus any from JWT_ISSUERS).
	Issuers []Issuer

	RequiredScope string

	// RolesClaims: comma-separated dotted claim paths to aggregate into the caller's
	// role set (JWT_ROLES_CLAIM), e.g. "realm_access.roles,resource_access.authz-api.roles".
	RolesClaims string
	// SearchRequiredRole: if set, the reverse-search endpoints (search/subject,
	// search/resource, search/action) require the caller to hold this role. Empty
	// (default) leaves search open. These are graph-enumeration queries, so gate
	// them to an auditor-style role in multi-tenant/end-user deployments.
	SearchRequiredRole string

	// DBRoleClaim: dot-separated claim path carrying the caller's per-app DB
	// role for pgauthz namespace enforcement on the direct backend (mirrors
	// the OPA front door's DB_ROLE_CLAIM). Empty = no role scoping.
	DBRoleClaim string
	// ClientDBRoles maps client ids (`azp` claim) to per-app DB roles — the
	// fallback when DBRoleClaim is unset/absent. JSON map via CLIENT_DB_ROLES.
	ClientDBRoles map[string]string

	SubjectTypeClaim   string
	SubjectTypeDefault string
	SubjectIDClaim     string
	SubjectIDFallback  string

	DefaultStore string
	StoreHeader  string

	// RequireStoreBinding (REQUIRE_STORE_BINDING): refuse to start unless every
	// trusted issuer carries an explicit `stores` binding — an issuer without
	// one can reach EVERY store. Off by default (the legacy single-issuer env
	// form has no stores field); set true in any multi-tenant deployment.
	RequireStoreBinding bool
	// RequireDBRoleBinding (REQUIRE_DB_ROLE_BINDING): when per-app DB role
	// derivation is configured (DB_ROLE_CLAIM / CLIENT_DB_ROLES), refuse to
	// start unless every issuer carries a `db_roles` or `client_db_roles`
	// binding — otherwise any trusted issuer can claim any reader role.
	RequireDBRoleBinding bool

	// AllowSubjectOverride lets a request-body subject override the
	// JWT-derived subject. Default false (token-only): a body subject that
	// differs from the authenticated subject is rejected. Enable for trusted
	// PEP/PDP deployments that evaluate access for arbitrary subjects.
	AllowSubjectOverride bool

	// pgbackend only
	DatabaseURL string
	DBPoolMax   int
	// DBRoleCacheTTLSeconds bounds how long a per-app role validation result
	// is cached (DB_ROLE_CACHE_TTL_SECONDS, default 60; 0 = no caching,
	// re-validate every request). Security-sensitive: a dropped role /
	// revoked membership takes effect within this window.
	DBRoleCacheTTLSeconds int

	// opabackend only
	OPAURL     string
	OPAPackage string
	// ForwardTokenToOPA: forward the verified bearer token to OPA as input.token so
	// OPA re-validates it (secure token path), instead of forwarding only the
	// resolved subject (which needs OPA's REQUIRE_TOKEN_FOR_READS=false). Enable in
	// trusted-single-subject deployments (e.g. the playground); leave off for
	// trusted-PEP setups that check arbitrary subjects on behalf of others.
	ForwardTokenToOPA bool

	LogLevel string
}

func Load() (*Config, error) {
	c := &Config{
		Profile:               Profile(env("PGAUTHORIZER_PROFILE", "")),
		ListenAddr:            env("LISTEN_ADDR", ":8080"),
		BaseURL:               env("BASE_URL", ""),
		JWKSURL:               env("JWKS_URL", ""),
		JWKSFile:              env("JWKS_FILE", ""),
		JWTIssuer:             env("JWT_ISSUER", ""),
		JWTAudience:           env("JWT_AUDIENCE", ""),
		RequiredScope:         env("REQUIRED_SCOPE", ""),
		RolesClaims:           env("JWT_ROLES_CLAIM", ""),
		SearchRequiredRole:    env("SEARCH_REQUIRED_ROLE", ""),
		DBRoleClaim:           env("DB_ROLE_CLAIM", ""),
		SubjectTypeClaim:      env("SUBJECT_TYPE_CLAIM", "subject_type"),
		SubjectTypeDefault:    env("SUBJECT_TYPE_DEFAULT", "internal_user"),
		SubjectIDClaim:        env("SUBJECT_ID_CLAIM", "preferred_username"),
		SubjectIDFallback:     env("SUBJECT_ID_FALLBACK_CLAIM", "sub"),
		DefaultStore:          env("DEFAULT_STORE", "demo"),
		StoreHeader:           env("STORE_HEADER", "X-AuthZ-Store"),
		RequireStoreBinding:   envBool("REQUIRE_STORE_BINDING", false),
		RequireDBRoleBinding:  envBool("REQUIRE_DB_ROLE_BINDING", false),
		AllowSubjectOverride:  envBool("ALLOW_SUBJECT_OVERRIDE", false),
		DatabaseURL:           env("DATABASE_URL", ""),
		DBPoolMax:             envInt("DB_POOL_MAX", 25),
		DBRoleCacheTTLSeconds: envInt("DB_ROLE_CACHE_TTL_SECONDS", 60),
		OPAURL:                env("OPA_URL", ""),
		OPAPackage:            env("OPA_PACKAGE", "authz"),
		ForwardTokenToOPA:     envBool("FORWARD_TOKEN_TO_OPA", false),
		LogLevel:              env("LOG_LEVEL", "info"),
	}

	// Build the trusted-issuer list. The legacy single JWKS_URL/JWKS_FILE/
	// JWT_ISSUER/JWT_AUDIENCE form one issuer; JWT_ISSUERS (a JSON array of
	// {issuer, audience, jwks_url, jwks_file}) adds more — so one instance can
	// trust, e.g., a demo IdP for tests and Keycloak for the playground.
	if c.JWKSURL != "" || c.JWKSFile != "" {
		c.Issuers = append(c.Issuers, Issuer{
			Issuer: c.JWTIssuer, Audience: c.JWTAudience,
			JWKSURL: c.JWKSURL, JWKSFile: c.JWKSFile,
		})
	}
	if raw := os.Getenv("CLIENT_DB_ROLES"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &c.ClientDBRoles); err != nil {
			return nil, fmt.Errorf("parsing CLIENT_DB_ROLES: %w", err)
		}
	}
	if raw := os.Getenv("JWT_ISSUERS"); raw != "" {
		var extra []Issuer
		if err := json.Unmarshal([]byte(raw), &extra); err != nil {
			return nil, fmt.Errorf("parsing JWT_ISSUERS: %w", err)
		}
		c.Issuers = append(c.Issuers, extra...)
	}
	for i, iss := range c.Issuers {
		if iss.JWKSURL == "" && iss.JWKSFile == "" {
			return nil, fmt.Errorf("issuer %d (%q) has no jwks_url or jwks_file", i, iss.Issuer)
		}
		for _, p := range iss.Stores {
			if _, err := regexp.Compile("^(?:" + p + ")$"); err != nil {
				return nil, fmt.Errorf("issuer %q: invalid store pattern %q: %w", iss.Issuer, p, err)
			}
		}
		for _, p := range iss.DBRoles {
			if _, err := regexp.Compile("^(?:" + p + ")$"); err != nil {
				return nil, fmt.Errorf("issuer %q: invalid db_roles pattern %q: %w", iss.Issuer, p, err)
			}
		}
	}
	if len(c.Issuers) == 0 {
		return nil, fmt.Errorf("JWKS_URL or JWKS_FILE (or JWT_ISSUERS) is required")
	}

	// Resolve the profile value. Default: compat-opa when an OPA_URL is set
	// (legacy behavior), otherwise full (direct pgx read+write). The
	// per-backend requirement (DATABASE_URL vs OPA_URL) is validated by the
	// command that wires the backend, not here — Load() stays free of
	// deployment-topology assumptions (kept testable in isolation).
	if c.Profile == "" {
		if c.OPAURL != "" {
			c.Profile = ProfileCompatOPA
		} else {
			c.Profile = ProfileFull
		}
	}
	switch c.Profile {
	case ProfileDecisionOnly, ProfileFull, ProfileCompatOPA:
		// ok
	default:
		return nil, fmt.Errorf("unknown PGAUTHORIZER_PROFILE %q (decision-only | full | compat-opa)", c.Profile)
	}

	// Binding requirements: an issuer without a stores binding can reach every
	// store; without a role binding it can claim any reader role. Enforce when
	// the REQUIRE_* flags are set; otherwise warn loudly in the configurations
	// where the gap is a real cross-tenant risk (more than one trusted issuer).
	roleDerivation := c.DBRoleClaim != "" || len(c.ClientDBRoles) > 0
	for _, iss := range c.Issuers {
		if !roleDerivation && len(iss.ClientDBRoles) > 0 {
			roleDerivation = true
		}
	}
	for _, iss := range c.Issuers {
		if len(iss.Stores) == 0 {
			if c.RequireStoreBinding {
				return nil, fmt.Errorf("REQUIRE_STORE_BINDING: issuer %q has no stores binding", iss.Issuer)
			}
			if len(c.Issuers) > 1 {
				log.Printf("WARNING: issuer %q has no stores binding — its tokens can access EVERY store; set stores patterns in JWT_ISSUERS (and REQUIRE_STORE_BINDING=true) for multi-tenant deployments", iss.Issuer)
			}
		}
		if roleDerivation && len(iss.DBRoles) == 0 && len(iss.ClientDBRoles) == 0 {
			if c.RequireDBRoleBinding {
				return nil, fmt.Errorf("REQUIRE_DB_ROLE_BINDING: issuer %q has no db_roles or client_db_roles binding", iss.Issuer)
			}
			if len(c.Issuers) > 1 {
				log.Printf("WARNING: issuer %q has no db_roles/client_db_roles binding — its tokens can claim ANY reader role; set db_roles patterns in JWT_ISSUERS (and REQUIRE_DB_ROLE_BINDING=true) for multi-tenant deployments", iss.Issuer)
			}
		}
	}

	return c, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

// UsesDirectBackend reports whether the profile connects to PostgreSQL directly
// (vs. the compat OPA path).
func (c *Config) UsesDirectBackend() bool {
	return c.Profile == ProfileDecisionOnly || c.Profile == ProfileFull
}

// Writable reports whether the profile's DB role is expected to hold write
// capability (drives the read-only startup assertion).
func (c *Config) Writable() bool {
	return c.Profile == ProfileFull || c.Profile == ProfileCompatOPA
}
