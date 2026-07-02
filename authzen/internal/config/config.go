package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// Issuer describes one trusted token issuer and where to find its signing keys.
// The service can trust several at once; the token's "iss" claim selects one.
type Issuer struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	JWKSURL  string `json:"jwks_url"`
	JWKSFile string `json:"jwks_file"`
}

type Config struct {
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

	SubjectTypeClaim   string
	SubjectTypeDefault string
	SubjectIDClaim     string
	SubjectIDFallback  string

	DefaultStore string
	StoreHeader  string

	// AllowSubjectOverride lets a request-body subject override the
	// JWT-derived subject. Default false (token-only): a body subject that
	// differs from the authenticated subject is rejected. Enable for trusted
	// PEP/PDP deployments that evaluate access for arbitrary subjects.
	AllowSubjectOverride bool

	// pgbackend only
	DatabaseURL string
	DBPoolMax   int

	// opabackend only
	OPAURL     string
	OPAPackage string

	LogLevel string
}

func Load() (*Config, error) {
	c := &Config{
		ListenAddr:           env("LISTEN_ADDR", ":8080"),
		BaseURL:              env("BASE_URL", ""),
		JWKSURL:              env("JWKS_URL", ""),
		JWKSFile:             env("JWKS_FILE", ""),
		JWTIssuer:            env("JWT_ISSUER", ""),
		JWTAudience:          env("JWT_AUDIENCE", ""),
		RequiredScope:        env("REQUIRED_SCOPE", ""),
		RolesClaims:          env("JWT_ROLES_CLAIM", ""),
		SearchRequiredRole:   env("SEARCH_REQUIRED_ROLE", ""),
		SubjectTypeClaim:     env("SUBJECT_TYPE_CLAIM", "subject_type"),
		SubjectTypeDefault:   env("SUBJECT_TYPE_DEFAULT", "internal_user"),
		SubjectIDClaim:       env("SUBJECT_ID_CLAIM", "preferred_username"),
		SubjectIDFallback:    env("SUBJECT_ID_FALLBACK_CLAIM", "sub"),
		DefaultStore:         env("DEFAULT_STORE", "demo"),
		StoreHeader:          env("STORE_HEADER", "X-AuthZ-Store"),
		AllowSubjectOverride: envBool("ALLOW_SUBJECT_OVERRIDE", false),
		DatabaseURL:          env("DATABASE_URL", ""),
		DBPoolMax:            envInt("DB_POOL_MAX", 25),
		OPAURL:               env("OPA_URL", ""),
		OPAPackage:           env("OPA_PACKAGE", "authz"),
		LogLevel:             env("LOG_LEVEL", "info"),
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
	}
	if len(c.Issuers) == 0 {
		return nil, fmt.Errorf("JWKS_URL or JWKS_FILE (or JWT_ISSUERS) is required")
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
