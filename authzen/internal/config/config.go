package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	ListenAddr  string
	BaseURL     string
	JWKSURL     string
	JWKSFile    string
	JWTIssuer   string
	JWTAudience string

	RequiredScope string

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

	if c.JWKSURL == "" && c.JWKSFile == "" {
		return nil, fmt.Errorf("JWKS_URL or JWKS_FILE is required")
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
