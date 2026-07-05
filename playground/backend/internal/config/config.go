// Package config loads the playground BFF configuration from the environment.
package config

import (
	"os"
	"strings"
)

// Config holds all runtime settings, sourced from environment variables.
type Config struct {
	Addr         string
	PgDSN        string
	ClientID     string
	ClientSecret string
	Issuer       string // OIDC issuer base; endpoints are resolved from its discovery doc
	RedirectURI  string
	OpaURL       string // internal OPA base, e.g. http://opa:8181
	AuthzenURL   string // internal authzen-opa base for the AuthZEN console (empty = disabled)
	EngineDSN    string // read-only DSN to the pgauthz engine DB (metadata for autocomplete)
	BaseURL      string // public app base, e.g. https://app.pgauthz.test
	BasePath     string // public path prefix this app is served under, e.g. /playground
	CookieSecure bool
	WebDir       string
	Scopes       string
	TLSCAFile    string // optional extra CA (e.g. mkcert dev root) to trust for outbound TLS
	// Explore mode (engine-direct, arbitrary-subject checks + model/tuple browsing) is
	// a privileged capability. Off by default; opt in and optionally require a role.
	ExploreEnabled bool   // PLAYGROUND_EXPLORE_ENABLED
	ExploreRole    string // PLAYGROUND_EXPLORE_ROLE — Keycloak role required (empty = any authenticated user)
	// SearchRole mirrors authzen-opa's SEARCH_REQUIRED_ROLE so the UI can reflect
	// whether the current user may use the AuthZEN reverse-search endpoints. Purely
	// cosmetic (the real gate is in authzen-opa); empty = show search for everyone.
	SearchRole string // PLAYGROUND_SEARCH_ROLE
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// Load reads the configuration from the environment, applying defaults.
func Load() Config {
	return Config{
		Addr:           env("ADDR", ":8080"),
		PgDSN:          env("PG_DSN", "postgres://playground:playground@playground-db:5432/pgauthz_playground"),
		ClientID:       env("CLIENT_ID", "playground-bff"),
		ClientSecret:   env("CLIENT_SECRET", "playground-bff-demo-secret"),
		Issuer:         env("ISSUER", "http://keycloak:8080/realms/pgauthz"),
		RedirectURI:    env("REDIRECT_URI", "https://app.pgauthz.test/auth/callback"),
		OpaURL:         env("OPA_URL", "http://opa:8181"),
		AuthzenURL:     env("AUTHZEN_URL", "http://pgauthzd-opa:8080"),
		EngineDSN:      env("ENGINE_DSN", ""),
		BaseURL:        env("BASE_URL", "https://app.pgauthz.test"),
		BasePath:       strings.TrimRight(env("BASE_PATH", "/playground"), "/"),
		CookieSecure:   env("COOKIE_SECURE", "true") == "true",
		WebDir:         env("WEB_DIR", "/web"),
		Scopes:         env("SCOPES", "openid profile"),
		TLSCAFile:      env("TLS_CA_FILE", ""),
		ExploreEnabled: env("PLAYGROUND_EXPLORE_ENABLED", "false") == "true",
		ExploreRole:    env("PLAYGROUND_EXPLORE_ROLE", ""),
		SearchRole:     env("PLAYGROUND_SEARCH_ROLE", ""),
	}
}
