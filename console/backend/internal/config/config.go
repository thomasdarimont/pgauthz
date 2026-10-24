// Package config loads the console BFF configuration from the environment.
package config

import (
	"os"
	"strings"
)

// TeamClaim maps a token claim to console teams: every value under Path
// becomes "team:<Prefix>_<value>" for the logged-in user, as a contextual
// tuple on console checks. Default: realm roles, groups, organizations.
type TeamClaim struct {
	Prefix string
	Path   string // dotted path into the token payload, e.g. realm_access.roles
}

// Config holds all runtime settings, sourced from environment variables.
type Config struct {
	Addr         string
	PgDSN        string // the BFF's own DB (sessions) — separate from the engine
	EngineDSN    string // the engine, as the authz_console role (db/security/roles.sql)
	ClientID     string
	ClientSecret string
	Issuer       string // OIDC issuer base; endpoints are resolved from its discovery doc
	RedirectURI  string
	BaseURL      string // public app base, e.g. https://app.pgauthz.test
	BasePath     string // public path prefix, e.g. /console
	CookieSecure bool
	WebDir       string
	Scopes       string
	TLSCAFile    string // optional extra CA (mkcert dev root) for outbound TLS

	// ConsoleStore is the pgauthz store that answers "may this person do this
	// in the console?" (examples/models/console). PlatformID / RegistryID are
	// the ids of its singleton objects.
	ConsoleStore string
	PlatformID   string
	RegistryID   string
	// SubjectType is the console store's type for people; the id is the
	// token's preferred_username (fallback: sub).
	SubjectType string
	TeamClaims  []TeamClaim
	// PgauthzdURL (optional) is a pgauthzd instance whose /readyz the Settings
	// page shows; empty = not shown.
	PgauthzdURL string
	// DecisionURL (optional) is the pgauthzd instance applications use for
	// decisions (OPA-fronted when the overlay is on). The Test tab's "as me"
	// mode sends the person's own token there with X-PGAuthz-Detail, so a
	// tester sees the real PEP path — including OPA and its hooks — for
	// themselves. Empty = the mode is hidden.
	DecisionURL string
	// PgauthzdInternalURL / PgauthzdServiceToken (optional): a pgauthzd's
	// internal callback listener (INTERNAL_LISTEN_ADDR, the service token OPA
	// presents) — Platform → Issuers reads the EFFECTIVE issuer set there
	// (every trusted issuer, binding source, applied revision). Empty = the
	// tab shows the database rows only.
	PgauthzdInternalURL  string
	PgauthzdServiceToken string
	// TraceURL (optional) is the tracing UI's trace page with a {trace_id}
	// placeholder, e.g. https://jaeger.example.com/trace/{trace_id}: the
	// Decisions tab links a logged decision into the application's trace.
	TraceURL string
	// I18nDir (optional) holds translation overrides: <lang>.json files whose
	// entries win over the SPA's built-in dictionaries, so an operator can
	// rename terms or add a language without rebuilding the image.
	I18nDir string
	// OPAURL / OPAToken (optional): the OPA sidecar fronting pgauthzd, read
	// for the Policies tab (GET /v1/policies is admin-only in OPA's system
	// authorization policy, so this is the admin token). Unset = the tab
	// says OPA is not configured.
	OPAURL   string
	OPAToken string
	// SelfSubjectTypes are the subject types that denote a PERSON in the
	// managed stores (CONSOLE_SELF_SUBJECT_TYPES, comma-separated; the console
	// subject type is always included). The test policy's "your own access"
	// means one of these types with the person's id — not any type that
	// happens to use the same id (agent:alice is not alice).
	SelfSubjectTypes []string
	// DeploymentEnvironment mirrors pgauthzd's flag so Settings can say which
	// stack this is.
	DeploymentEnvironment string

	// LocalAdmin (optional) is a username/password sign-in that needs no OpenID
	// Provider — for a first look at a fresh deployment and for tests. Set
	// CONSOLE_LOCAL_ADMIN_USER and CONSOLE_LOCAL_ADMIN_PASSWORD together; the
	// person signs in as <SubjectType>:<user> with the memberships in
	// LocalAdminTeams (default: the console_admin team the seed makes platform
	// admin). Unset either variable and restart to DEACTIVATE it: the sign-in
	// disappears and every local session is rejected at once. Refused under
	// DEPLOYMENT_ENVIRONMENT=production unless LocalAdminAllowInProduction.
	LocalAdminUser              string
	LocalAdminPassword          string
	LocalAdminTeams             []string
	LocalAdminAllowInProduction bool
	// LocalAdminStoreRole is the store role the local admin holds on EVERY
	// store, contextually (nothing written): "owner" by default, so the
	// account can do everything a test needs — platform admin alone only sees
	// stores. Empty = no store role beyond what the teams grant.
	LocalAdminStoreRole string
}

// LocalAdminEnabled reports whether the local sign-in is configured.
func (c Config) LocalAdminEnabled() bool { return c.LocalAdminUser != "" && c.LocalAdminPassword != "" }

// Production reports the production profile (DEPLOYMENT_ENVIRONMENT).
func (c Config) Production() bool {
	return c.DeploymentEnvironment == "production" || c.DeploymentEnvironment == "prod"
}

// localAdminStoreRole: CONSOLE_LOCAL_ADMIN_STORE_ROLE, default "owner"; the
// explicit empty value "none" switches it off (an empty variable reads as unset).
func localAdminStoreRole() string {
	v := env("CONSOLE_LOCAL_ADMIN_STORE_ROLE", "owner")
	if v == "none" {
		return ""
	}
	return v
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func parseTeamClaims(spec string) []TeamClaim {
	var out []TeamClaim
	for part := range strings.SplitSeq(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		prefix, path, ok := strings.Cut(part, "=")
		if !ok || prefix == "" || path == "" {
			continue
		}
		out = append(out, TeamClaim{Prefix: strings.TrimSpace(prefix), Path: strings.TrimSpace(path)})
	}
	return out
}

// Load reads the configuration from the environment, applying defaults.
func Load() Config {
	return Config{
		Addr:         env("ADDR", ":8080"),
		PgDSN:        env("PG_DSN", "postgres://console:console@console-db:5432/pgauthz_console"),
		EngineDSN:    env("ENGINE_DSN", "postgres://authz_console:authz@authz-db:5432/authz"),
		ClientID:     env("CLIENT_ID", "console-bff"),
		ClientSecret: env("CLIENT_SECRET", "console-bff-demo-secret"),
		Issuer:       env("ISSUER", ""), // empty = no OpenID Provider (local admin only)
		RedirectURI:  env("REDIRECT_URI", "https://app.pgauthz.test/console/auth/callback"),
		BaseURL:      env("BASE_URL", "https://app.pgauthz.test"),
		BasePath:     strings.TrimRight(env("BASE_PATH", "/console"), "/"),
		CookieSecure: env("COOKIE_SECURE", "true") == "true",
		WebDir:       env("WEB_DIR", "/web"),
		Scopes:       env("SCOPES", "openid profile"),
		TLSCAFile:    env("TLS_CA_FILE", ""),

		ConsoleStore: env("CONSOLE_STORE", "console"),
		PlatformID:   env("CONSOLE_PLATFORM_ID", "default"),
		RegistryID:   env("CONSOLE_REGISTRY_ID", "default"),
		SubjectType:  env("CONSOLE_SUBJECT_TYPE", "user"),
		TeamClaims:   parseTeamClaims(env("CONSOLE_TEAM_CLAIMS", "role=realm_access.roles,group=groups,org=organization")),

		PgauthzdURL:           env("PGAUTHZD_URL", ""),
		DecisionURL:           env("PGAUTHZD_DECISION_URL", ""),
		PgauthzdInternalURL:   env("PGAUTHZD_INTERNAL_URL", ""),
		PgauthzdServiceToken:  env("PGAUTHZD_SERVICE_TOKEN", ""),
		TraceURL:              env("CONSOLE_TRACE_URL", ""),
		I18nDir:               env("CONSOLE_I18N_DIR", ""),
		OPAURL:                env("CONSOLE_OPA_URL", ""),
		OPAToken:              env("CONSOLE_OPA_TOKEN", ""),
		SelfSubjectTypes:      splitList(env("CONSOLE_SELF_SUBJECT_TYPES", "")),
		DeploymentEnvironment: env("DEPLOYMENT_ENVIRONMENT", "dev"),

		LocalAdminUser:              env("CONSOLE_LOCAL_ADMIN_USER", ""),
		LocalAdminPassword:          env("CONSOLE_LOCAL_ADMIN_PASSWORD", ""),
		LocalAdminTeams:             splitList(env("CONSOLE_LOCAL_ADMIN_TEAMS", "role_console_admin")),
		LocalAdminAllowInProduction: env("CONSOLE_LOCAL_ADMIN_ALLOW_IN_PRODUCTION", "") == "true",
		LocalAdminStoreRole:         localAdminStoreRole(),
	}
}

// splitList splits a comma-separated env value, trimming blanks.
func splitList(v string) []string {
	var out []string
	for x := range strings.SplitSeq(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
