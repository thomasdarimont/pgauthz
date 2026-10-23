package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
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
	// plain store names match exactly and patterns like "tenant_a_.*" cover
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
	// PEPClients (ADR 0014) names the clients of this issuer — token `azp`,
	// else `client_id` — that may ASSERT a request-body subject (and a
	// differing performed_by / recorded_by), and in which stores: client id →
	// anchored store patterns, the Stores syntax. A pattern may not reach
	// beyond the issuer's Stores binding. Everything not listed is
	// self-subject: the token's subject is authoritative. ALLOW_SUBJECT_OVERRIDE
	// =true makes the map irrelevant (and is refused alongside it in
	// production).
	PEPClients map[string][]string `json:"pep_clients"`
}

// Profile selects an instance's DB CAPABILITY (PGAUTHORIZER_PROFILE): read-only
// vs read+write. The security guarantee comes from the DB connection ROLE, not
// this flag — a decision-only instance must connect with a role that physically
// cannot write, and asserts so at startup (fail closed). The profile ties the
// DB role's expected privilege to the exposed write surface, so a read-only API
// can never sit on a writable role by accident.
//
// Fronting an OPA policy sidecar is ORTHOGONAL to the profile: set OPA_URL and
// pgauthzd consults OPA for the AuthZEN /access/v1 surface (forwarding the
// token); the native /pgauthz/v1 surface is always served directly by pgx and
// gated by pgauthzd itself. (This supersedes the former `compat-opa` profile.)
type Profile string

const (
	// ProfileDecisionOnly — read-only: AuthZEN eval/search + native reads over a
	// direct read-only pgx connection. Asserts its DB role cannot write. Scale
	// near replicas.
	ProfileDecisionOnly Profile = "decision-only"
	// ProfileFull — direct pgx with read AND write capability (the writer role
	// path); near the primary. Serves the native write API, gated by the
	// writer-role claim (WRITER_ROLE) on the public listener.
	ProfileFull Profile = "full"
)

type Config struct {
	Profile Profile
	// ListenAddr is the primary (external) listener. It serves the AuthZEN
	// /access/v1 surface (OPA-fronted when OPA_URL is set, else direct pgx) plus
	// the native /pgauthz/v1 surface — the latter only when NOT fronting OPA.
	ListenAddr string
	// InternalListenAddr is the OPA CALLBACK listener: it serves the native raw
	// endpoints an OPA sidecar calls back into, authenticated by the shared
	// service token (not the end-user JWT). It must NOT be exposed to untrusted
	// callers — bind it to the sidecar/localhost network. Set this on any
	// instance a co-located OPA calls back into. Empty = disabled.
	InternalListenAddr string
	// InternalServiceToken is the shared SERVICE credential the internal
	// listener requires (Authorization: Bearer <token>) — it proves the call
	// came from the trusted OPA sidecar. The listener then trusts OPA's asserted
	// subject (body) + per-app role (X-PGAuthz-Role), the trusted-backend role
	// the native `/pgauthz/v1` callback plays. REQUIRED when InternalListenAddr is set (fail
	// closed: no unauthenticated internal listener). Env INTERNAL_SERVICE_TOKEN.
	InternalServiceToken string
	// Optional mTLS on the internal listener: the transport-layer caller
	// authentication that layers UNDER the service token. When all three are
	// set, the listener serves HTTPS and REQUIRES + verifies a client
	// certificate chained to InternalClientCA (so only the OPA sidecar holding a
	// matching cert can connect). Prefer mesh-provided mTLS where available;
	// these are for cross-network / no-mesh deployments. Empty = plain HTTP
	// (fine for same-pod/localhost). Env INTERNAL_TLS_CERT / INTERNAL_TLS_KEY /
	// INTERNAL_CLIENT_CA.
	InternalTLSCert  string
	InternalTLSKey   string
	InternalClientCA string
	BaseURL          string
	// TrustForwardedHeaders (TRUST_FORWARDED_HEADERS, default false) lets the
	// discovery document take its scheme and host from X-Forwarded-Proto /
	// X-Forwarded-Host, for an instance behind a TLS-terminating proxy that
	// sets them. Off by default: trusting them from arbitrary clients would
	// let a caller choose what the PDP advertises as its identifier. BASE_URL,
	// when set, wins over both.
	TrustForwardedHeaders bool
	JWKSURL               string
	JWKSFile              string
	JWTIssuer             string
	JWTAudience           string

	// Issuers is the resolved set of trusted issuers (the legacy single-issuer
	// env vars plus any from JWT_ISSUERS).
	Issuers []Issuer

	RequiredScope string

	// RolesClaims: comma-separated dotted claim paths to aggregate into the
	// caller's role set (JWT_ROLES_CLAIM), e.g.
	// "realm_access.roles,resource_access.authz-api.roles". Defaults to "roles"
	// (matching OPA's authn_config) so the writer-role and search-role gates work
	// out of the box; override for issuers that nest roles elsewhere (Keycloak).
	RolesClaims string
	// SearchRequiredRole: if set, the reverse-search endpoints (search/subject,
	// search/resource, search/action) require the caller to hold this role. Empty
	// (default) leaves search open. These are graph-enumeration queries, so gate
	// them to an auditor-style role in multi-tenant/end-user deployments.
	SearchRequiredRole string
	// AllowUnboundMultiIssuer: with MORE THAN ONE trusted issuer, unbound
	// issuers (no stores / db_roles binding) are a cross-tenant risk and are
	// FATAL at startup by default (review #10). This deliberately alarming
	// override restores the old warn-and-continue behavior.
	AllowUnboundMultiIssuer bool
	// WatchRequiredRole gates the native watch/changefeed route on the PUBLIC
	// listener (review #10): the changefeed exposes the store's authorization
	// topology (subjects, objects, relations, mutation timing), and the
	// daemon's DB role holds authz_auditor precisely to serve it — so the
	// HTTP layer must decide WHO may ask. DENY BY DEFAULT: unset = the public
	// watch route returns 403; a role name = callers holding it (JWT roles)
	// may watch; "*" = explicitly open (discouraged). The internal callback
	// listener is unaffected (OPA is a trusted PEP).
	WatchRequiredRole string
	// ExplainRequiredRole gates native explain on the public listener the same
	// way search is gated: empty = open (back-compat; explain reveals model
	// structure and resolution traces — set a role in production).
	ExplainRequiredRole string

	// WriterRole: the JWT role (within JWT_ROLES_CLAIM) a caller must hold to use
	// the native write endpoints on the PUBLIC listener — pgauthzd is the write
	// front door and authorizes writes itself (no OPA needed on the write path).
	// Default "authz_writer". The service-token callback listener does NOT apply
	// this gate (it trusts the upstream OPA's asserted X-PGAuthz-Role). Env
	// WRITER_ROLE.
	WriterRole string
	// RecorderRole: the JWT role a caller must hold to feed the ACTION LOG
	// (POST /pgauthz/v1/events, ADR 0012) on the PUBLIC listener; the
	// WriterRole also passes (a writer can record). Default "authz_recorder".
	// Like WriterRole it is not applied on the callback listener. Env
	// RECORDER_ROLE.
	RecorderRole string

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

	// ActorClaim (ACTOR_CLAIM): dot-separated path of the verified-token claim
	// that names a DELEGATED ACTOR — the party acting on the token subject's
	// behalf (RFC 8693 `act.client_id`; Keycloak token-exchange delegation).
	// When the path resolves to a non-empty string the request's principal is
	// (ActorSubjectType, <value>) and the token's own subject is carried as
	// on_behalf_of (decision log): an agent holding a delegated token is
	// checked with ITS authority, never the user's. Empty = off — a token
	// carrying an act claim is then treated as its subject, as before.
	ActorClaim string
	// ActorSubjectType (ACTOR_SUBJECT_TYPE): the subject type of a delegated
	// actor, e.g. "agent" (the default).
	ActorSubjectType string

	// FreshnessKeys are the ordered HMAC secrets for signing/verifying freshness
	// tokens (ADR 0009 read-your-writes): the FIRST key mints, EVERY key
	// verifies — which is what makes key rotation a zero-downtime overlap
	// ("old,new" → "new,old" → "new"; see PRODUCTION.md). Empty disables the
	// feature: writes mint no token, and a read presenting
	// `X-PGAuthz-Consistency: at_least_as_fresh` is rejected (400) rather than
	// served as if fresh (fail closed). Env FRESHNESS_TOKEN_KEYS
	// (comma-separated; secrets must not contain commas), or the single-key
	// alias FRESHNESS_TOKEN_KEY — setting both is a startup error.
	FreshnessKeys []string
	// FreshnessPrimaryURL, when set on a decision-only reader, is a reader-role
	// DSN to the PRIMARY used for TRANSPARENT freshness fallback (ADR 0009): an
	// at_least_as_fresh read the local replica can't satisfy is transparently
	// re-run on the primary (authoritative) instead of returning 409. Empty = the
	// 409 + X-PGAuthz-Stale behavior (caller retries the primary). Env
	// FRESHNESS_PRIMARY_URL. Note: this gives readers a network path to the
	// primary — it trades isolation/load-visibility for client convenience.
	FreshnessPrimaryURL string
	// FreshnessPrimaryPoolMax bounds the fallback pool so a fallback storm can't
	// exhaust the primary's connections (keep it small). Env
	// FRESHNESS_PRIMARY_POOL_MAX, default 10.
	FreshnessPrimaryPoolMax int

	// OpenAPIEnabled serves this instance's OpenAPI description at
	// GET /pgauthz/v1/openapi.{json,yaml} on the public listener,
	// unauthenticated (the document ships in the public repository). The served
	// document is INSTANCE-ACCURATE: an OPA-fronted instance's copy omits the
	// native paths its public listener does not register. Env OPENAPI_ENABLED,
	// default true; set false to disable the endpoints entirely (exposure
	// minimization).
	OpenAPIEnabled bool

	// SwaggerUIEnabled (SWAGGER_UI_ENABLED, default false) serves an embedded
	// Swagger UI at GET /pgauthz/v1/docs for the OpenAPI document above —
	// same origin, so "Try it out" needs no CORS. The assets are vendored
	// into the binary (internal/api/swaggerui, pinned version), never loaded
	// from a CDN. Off by default: it is a developer convenience, not part of
	// the API surface. Needs OPENAPI_ENABLED.
	SwaggerUIEnabled bool
	// SwaggerUIOIDCIssuer / SwaggerUIOIDCClientID / SwaggerUIOIDCScopes
	// (SWAGGER_UI_OIDC_ISSUER, SWAGGER_UI_OIDC_CLIENT_ID, SWAGGER_UI_OIDC_SCOPES
	// default "openid") let the embedded Swagger UI log a user in with the
	// authorization code flow + PKCE against an OpenID Provider instead of a
	// pasted token: the served OpenAPI document gains an `oidc` security
	// scheme (openIdConnect, the issuer's discovery URL) on every
	// authenticated operation, and the UI is initialised with the public
	// client id. The issuer must be one pgauthzd trusts (JWT_ISSUERS) and the
	// client must be registered there with redirect URI
	// <public base>/pgauthz/v1/docs/oauth2-redirect.html (keycloak/terraform/
	// client.swagger-ui.tf is the demo's).
	SwaggerUIOIDCIssuer   string
	SwaggerUIOIDCClientID string
	SwaggerUIOIDCScopes   string
	// SwaggerUIOIDCAuthorizationURL / SwaggerUIOIDCTokenURL
	// (SWAGGER_UI_OIDC_AUTHORIZATION_URL, SWAGGER_UI_OIDC_TOKEN_URL, optional,
	// both or neither): with them the served document describes exactly ONE
	// flow — oauth2 authorizationCode with these endpoints — so the Authorize
	// dialog shows one login. Without them it names the issuer's discovery URL
	// (openIdConnect), which works but makes Swagger UI render a section per
	// grant type the provider advertises.
	SwaggerUIOIDCAuthorizationURL string
	SwaggerUIOIDCTokenURL         string

	// CORSAllowedOrigins (CORS_ALLOWED_ORIGINS, comma-separated, default empty)
	// are the browser origins that may call the AUTHENTICATED API cross-origin
	// — a browser-based PEP, or Swagger UI's "Try it out" from another port.
	// "*" allows any origin. The public endpoints (discovery, health, the
	// OpenAPI document) answer any origin regardless: they carry no
	// credentials and are public by design. Empty = no CORS headers on the
	// authenticated surface (browsers refuse cross-origin calls).
	CORSAllowedOrigins []string

	// DeploymentEnvironment (DEPLOYMENT_ENVIRONMENT, e.g. "production") is a
	// SERVER-configured label forwarded to OPA policy hooks as
	// input.deployment.environment (ADR 0011). Environment-gated hooks read it
	// instead of a caller-supplied context field, which they must not trust.
	// Empty = the field is still present but "".
	//
	// It also selects the PRODUCTION PROFILE: with "production" (or "prod")
	// the discovery/diagnostic surfaces must be role-gated — SEARCH_REQUIRED_ROLE
	// and EXPLAIN_REQUIRED_ROLE set, WATCH_REQUIRED_ROLE not "*" — or startup
	// fails (see AllowOpenDiagnostics). Reverse search enumerates the access
	// graph and explain reveals model structure and resolution traces; the
	// open-by-default runtime behaviour stays for development and back-compat,
	// the production profile is deliberately opinionated (external review).
	DeploymentEnvironment string
	// AllowOpenDiagnostics (ALLOW_OPEN_DIAGNOSTICS) is the deliberately alarming
	// override that lets a production-labelled instance start with an open
	// search/explain/watch surface (logged as a WARNING on every start).
	AllowOpenDiagnostics bool
	// AllowMissingAudience (ALLOW_MISSING_AUDIENCE) lets a trusted issuer be
	// configured WITHOUT an expected `aud`. Every issuer must otherwise pin an
	// audience (JWT_AUDIENCE / "audience" in JWT_ISSUERS): without one, any
	// token the IdP mints for ANY other API — same signing keys, same subject
	// claims — is accepted here. Startup fails by default; the
	// override starts anyway and logs a WARNING on every start.
	AllowMissingAudience bool
	// OPAMaxResponseBytes bounds every OPA HTTP response body (review #10):
	// a broken/misconfigured OPA must cause a clean policy_evaluation_failed,
	// not unbounded allocation. Default 10 MiB, matching HTTP_MAX_BODY_BYTES.
	OPAMaxResponseBytes int64
	// CursorSealKey seals filtered-enumeration page cursors (they carry raw
	// keyset ids that hooks may have removed from results — ADR 0011).
	// Comma-separated keyring: first mints, all accept (rotate by prepending,
	// then dropping the old key). Unset = random per-process key (opaque but
	// not portable across replicas/restarts).
	CursorSealKey string

	// MetricsListenAddr, when set, serves the Prometheus `/metrics` endpoint on a
	// SEPARATE listener (ADR 0010). Bind it to the pod/mesh network — never the
	// public client listener (tenants must not scrape ops data). Empty = off. Env
	// METRICS_LISTEN_ADDR (e.g. ":9090").
	MetricsListenAddr string
	// MetricsSampleIntervalSeconds bounds how often the engine/tenant gauges
	// (per-store tuple counts, ADR 0010 Slice 3) are sampled from the DB. Only
	// active when metrics are exposed. 0 disables the sampler. Env
	// METRICS_SAMPLE_INTERVAL_SECONDS, default 30.
	MetricsSampleIntervalSeconds int
	// MetricsMaxStores caps the number of per-store series emitted (top-N by
	// tuple count) so many tenants can't explode Prometheus cardinality;
	// `pgauthzd_stores_total` still reports the true count. Env
	// METRICS_MAX_STORES, default 100.
	MetricsMaxStores int

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

	// ContextualTuples (CONTEXTUAL_TUPLES) says who may send contextual
	// tuples — ephemeral "what-if" relationships evaluated with a native
	// check — on the PUBLIC listener: "off" (never), "trusted-peps" (default:
	// only a caller that may assert a subject for the store — a pep_clients
	// entry, or ALLOW_SUBJECT_OVERRIDE=true — the same trust that lets a
	// caller shape the question), or "any" (every authenticated caller;
	// refused in production). The callback listener always accepts them:
	// its caller is OPA. Nothing is ever written; the switch bounds who can
	// forge a decision to their own question and probe the graph with
	// hypotheticals.
	ContextualTuples string

	// pgbackend only
	DatabaseURL string
	DBPoolMax   int
	// DefaultDBRole, when set, is the role the read path SET LOCAL ROLEs to when
	// a request carries no per-app db_role. It mirrors the pgauthzd reader
	// profile's always-SET-ROLE model (default authz_reader): the query never runs as the raw
	// connection role, so that role's SET-ROLE memberships (needed to assume
	// per-app roles) don't leak into membership-keyed checks like namespace
	// access. Set to a namespace-free reader (e.g. authz_reader) on the compat
	// read callback whose connection role is granted per-app roles. Empty = run
	// as the connection role (fine when it holds no per-app memberships). Env
	// DEFAULT_DB_ROLE.
	DefaultDBRole string
	// DBRoleCacheTTLSeconds bounds how long a per-app role validation result
	// is cached (DB_ROLE_CACHE_TTL_SECONDS, default 60; 0 = no caching,
	// re-validate every request). Security-sensitive: a dropped role /
	// revoked membership takes effect within this window.
	DBRoleCacheTTLSeconds int

	// HTTP hardening (review #9). Applied to EVERY listener: a slow-header
	// (slowloris) or idle-connection flood must not exhaust the front door.
	// Deliberately NO WriteTimeout — long-running search/explain/watch
	// responses must not be killed mid-write.
	//
	// HTTPReadHeaderTimeout: max time to read request headers. Env
	// HTTP_READ_HEADER_TIMEOUT (Go duration), default 5s.
	HTTPReadHeaderTimeout time.Duration
	// HTTPIdleTimeout: max keep-alive idle time. Env HTTP_IDLE_TIMEOUT,
	// default 60s.
	HTTPIdleTimeout time.Duration
	// HTTPMaxBodyBytes caps request bodies (http.MaxBytesReader). Generous by
	// default — batch writes/offboarding payloads are legitimately large.
	// Env HTTP_MAX_BODY_BYTES, default 10 MiB; 0 disables the cap.
	HTTPMaxBodyBytes int64

	// opabackend only
	OPAURL     string
	OPAPackage string
	// OPARequestTimeout bounds every OPA HTTP call (decisions, searches, the
	// readiness query). Go's zero client timeout is UNLIMITED — a black-holed
	// OPA would otherwise hang requests and startup (review #9). Env
	// OPA_REQUEST_TIMEOUT (Go duration), default 10s (decisions are fast, but
	// OPA-fronted searches can be slower).
	OPARequestTimeout time.Duration
	// OPADeepReadinessRequired (OPA_DEEP_READINESS_REQUIRED, default false):
	// when true, a policy set WITHOUT the data.authz.pgauthz.callback_healthy
	// rule FAILS readiness instead of silently degrading to the shallow
	// OPA-/health-only check — so an operator can't believe end-to-end
	// readiness is active when it isn't (review #9). Leave false only when a
	// custom Rego bundle deliberately omits the rule; either way the active
	// mode is exported as pgauthzd_opa_readiness_mode{mode}.
	OPADeepReadinessRequired bool
	// OPAEvalMetrics adds `metrics=true` to OPA queries so pgauthzd can record
	// OPA's own Rego evaluation time (`pgauthzd_opa_rego_eval_duration_seconds`,
	// from timer_rego_query_eval_ns). Small per-request OPA overhead; env
	// OPA_EVAL_METRICS, default true. Disable to shed that overhead when the
	// isolated eval-time histogram isn't needed.
	OPAEvalMetrics bool
	// ForwardTokenToOPA: forward the verified bearer token to OPA as input.token so
	// OPA re-validates it (secure token path), instead of forwarding only the
	// resolved subject (which needs OPA's REQUIRE_TOKEN_FOR_READS=false). Enable in
	// trusted-single-subject deployments (e.g. the playground); leave off for
	// trusted-PEP setups that check arbitrary subjects on behalf of others.
	ForwardTokenToOPA bool

	LogLevel string
	// Decision log (ADR 0013): one JSON line per decision, emitted by the daemon.
	// DecisionLog is the sink: off (default) | stdout | stderr | file:<path>
	// | postgres (ADR 0015: a sink database, DecisionLogDSN, batched inserts
	// into daily partitions, retention DecisionLogRetentionDays, at most
	// DecisionLogQueue lines waiting between flushes — the console's
	// Decisions tab reads that table).
	DecisionLog              string
	DecisionLogDSN           string
	DecisionLogRetentionDays int
	DecisionLogQueue         int
	// DecisionLogSample in [0,1] samples ALLOW lines; denies, conditionals and
	// errors are always written. Default 1 (everything).
	DecisionLogSample float64
	// DecisionLogDetail upgrades plain checks to the detailed evaluation FOR
	// THE LOG ONLY (state/reason on every line); responses are unchanged.
	DecisionLogDetail bool
	// DecisionLogRequired makes the requested log stream evidence, not best
	// effort: after a failed write, readiness reports 503 and decision
	// endpoints refuse (503) until the sink accepts a line again (probed at
	// most once per second). If DecisionLogSearches is also enabled, search
	// endpoints refuse the same way, because those search lines are part of
	// the requested evidence stream. Implies DecisionLogSample = 1. Regulated
	// deployments only.
	DecisionLogRequired bool
	// DecisionLogSearches adds one line per search (AuthZEN search/*, native
	// list-*): actor, store, kind, query dimensions, result COUNT, latency —
	// never the returned ids.
	DecisionLogSearches bool
}

// deploymentEnvRe bounds DEPLOYMENT_ENVIRONMENT to a short identifier
// (letters/digits/_/-, ≤32), since hooks gate on it.
var deploymentEnvRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,31}$`)

func Load() (*Config, error) {
	envErrs = nil // fresh collection per Load (tests call it repeatedly)
	c := &Config{
		Profile:                       Profile(env("PGAUTHORIZER_PROFILE", "")),
		ListenAddr:                    env("LISTEN_ADDR", ":8080"),
		InternalListenAddr:            env("INTERNAL_LISTEN_ADDR", ""),
		InternalServiceToken:          env("INTERNAL_SERVICE_TOKEN", ""),
		InternalTLSCert:               env("INTERNAL_TLS_CERT", ""),
		InternalTLSKey:                env("INTERNAL_TLS_KEY", ""),
		InternalClientCA:              env("INTERNAL_CLIENT_CA", ""),
		BaseURL:                       env("BASE_URL", ""),
		TrustForwardedHeaders:         envBool("TRUST_FORWARDED_HEADERS", false),
		JWKSURL:                       env("JWKS_URL", ""),
		JWKSFile:                      env("JWKS_FILE", ""),
		JWTIssuer:                     env("JWT_ISSUER", ""),
		JWTAudience:                   env("JWT_AUDIENCE", ""),
		RequiredScope:                 env("REQUIRED_SCOPE", ""),
		RolesClaims:                   env("JWT_ROLES_CLAIM", "roles"),
		SearchRequiredRole:            env("SEARCH_REQUIRED_ROLE", ""),
		AllowUnboundMultiIssuer:       envBool("ALLOW_UNBOUND_MULTI_ISSUER", false),
		WatchRequiredRole:             env("WATCH_REQUIRED_ROLE", ""),
		ExplainRequiredRole:           env("EXPLAIN_REQUIRED_ROLE", ""),
		WriterRole:                    env("WRITER_ROLE", "authz_writer"),
		RecorderRole:                  env("RECORDER_ROLE", "authz_recorder"),
		DBRoleClaim:                   env("DB_ROLE_CLAIM", ""),
		SubjectTypeClaim:              env("SUBJECT_TYPE_CLAIM", "subject_type"),
		SubjectTypeDefault:            env("SUBJECT_TYPE_DEFAULT", "internal_user"),
		SubjectIDClaim:                env("SUBJECT_ID_CLAIM", "preferred_username"),
		SubjectIDFallback:             env("SUBJECT_ID_FALLBACK_CLAIM", "sub"),
		ActorClaim:                    env("ACTOR_CLAIM", ""),
		ActorSubjectType:              env("ACTOR_SUBJECT_TYPE", "agent"),
		FreshnessPrimaryURL:           env("FRESHNESS_PRIMARY_URL", ""),
		FreshnessPrimaryPoolMax:       envInt("FRESHNESS_PRIMARY_POOL_MAX", 10),
		OpenAPIEnabled:                envBool("OPENAPI_ENABLED", true),
		CORSAllowedOrigins:            envList("CORS_ALLOWED_ORIGINS"),
		SwaggerUIEnabled:              envBool("SWAGGER_UI_ENABLED", false),
		SwaggerUIOIDCIssuer:           strings.TrimRight(env("SWAGGER_UI_OIDC_ISSUER", ""), "/"),
		SwaggerUIOIDCClientID:         env("SWAGGER_UI_OIDC_CLIENT_ID", ""),
		SwaggerUIOIDCScopes:           env("SWAGGER_UI_OIDC_SCOPES", "openid"),
		SwaggerUIOIDCAuthorizationURL: env("SWAGGER_UI_OIDC_AUTHORIZATION_URL", ""),
		SwaggerUIOIDCTokenURL:         env("SWAGGER_UI_OIDC_TOKEN_URL", ""),
		DeploymentEnvironment:         env("DEPLOYMENT_ENVIRONMENT", ""),
		AllowOpenDiagnostics:          envBool("ALLOW_OPEN_DIAGNOSTICS", false),
		AllowMissingAudience:          envBool("ALLOW_MISSING_AUDIENCE", false),
		OPAMaxResponseBytes:           int64(envInt("OPA_MAX_RESPONSE_BYTES", 10<<20)),
		CursorSealKey:                 env("CURSOR_SEAL_KEY", ""),
		MetricsListenAddr:             env("METRICS_LISTEN_ADDR", ""),
		MetricsSampleIntervalSeconds:  envInt("METRICS_SAMPLE_INTERVAL_SECONDS", 30),
		MetricsMaxStores:              envInt("METRICS_MAX_STORES", 100),
		DefaultStore:                  env("DEFAULT_STORE", "demo"),
		StoreHeader:                   env("STORE_HEADER", "X-PGAuthz-Store"),
		RequireStoreBinding:           envBool("REQUIRE_STORE_BINDING", false),
		RequireDBRoleBinding:          envBool("REQUIRE_DB_ROLE_BINDING", false),
		AllowSubjectOverride:          envBool("ALLOW_SUBJECT_OVERRIDE", false),
		ContextualTuples:              env("CONTEXTUAL_TUPLES", ContextualTuplesTrustedPEPs),
		DatabaseURL:                   env("DATABASE_URL", ""),
		DBPoolMax:                     envInt("DB_POOL_MAX", 25),
		DefaultDBRole:                 env("DEFAULT_DB_ROLE", ""),
		DBRoleCacheTTLSeconds:         envInt("DB_ROLE_CACHE_TTL_SECONDS", 60),
		HTTPReadHeaderTimeout:         envDuration("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
		HTTPIdleTimeout:               envDuration("HTTP_IDLE_TIMEOUT", 60*time.Second),
		HTTPMaxBodyBytes:              int64(envInt("HTTP_MAX_BODY_BYTES", 10<<20)),
		OPAURL:                        env("OPA_URL", ""),
		OPAPackage:                    env("OPA_PACKAGE", "authz"),
		OPARequestTimeout:             envDuration("OPA_REQUEST_TIMEOUT", 10*time.Second),
		OPADeepReadinessRequired:      envBool("OPA_DEEP_READINESS_REQUIRED", false),
		OPAEvalMetrics:                envBool("OPA_EVAL_METRICS", true),
		ForwardTokenToOPA:             envBool("FORWARD_TOKEN_TO_OPA", false),
		LogLevel:                      env("LOG_LEVEL", "info"),
		DecisionLog:                   env("DECISION_LOG", "off"),
		DecisionLogDSN:                env("DECISION_LOG_DSN", ""),
		DecisionLogRetentionDays:      envInt("DECISION_LOG_RETENTION_DAYS", 30),
		DecisionLogQueue:              envInt("DECISION_LOG_QUEUE", 10000),
		DecisionLogSample:             envFloat("DECISION_LOG_SAMPLE", 1),
		DecisionLogDetail:             envBool("DECISION_LOG_DETAIL", false),
		DecisionLogRequired:           envBool("DECISION_LOG_REQUIRED", false),
		DecisionLogSearches:           envBool("DECISION_LOG_SEARCHES", false),
	}

	// Freshness keyring: FRESHNESS_TOKEN_KEYS (ordered, comma-separated — first
	// mints, all verify) or the single-key alias FRESHNESS_TOKEN_KEY. Both set
	// is ambiguous (which one mints?) → refuse to start rather than guess.
	keysRaw, keyRaw := os.Getenv("FRESHNESS_TOKEN_KEYS"), os.Getenv("FRESHNESS_TOKEN_KEY")
	if keysRaw != "" && keyRaw != "" {
		return nil, fmt.Errorf("set FRESHNESS_TOKEN_KEYS or FRESHNESS_TOKEN_KEY, not both")
	}
	if keysRaw == "" {
		keysRaw = keyRaw
	}
	seen := map[string]bool{}
	for _, k := range strings.Split(keysRaw, ",") {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if seen[k] {
			return nil, fmt.Errorf("FRESHNESS_TOKEN_KEYS: duplicate key entry")
		}
		seen[k] = true
		c.FreshnessKeys = append(c.FreshnessKeys, k)
	}
	// Distinct secrets deriving the SAME key id (a ~2^-31-per-pair sha256-prefix
	// accident) would silently shadow one key at verification time — make it a
	// deterministic startup error instead.
	// Invalid (not merely absent) environment values are fatal — a typo in a
	// security flag must never silently select the default (review #10).
	if len(envErrs) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n  %s", strings.Join(envErrs, "\n  "))
	}

	if err := authz.NewKeyring(c.FreshnessKeys).Validate(); err != nil {
		return nil, err
	}

	// CURSOR_SEAL_KEY keyring parsing is strict: a set-but-malformed value
	// (empty segments, e.g. a stray comma) must be a startup error — silently
	// skipping entries or falling back to the random per-process key would
	// break cursor continuity invisibly.
	if c.CursorSealKey != "" {
		for _, seg := range strings.Split(c.CursorSealKey, ",") {
			if strings.TrimSpace(seg) == "" {
				return nil, fmt.Errorf("CURSOR_SEAL_KEY contains an empty key segment (stray comma?)")
			}
		}
	}

	// DEPLOYMENT_ENVIRONMENT is forwarded verbatim to policy hooks
	// (input.deployment.environment) as a security-relevant gate value, so
	// bound it to a small identifier set — no spaces/control chars that could
	// confuse a hook's comparison. Empty is allowed (feature unused).
	if c.DeploymentEnvironment != "" && !deploymentEnvRe.MatchString(c.DeploymentEnvironment) {
		return nil, fmt.Errorf("DEPLOYMENT_ENVIRONMENT %q must match %s", c.DeploymentEnvironment, deploymentEnvRe.String())
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
		if err := validatePEPClients(iss); err != nil {
			return nil, fmt.Errorf("issuer %d (%q): %w", i, iss.Issuer, err)
		}
		// Audience is required (F21): an issuer without one accepts every token
		// its IdP mints for any other API. Fail closed at startup unless the
		// operator overrides deliberately.
		if strings.TrimSpace(iss.Audience) == "" {
			if c.IsProduction() {
				// The production profile has no override for this one: an
				// audience-less issuer is an authentication hole, not a
				// diagnostic surface, so there is no trusted-network argument.
				return nil, fmt.Errorf("issuer %d (%q) has no audience — tokens this IdP mints for ANY other API would be accepted here; set JWT_AUDIENCE (legacy form) or \"audience\" in JWT_ISSUERS to this API's identifier (ALLOW_MISSING_AUDIENCE is not honoured with DEPLOYMENT_ENVIRONMENT=%s)", i, iss.Issuer, c.DeploymentEnvironment)
			}
			if !c.AllowMissingAudience {
				return nil, fmt.Errorf("issuer %d (%q) has no audience — tokens this IdP mints for ANY other API would be accepted here; set JWT_AUDIENCE (legacy form) or \"audience\" in JWT_ISSUERS to this API's identifier, or override deliberately with ALLOW_MISSING_AUDIENCE=true", i, iss.Issuer)
			}
			log.Printf("WARNING (ALLOW_MISSING_AUDIENCE): issuer %q has no audience — tokens minted for any other API are accepted", iss.Issuer)
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

	// Resolve the profile value. Default: full (direct pgx read+write). Fronting
	// OPA is orthogonal (OPA_URL), not a profile. The backend requirement
	// (DATABASE_URL) is validated by the command that wires the backend, not
	// here — Load() stays free of deployment-topology assumptions (kept testable
	// in isolation).
	if c.Profile == "" {
		c.Profile = ProfileFull
	}
	if c.SwaggerUIEnabled && !c.OpenAPIEnabled {
		return nil, fmt.Errorf("SWAGGER_UI_ENABLED=true needs OPENAPI_ENABLED=true — the UI renders the served OpenAPI document")
	}
	if (c.SwaggerUIOIDCIssuer == "") != (c.SwaggerUIOIDCClientID == "") {
		return nil, fmt.Errorf("SWAGGER_UI_OIDC_ISSUER and SWAGGER_UI_OIDC_CLIENT_ID go together — the UI needs the issuer to discover endpoints and the client id to log in")
	}
	if (c.SwaggerUIOIDCAuthorizationURL == "") != (c.SwaggerUIOIDCTokenURL == "") {
		return nil, fmt.Errorf("SWAGGER_UI_OIDC_AUTHORIZATION_URL and SWAGGER_UI_OIDC_TOKEN_URL go together")
	}
	switch {
	case c.DecisionLog == "" || c.DecisionLog == "off" || c.DecisionLog == "stdout" || c.DecisionLog == "stderr":
	case strings.HasPrefix(c.DecisionLog, "file:") && len(c.DecisionLog) > len("file:"):
	case c.DecisionLog == "postgres":
		if strings.TrimSpace(c.DecisionLogDSN) == "" {
			return nil, fmt.Errorf("DECISION_LOG=postgres needs DECISION_LOG_DSN (the sink database; never the engine's read-only role)")
		}
		if c.DecisionLogRetentionDays < 0 {
			return nil, fmt.Errorf("DECISION_LOG_RETENTION_DAYS %d: expected 0 (keep) or a number of days", c.DecisionLogRetentionDays)
		}
		if c.DecisionLogQueue <= 0 {
			return nil, fmt.Errorf("DECISION_LOG_QUEUE %d: expected a positive number of lines", c.DecisionLogQueue)
		}
	default:
		return nil, fmt.Errorf("DECISION_LOG %q: expected off | stdout | stderr | file:<path> | postgres", c.DecisionLog)
	}
	if c.DecisionLogSample < 0 || c.DecisionLogSample > 1 {
		return nil, fmt.Errorf("DECISION_LOG_SAMPLE %v: expected a fraction in [0,1]", c.DecisionLogSample)
	}
	if c.DecisionLogRequired && c.DecisionLogSample < 1 {
		return nil, fmt.Errorf("DECISION_LOG_REQUIRED=true means complete evidence: DECISION_LOG_SAMPLE must be 1 (got %v)", c.DecisionLogSample)
	}
	if c.DecisionLog == "" || c.DecisionLog == "off" {
		if c.DecisionLogRequired {
			return nil, fmt.Errorf("DECISION_LOG_REQUIRED=true needs a sink: set DECISION_LOG")
		}
		if c.DecisionLogSearches {
			return nil, fmt.Errorf("DECISION_LOG_SEARCHES=true needs a sink: set DECISION_LOG")
		}
	}
	switch c.Profile {
	case ProfileDecisionOnly, ProfileFull:
		// ok
	default:
		return nil, fmt.Errorf("unknown PGAUTHORIZER_PROFILE %q (decision-only | full)", c.Profile)
	}
	if c.ActorClaim != "" && strings.TrimSpace(c.ActorSubjectType) == "" {
		return nil, fmt.Errorf("ACTOR_CLAIM is set but ACTOR_SUBJECT_TYPE is empty — a delegated actor needs a subject type (e.g. agent)")
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
				// SECURE BY DEFAULT for multi-issuer (review #10): an unbound
				// issuer reaches every store — fail startup instead of warning
				// past a cross-tenant hole. The production profile has no
				// override for this: bindings are configuration, add them.
				if c.IsProduction() {
					return nil, fmt.Errorf("issuer %q has no stores binding while %d issuers are trusted — its tokens could access EVERY store; add stores patterns in JWT_ISSUERS (ALLOW_UNBOUND_MULTI_ISSUER is not honoured with DEPLOYMENT_ENVIRONMENT=%s)", iss.Issuer, len(c.Issuers), c.DeploymentEnvironment)
				}
				if !c.AllowUnboundMultiIssuer {
					return nil, fmt.Errorf("issuer %q has no stores binding while %d issuers are trusted — its tokens could access EVERY store; add stores patterns in JWT_ISSUERS, or override deliberately with ALLOW_UNBOUND_MULTI_ISSUER=true", iss.Issuer, len(c.Issuers))
				}
				log.Printf("WARNING (ALLOW_UNBOUND_MULTI_ISSUER): issuer %q has no stores binding — its tokens can access EVERY store", iss.Issuer)
			}
		}
		if roleDerivation && len(iss.DBRoles) == 0 && len(iss.ClientDBRoles) == 0 {
			if c.RequireDBRoleBinding {
				return nil, fmt.Errorf("REQUIRE_DB_ROLE_BINDING: issuer %q has no db_roles or client_db_roles binding", iss.Issuer)
			}
			if len(c.Issuers) > 1 {
				if c.IsProduction() {
					return nil, fmt.Errorf("issuer %q has no db_roles/client_db_roles binding while %d issuers are trusted and DB-role derivation is active — its tokens could claim ANY reader role; add db_roles patterns in JWT_ISSUERS (ALLOW_UNBOUND_MULTI_ISSUER is not honoured with DEPLOYMENT_ENVIRONMENT=%s)", iss.Issuer, len(c.Issuers), c.DeploymentEnvironment)
				}
				if !c.AllowUnboundMultiIssuer {
					return nil, fmt.Errorf("issuer %q has no db_roles/client_db_roles binding while %d issuers are trusted and DB-role derivation is active — its tokens could claim ANY reader role; add db_roles patterns in JWT_ISSUERS, or override deliberately with ALLOW_UNBOUND_MULTI_ISSUER=true", iss.Issuer, len(c.Issuers))
				}
				log.Printf("WARNING (ALLOW_UNBOUND_MULTI_ISSUER): issuer %q has no db_roles/client_db_roles binding — its tokens can claim ANY reader role", iss.Issuer)
			}
		}
	}

	// Contextual tuples on the public listener: a known mode, and "any" —
	// every authenticated caller may inject what-if tuples — never under the
	// production label (a warning elsewhere).
	switch c.ContextualTuples {
	case ContextualTuplesOff, ContextualTuplesTrustedPEPs:
	case ContextualTuplesAny:
		if c.IsProduction() {
			return nil, fmt.Errorf("CONTEXTUAL_TUPLES=any lets EVERY authenticated caller inject what-if tuples into its own checks (forged decisions, graph probing); use trusted-peps or off (DEPLOYMENT_ENVIRONMENT=%s refuses any)", c.DeploymentEnvironment)
		}
		log.Printf("WARNING: CONTEXTUAL_TUPLES=any — every authenticated caller may inject what-if tuples into its own checks; prefer trusted-peps (the default) or off")
	default:
		return nil, fmt.Errorf("unknown CONTEXTUAL_TUPLES %q (off | trusted-peps | any)", c.ContextualTuples)
	}

	// Subject assertion (ADR 0014): the coarse switch and the per-client map
	// together mean the map is dead configuration — every token may assert.
	// Say so; in production refuse, like the other ALLOW_* overrides.
	if c.AllowSubjectOverride && c.HasPEPClients() {
		if c.IsProduction() {
			return nil, fmt.Errorf("ALLOW_SUBJECT_OVERRIDE=true together with pep_clients in JWT_ISSUERS: the switch lets EVERY token assert any subject and makes the per-client map meaningless; drop one (DEPLOYMENT_ENVIRONMENT=%s refuses the combination)", c.DeploymentEnvironment)
		}
		log.Printf("WARNING: ALLOW_SUBJECT_OVERRIDE=true makes pep_clients in JWT_ISSUERS meaningless — every token may assert any subject; drop the switch to enforce the per-client map")
	}

	// PRODUCTION PROFILE (external review): a production-labelled instance must
	// not expose graph enumeration (search), model structure + traces (explain)
	// or the changefeed (watch) to every authenticated caller. Fail closed at
	// startup — a misconfiguration must not become an open surface — unless the
	// operator overrides deliberately.
	if c.IsProduction() {
		// ALLOW_MISSING_AUDIENCE is forbidden outright under the production
		// label, even when every issuer currently pins an audience: a latent
		// override would silently take effect the day an issuer entry loses
		// its audience. Open diagnostics keep their override (a trusted
		// internal network is a legitimate reason); an unverified audience
		// has none.
		if c.AllowMissingAudience {
			return nil, fmt.Errorf("ALLOW_MISSING_AUDIENCE=true is forbidden with DEPLOYMENT_ENVIRONMENT=%s — give every issuer an audience and unset the override", c.DeploymentEnvironment)
		}
		// Same for the unbound-issuer override: an issuer that can reach every
		// store or claim every reader role is a cross-tenant hole, and the fix
		// (stores / db_roles patterns) is pure configuration.
		if c.AllowUnboundMultiIssuer {
			return nil, fmt.Errorf("ALLOW_UNBOUND_MULTI_ISSUER=true is forbidden with DEPLOYMENT_ENVIRONMENT=%s — bind every issuer (stores, db_roles) and unset the override", c.DeploymentEnvironment)
		}
		if open := c.openDiagnostics(); len(open) > 0 {
			if !c.AllowOpenDiagnostics {
				return nil, fmt.Errorf("DEPLOYMENT_ENVIRONMENT=%s requires role-gated diagnostic surfaces, but: %s — set them (e.g. authz_auditor), or override deliberately with ALLOW_OPEN_DIAGNOSTICS=true", c.DeploymentEnvironment, strings.Join(open, "; "))
			}
			log.Printf("WARNING (ALLOW_OPEN_DIAGNOSTICS): production instance with open diagnostic surfaces: %s", strings.Join(open, "; "))
		}
	}

	return c, nil
}

// IsProduction reports whether DEPLOYMENT_ENVIRONMENT selects the production
// profile ("production" or "prod").
func (c *Config) IsProduction() bool {
	return c.DeploymentEnvironment == "production" || c.DeploymentEnvironment == "prod"
}

// openDiagnostics lists the diagnostic surfaces the production profile
// considers open: search and explain ungated, or watch explicitly opened.
// (An unset WATCH_REQUIRED_ROLE disables watch on the public listener — that
// is closed, not open.)
func (c *Config) openDiagnostics() []string {
	var open []string
	if c.SearchRequiredRole == "" || c.SearchRequiredRole == "*" {
		open = append(open, "SEARCH_REQUIRED_ROLE is unset (reverse search enumerates the access graph)")
	}
	if c.ExplainRequiredRole == "" || c.ExplainRequiredRole == "*" {
		open = append(open, "EXPLAIN_REQUIRED_ROLE is unset (explain reveals model structure and resolution traces)")
	}
	if c.WatchRequiredRole == "*" {
		open = append(open, `WATCH_REQUIRED_ROLE is "*" (the changefeed is open to every caller)`)
	}
	return open
}

// Strict environment parsing (review #10): absence means the documented
// default, a VALID value is used, and an INVALID value is a STARTUP FAILURE —
// never a silent fallback (REQUIRE_STORE_BINDING=treu must not quietly become
// "false"). Helpers collect errors into envErrs; Load() fails when any exist.
var envErrs []string

func envFail(key, v, want string) {
	envErrs = append(envErrs, fmt.Sprintf("%s=%q is invalid (%s)", key, v, want))
}

// The CONTEXTUAL_TUPLES modes.
const (
	ContextualTuplesOff         = "off"
	ContextualTuplesTrustedPEPs = "trusted-peps"
	ContextualTuplesAny         = "any"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			envFail(key, v, "expected an integer")
			return fallback
		}
		return n
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			envFail(key, v, "expected a Go duration like 10s or 1m")
			return fallback
		}
		return d
	}
	return fallback
}

func envFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			envFail(key, v, "expected a number")
			return fallback
		}
		return f
	}
	return fallback
}

// HasPEPClients reports whether any issuer names clients that may assert
// subjects (ADR 0014).
func (c *Config) HasPEPClients() bool {
	for _, iss := range c.Issuers {
		if len(iss.PEPClients) > 0 {
			return true
		}
	}
	return false
}

// regexMeta are the characters that make a store pattern a pattern rather
// than a plain name.
const regexMeta = `.*+?()[]{}|^$\`

// validatePEPClients checks an issuer's pep_clients (ADR 0014): every pattern
// compiles anchored, and none reaches beyond the issuer's stores binding — a
// pattern is accepted when the issuer is unbound, when it is literally one of
// the issuer's stores patterns, or when it is a plain store name that one of
// them matches. Assertion must never widen where a token may ask.
func validatePEPClients(iss Issuer) error {
	for client, patterns := range iss.PEPClients {
		if strings.TrimSpace(client) == "" {
			return fmt.Errorf("pep_clients has an empty client id")
		}
		if len(patterns) == 0 {
			return fmt.Errorf("pep_clients[%q] lists no stores (use [\".*\"] for every store of the binding)", client)
		}
		for _, p := range patterns {
			if _, err := regexp.Compile("^(?:" + p + ")$"); err != nil {
				return fmt.Errorf("pep_clients[%q]: invalid store pattern %q: %w", client, p, err)
			}
			if len(iss.Stores) == 0 {
				continue
			}
			covered := false
			for _, sp := range iss.Stores {
				if sp == p {
					covered = true
					break
				}
				if !strings.ContainsAny(p, regexMeta) && regexp.MustCompile("^(?:"+sp+")$").MatchString(p) {
					covered = true
					break
				}
			}
			if !covered {
				return fmt.Errorf("pep_clients[%q]: store pattern %q is not covered by the issuer's stores binding %v — assertion cannot widen where tokens may ask", client, p, iss.Stores)
			}
		}
	}
	return nil
}

// SwaggerUIOIDC reports whether the embedded Swagger UI logs in via OIDC.
func (c *Config) SwaggerUIOIDC() bool {
	return c.SwaggerUIOIDCIssuer != "" && c.SwaggerUIOIDCClientID != ""
}

// envList reads a comma-separated list, trimmed, empty entries dropped.
func envList(key string) []string {
	var out []string
	for _, v := range strings.Split(os.Getenv(key), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func envBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			envFail(key, v, "expected true or false")
			return fallback
		}
		return b
	}
	return fallback
}

// UsesOPA reports whether an OPA policy sidecar fronts the AuthZEN /access/v1
// surface (OPA_URL set). Orthogonal to the profile.
func (c *Config) UsesOPA() bool {
	return c.OPAURL != ""
}

// Writable reports whether the profile's DB role is expected to hold write
// capability (drives the read-only startup assertion + the native write API).
func (c *Config) Writable() bool {
	return c.Profile == ProfileFull
}

// FreshnessEnabled reports whether freshness tokens (ADR 0009) are configured
// (at least one HMAC key is set). When false, writes mint no token and reads
// reject an at_least_as_fresh request (fail closed).
func (c *Config) FreshnessEnabled() bool {
	return len(c.FreshnessKeys) > 0
}
