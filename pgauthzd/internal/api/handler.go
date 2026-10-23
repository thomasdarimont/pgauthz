package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
	"thomasdarimont.de/authz/pgauthzd/internal/decisionlog"
	"thomasdarimont.de/authz/pgauthzd/internal/metrics"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var (
	errSubjectRequired  = errors.New("subject.type and subject.id are required")
	errSubjectForbidden = errors.New("request subject does not match the authenticated subject (body-subject override is disabled)")
)

const defaultPageSize = 100

// Handler wires all AuthZEN endpoints to a backend.
type Handler struct {
	// issuers is the trusted-issuer set in force — store bindings and PEP
	// clients (ADR 0014) read per request, swapped as one value when the
	// database bindings change (ISSUERS_SOURCE=env+db). Shared with the JWT
	// middleware (WithIssuers); built from cfg.Issuers otherwise.
	issuers *Issuers
	// backend serves the AuthZEN surface (/access/v1): the OPA backend when
	// OPA_URL is set (policy enrichment), else the direct pgx backend.
	backend authz.Backend
	// raw serves the native /pgauthz/v1 READ surface and is ALWAYS a direct pgx
	// backend — never OPA. When not fronting OPA, raw == backend; when fronting
	// OPA it is the separate direct pgx backend, which is what keeps the native
	// raw endpoints policy-free (no re-entry into the OPA policy layer).
	raw authz.Backend
	// rawWrite serves the native /pgauthz/v1 WRITE surface — a WRITER-capable
	// direct pgx backend (set only on a full instance). nil = writes unavailable
	// (decision-only), and the write routes return 501/403.
	rawWrite authz.Backend
	// requireWriterRole gates the native write endpoints behind the WRITER_ROLE
	// claim. Set on the PUBLIC (JWT) router — pgauthzd authorizes writes itself.
	// Left false on the service-token CALLBACK router, which trusts the upstream
	// OPA's asserted X-PGAuthz-Role instead of a JWT role claim.
	requireWriterRole bool
	// gateDiagnostics applies the WATCH_REQUIRED_ROLE / EXPLAIN_REQUIRED_ROLE
	// gates — true only on the PUBLIC listener (the callback listener is a
	// trusted-PEP surface authenticated by service credential; OPA-mediated
	// explain, e.g. the playground, must keep working).
	gateDiagnostics bool
	cfg             *config.Config
	// freshKeys is the freshness-token keyring derived once from
	// cfg.FreshnessKeys: freshKeys[0] mints, every entry verifies (rotation
	// overlap, ADR 0009). Empty = feature disabled.
	freshKeys authz.Keyring
	// decisions is the decision log (ADR 0013); nil = off. listener labels
	// the lines: "public" | "callback".
	decisions *decisionlog.Logger
	listener  string
	version   string
	// modelCache: per-store model provenance for decision-log lines (TTL).
	modelMu    sync.Mutex
	modelCache map[string]modelCacheEntry
}

func NewHandler(backend, raw, rawWrite authz.Backend, cfg *config.Config, opts ...Option) *Handler {
	h := &Handler{backend: backend, raw: raw, rawWrite: rawWrite, cfg: cfg,
		freshKeys: authz.NewKeyring(cfg.FreshnessKeys), listener: "public"}
	for _, o := range opts {
		o(h)
	}
	if h.issuers == nil {
		h.issuers = NewIssuers(IssuerConfigsFrom(cfg.Issuers))
	}
	return h
}

// mayAssertSubject (ADR 0014) says whether this request's caller may name a
// subject other than its token's — on the decision path (a body subject) and
// on the write path (performed_by / recorded_by) alike. Yes when the coarse
// ALLOW_SUBJECT_OVERRIDE is on, else when the token's client (azp) is listed
// in its issuer's pep_clients for this store. Deny by default.
func (h *Handler) mayAssertSubject(r *http.Request, store string) bool {
	if h.cfg.AllowSubjectOverride {
		return true
	}
	clients := h.issuers.Current().pepClients[IssuerFromContext(r.Context())]
	if clients == nil {
		return false
	}
	client := ClientFromContext(r.Context())
	if client == "" {
		return false
	}
	for _, p := range clients[client] {
		if p.MatchString(store) {
			return true
		}
	}
	return false
}

// mayUseContextualTuples applies CONTEXTUAL_TUPLES to a request that carries
// contextual tuples: the callback listener always may (its caller is OPA, a
// trusted sidecar); on the public listener "off" never, "any" every caller,
// and "trusted-peps" (the default) only a caller that may assert a subject
// for the store — the same trust boundary that lets a caller shape the
// question (pep_clients / ALLOW_SUBJECT_OVERRIDE).
func (h *Handler) mayUseContextualTuples(r *http.Request, store string) bool {
	if h.listener == "callback" {
		return true
	}
	switch h.cfg.ContextualTuples {
	case config.ContextualTuplesAny:
		return true
	case config.ContextualTuplesOff:
		return false
	default:
		return h.mayAssertSubject(r, store)
	}
}

// assertionDenied explains a refused assertion: who tried, for which store.
// It IS an errSubjectForbidden (errors.Is), so the 403 mapping applies.
func (h *Handler) assertionDenied(r *http.Request, store string) error {
	client := ClientFromContext(r.Context())
	if client == "" {
		client = "(no azp/client_id claim)"
	}
	return &assertionDeniedError{client: client, store: store}
}

type assertionDeniedError struct{ client, store string }

func (e *assertionDeniedError) Error() string {
	return fmt.Sprintf("request subject does not match the authenticated subject, and client %q may not assert subjects in store %q (ADR 0014: list it in the issuer's pep_clients, or ALLOW_SUBJECT_OVERRIDE)", e.client, e.store)
}

func (e *assertionDeniedError) Is(target error) bool { return target == errSubjectForbidden }

// NewRouter returns the main JWT-authed listener: the AuthZEN /access/v1 surface
// (served by `backend` — the OPA sidecar when OPA_URL is set, else direct pgx).
//
// The native /pgauthz/v1 surface (served by `raw`/`rawWrite`, always direct pgx)
// is exposed on the public listener ONLY when this instance is NOT fronting OPA.
// The native path bypasses OPA policy, so when OPA fronts /access/v1 it stays
// off the public listener and lives only on the internal callback listener OPA
// calls back into — a client can't sidestep policy via the raw API. When native
// IS exposed here, pgauthzd authorizes writes itself, so the write routes are
// gated by the WRITER_ROLE claim (requireWriterRole).
func NewRouter(backend, raw, rawWrite authz.Backend, cfg *config.Config, jwtMW *JWTMiddleware, opts ...Option) http.Handler {
	h := NewHandler(backend, raw, rawWrite, cfg, opts...)
	h.listener = "public"
	h.requireWriterRole = true
	h.gateDiagnostics = true
	return withMiddleware(newPublicMux(h, cfg.UsesOPA()), jwtMW, cfg.HTTPMaxBodyBytes, cfg.CORSAllowedOrigins)
}

// newPublicMux wires the PUBLIC listener's route set. Kept as its own function
// so the OpenAPI route-coverage test (openapi_test.go) introspects exactly the
// mux production uses — not a re-declared copy that could drift.
func newPublicMux(h *Handler, usesOPA bool) *http.ServeMux {
	mux := http.NewServeMux()
	registerAuthZEN(mux, h)
	if !usesOPA {
		registerNativeRead(mux, h)
		registerNativeWrite(mux, h)
	}
	// The admin API on the public listener (ADMIN_API_ENABLED without
	// ADMIN_LISTEN_ADDR): a full instance only; the routes carry the gate.
	if h.cfg != nil && h.cfg.AdminAPIEnabled && h.cfg.AdminListenAddr == "" && h.rawWrite != nil {
		registerAdmin(mux, h)
	}
	// The probes: on the public listener unless PUBLIC_HEALTH_ENABLED=false
	// (then on the management listener only — nothing about the backend is
	// learnable from the client-facing port).
	if h.cfg == nil || !h.cfg.PublicHealthDisabled {
		mux.HandleFunc("GET /healthz", h.Healthz) // deprecated alias of /readyz
		mux.HandleFunc("GET /livez", h.Livez)
		mux.HandleFunc("GET /readyz", h.Readyz)
	}
	// The API contract, served unauthenticated (exempted in the JWT
	// middleware) and INSTANCE-ACCURATE (an OPA-fronted instance's copy omits
	// the native paths its public listener does not register). OPENAPI_ENABLED
	// (default true) turns the endpoints off entirely.
	if h.cfg.OpenAPIEnabled {
		mux.HandleFunc("GET /pgauthz/v1/openapi.json", h.OpenAPIJSON)
		mux.HandleFunc("GET /pgauthz/v1/openapi.yaml", h.OpenAPIYAML)
		// The embedded Swagger UI for that document (SWAGGER_UI_ENABLED,
		// default off): a developer convenience, same-origin, assets
		// vendored into the binary (swaggerui.go).
		if h.cfg.SwaggerUIEnabled {
			mux.HandleFunc("GET /pgauthz/v1/docs", h.SwaggerUI)
			mux.HandleFunc("GET /pgauthz/v1/docs/{asset}", h.SwaggerUIAsset)
		}
	}
	return mux
}

// NewCallbackRouter is the OPA CALLBACK listener: the native surface an OPA
// sidecar calls back into, guarded by a shared SERVICE credential (not the
// end-user JWT) — OPA already authenticated the caller and asserts the subject
// + per-app role. It serves native READS, plus native WRITES when this instance
// is writer-capable (rawWrite != nil), so a read-only instance's callback stays
// structurally read-only. Capability follows the instance's role; reader/writer
// separation is achieved by pointing OPA at different instances. Must not be
// exposed to untrusted callers.
func NewCallbackRouter(h *Handler, serviceToken string) http.Handler {
	h.listener = "callback"
	mux := http.NewServeMux()
	registerNativeRead(mux, h)
	if h.rawWrite != nil {
		registerNativeWrite(mux, h)
	}
	mux.HandleFunc("GET /healthz", h.Healthz) // deprecated alias of /readyz
	mux.HandleFunc("GET /livez", h.Livez)
	mux.HandleFunc("GET /readyz", h.Readyz)
	var handler http.Handler = spanNamed(mux)
	handler = MaxBody(h.cfg.HTTPMaxBodyBytes)(handler)
	handler = ServiceAuthMiddleware(serviceToken)(handler)
	handler = RequestID(handler)
	handler = Logging(handler)
	handler = Recovery(handler)
	return Metrics(mux, handler)
}

func withMiddleware(mux *http.ServeMux, jwtMW *JWTMiddleware, maxBodyBytes int64, corsOrigins []string) http.Handler {
	var handler http.Handler = spanNamed(mux)
	handler = MaxBody(maxBodyBytes)(handler)
	handler = jwtMW.Middleware(handler)
	// CORS sits OUTSIDE the JWT middleware: a browser's preflight carries no
	// Authorization and must be answered before authentication.
	handler = CORS(corsOrigins)(handler)
	handler = RequestID(handler)
	handler = Logging(handler)
	handler = Recovery(handler)
	return Metrics(mux, handler)
}

// MaxBody caps request bodies via http.MaxBytesReader (review #9): an
// oversized body fails the handler's JSON decode with a clear error instead of
// buffering without bound. n <= 0 disables the cap.
func MaxBody(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if n > 0 && r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requireJSON refuses a request whose declared Content-Type is not JSON with
// 415 (AuthZEN 1.0 §10.1: requests MUST carry application/json). Media-type
// parameters (application/json; charset=utf-8) and +json structured suffixes
// are accepted. A request WITHOUT a Content-Type header is let through — its
// body is parsed as JSON regardless — so clients that never set the header
// keep working; only an explicit, different media type is an error.
func requireJSON(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "" {
			mt, _, err := mime.ParseMediaType(ct)
			if err != nil || !isJSONMediaType(mt) {
				writeUnsupportedMediaType(w, ct)
				return
			}
		}
		next(w, r)
	}
}

func isJSONMediaType(mt string) bool {
	return mt == "application/json" || strings.HasSuffix(mt, "+json")
}

// registerAuthZEN wires the spec-compliant AuthZEN surface + tenant discovery.
func registerAuthZEN(mux *http.ServeMux, h *Handler) {
	// Read routes carry the freshness guard (ADR 0009): a no-op unless the caller
	// sends X-PGAuthz-Consistency: at_least_as_fresh + a token.
	// Every AuthZEN request body is JSON (§10.1); a declared other media type
	// is refused with 415 before the body is read.
	eval := requireJSON(h.readGuard(h.Evaluation))
	evals := requireJSON(h.readGuard(h.Evaluations))
	searchSub := requireJSON(h.readGuard(h.SearchSubject))
	searchRes := requireJSON(h.readGuard(h.SearchResource))
	searchAct := requireJSON(h.readGuard(h.SearchAction))

	mux.HandleFunc("POST /access/v1/evaluation", eval)
	mux.HandleFunc("POST /access/v1/evaluations", evals)
	mux.HandleFunc("POST /access/v1/search/subject", searchSub)
	mux.HandleFunc("POST /access/v1/search/resource", searchRes)
	mux.HandleFunc("POST /access/v1/search/action", searchAct)
	mux.HandleFunc("GET /.well-known/authzen-configuration", h.WellKnown)

	// Store-scoped variants (OpenFGA-style): the path segment selects the
	// pgauthz store, so each store presents as its own AuthZEN PDP with its
	// own discovery document. Path beats the store header, which beats
	// DEFAULT_STORE — see store().
	mux.HandleFunc("POST /stores/{store}/access/v1/evaluation", eval)
	mux.HandleFunc("POST /stores/{store}/access/v1/evaluations", evals)
	mux.HandleFunc("POST /stores/{store}/access/v1/search/subject", searchSub)
	mux.HandleFunc("POST /stores/{store}/access/v1/search/resource", searchRes)
	mux.HandleFunc("POST /stores/{store}/access/v1/search/action", searchAct)
	mux.HandleFunc("GET /stores/{store}/.well-known/authzen-configuration", h.WellKnown)
	// AuthZEN 1.0 §9.2 tenant model: the well-known URI is INSERTED between
	// host and the tenant path, so discovery for the PDP identified by
	// .../stores/{store} lives at /.well-known/authzen-configuration/stores/{store}.
	mux.HandleFunc("GET /.well-known/authzen-configuration/stores/{store}", h.WellKnown)
}

// registerNativeRead wires the native raw decision + search + explain/watch
// surface. Policy-free (served by the direct `raw` backend); 501 if raw is not
// a direct backend.
func registerNativeRead(mux *http.ServeMux, h *Handler) {
	// Freshness guard (ADR 0009) on the point-read routes; not on watch (a
	// cursor-based changefeed, not a read-your-writes point query).
	explain := h.readGuard(h.Explain)
	// The effective issuer set (ISSUERS_REQUIRED_ROLE on the public listener).
	mux.HandleFunc("GET /pgauthz/v1/issuers", h.Issuers)
	check := h.readGuard(h.NativeCheck)
	checkBatch := h.readGuard(h.NativeCheckBatch)
	listObjects := h.readGuard(h.NativeListObjects)
	listSubjects := h.readGuard(h.NativeListSubjects)
	listActions := h.readGuard(h.NativeListActions)

	grantOptions := h.readGuard(h.GrantOptions)
	mux.HandleFunc("POST /pgauthz/v1/explain", explain)
	mux.HandleFunc("POST /pgauthz/v1/watch", h.Watch)
	mux.HandleFunc("POST /pgauthz/v1/grant-options", grantOptions)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/explain", explain)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/watch", h.Watch)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/grant-options", grantOptions)

	mux.HandleFunc("POST /pgauthz/v1/check", check)
	mux.HandleFunc("POST /pgauthz/v1/check-batch", checkBatch)
	mux.HandleFunc("POST /pgauthz/v1/list-objects", listObjects)
	mux.HandleFunc("POST /pgauthz/v1/list-subjects", listSubjects)
	mux.HandleFunc("POST /pgauthz/v1/list-actions", listActions)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/check", check)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/check-batch", checkBatch)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/list-objects", listObjects)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/list-subjects", listSubjects)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/list-actions", listActions)
}

// registerNativeWrite wires the native write path (full profile only; 403 on
// decision-only, 501 when raw is not a NativeWriter).
func registerNativeWrite(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("POST /pgauthz/v1/write", h.WriteTuples)
	mux.HandleFunc("POST /pgauthz/v1/delete", h.DeleteTuples)
	mux.HandleFunc("POST /pgauthz/v1/delete-user", h.DeleteUserTuples)
	mux.HandleFunc("POST /pgauthz/v1/write-checked", h.WriteTuplesChecked)
	mux.HandleFunc("POST /pgauthz/v1/grant", h.Grant)
	mux.HandleFunc("POST /pgauthz/v1/revoke", h.Revoke)
	mux.HandleFunc("POST /pgauthz/v1/apply-grants", h.ApplyGrants)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/write", h.WriteTuples)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/delete", h.DeleteTuples)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/delete-user", h.DeleteUserTuples)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/write-checked", h.WriteTuplesChecked)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/grant", h.Grant)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/revoke", h.Revoke)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/apply-grants", h.ApplyGrants)
	// The action log (ADR 0012): a write in every operational sense (writer DB
	// connection, consistency mode, audit actor), gated by RECORDER_ROLE.
	mux.HandleFunc("POST /pgauthz/v1/events", h.RecordEvents)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/events", h.RecordEvents)
	mux.HandleFunc("POST /pgauthz/v1/events/reserve", h.ReserveEvent)
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/events/reserve", h.ReserveEvent)
}

// store resolves the pgauthz store for a request: the /stores/{store} path
// segment wins, then the store header (X-PGAuthz-Store), then DEFAULT_STORE.
// NOTE: store selection is caller-controlled — per-store access control (who
// may query which store) is a policy concern; SEARCH_REQUIRED_ROLE gates the
// search endpoints globally, not per store.
// storeChecked resolves the request's store AND enforces the per-issuer store
// binding (Issuer.Stores): tokens from an issuer with a configured store list
// may only access those stores (multi-tenant isolation). Issuers without a
// list — and the legacy unpinned validator — are unrestricted. Writes a 403
// and returns ok=false on a violation.
func (h *Handler) storeChecked(w http.ResponseWriter, r *http.Request) (string, bool) {
	store := h.store(r)
	allowed, restricted := h.issuers.Current().stores[IssuerFromContext(r.Context())]
	if !restricted {
		return store, true
	}
	for _, p := range allowed {
		if p.MatchString(store) {
			return store, true
		}
	}
	metrics.AuthzDenied.WithLabelValues("store_binding").Inc()
	writeForbidden(w, "issuer is not allowed to access store '"+store+"'")
	return "", false
}

func (h *Handler) store(r *http.Request) string {
	s := r.PathValue("store")
	if s == "" {
		s = r.Header.Get(h.cfg.StoreHeader)
	}
	if s == "" {
		s = h.cfg.DefaultStore
	}
	// The request's span (OpenTelemetry) names the store as a tag, so a
	// trace is queried by store without parsing paths or headers.
	trace.SpanFromContext(r.Context()).SetAttributes(attribute.String("pgauthz.store", s))
	return s
}

// resolveSubjectPair applies the subject-assertion policy to a body-supplied
// subject and the JWT-derived subject. `assert` is mayAssertSubject for the
// request's store (ADR 0014).
//
//   - Self-subject (assert=false, the default): the authenticated JWT
//     subject is authoritative. A body subject is accepted only if it matches
//     the token; a differing one is rejected (errSubjectForbidden) — it would
//     be an impersonation attempt. An AUTHENTICATED token that names no
//     subject (a service credential without sub/preferred_username) is a
//     caller that may not speak for anyone: a body subject is refused too —
//     it would otherwise be the one credential that bypasses the assertion
//     grant. Only when no token was verified at all (a no-auth/system
//     deployment, authenticated=false) is the body the only source.
//   - Assertion allowed (assert=true — ALLOW_SUBJECT_OVERRIDE, or the client
//     is a pep_client for the store): the trusted-PEP/PDP mode — the body
//     subject wins, with the JWT subject as a fallback when the body names NO
//     subject at all. A partial body subject (type without id, or id without
//     type) is a malformed request, not half of one to complete from the
//     token: a type describes its id, so mixing the body's id with the
//     token's type would check a principal nobody named (AuthZEN 1.0 §10.1
//     wants a 400 for a subject without type).
func (h *Handler) resolveSubjectPair(bodyType, bodyID, jwtType, jwtID string, assert, authenticated bool) (subjectType, subjectID string, err error) {
	if assert {
		if bodyType == "" && bodyID == "" {
			bodyType, bodyID = jwtType, jwtID
		}
		if bodyType == "" || bodyID == "" {
			return "", "", errSubjectRequired
		}
		return bodyType, bodyID, nil
	}

	// Self-subject: the JWT subject is authoritative when present.
	if jwtType != "" && jwtID != "" {
		if (bodyType != "" && bodyType != jwtType) || (bodyID != "" && bodyID != jwtID) {
			return "", "", errSubjectForbidden
		}
		return jwtType, jwtID, nil
	}

	// A verified token without a subject may not name one.
	if authenticated {
		if bodyType != "" || bodyID != "" {
			return "", "", errSubjectForbidden
		}
		return "", "", errSubjectRequired
	}

	// No token at all: the body is the only available source.
	if bodyType == "" || bodyID == "" {
		return "", "", errSubjectRequired
	}
	return bodyType, bodyID, nil
}

// authenticated reports whether the request carries a verified token (the JWT
// middleware records its issuer).
func authenticated(r *http.Request) bool { return IssuerFromContext(r.Context()) != "" }

// resolveSubject resolves the effective subject for single-subject endpoints,
// applying the assertion policy for the request's store against the
// JWT-derived subject.
func (h *Handler) resolveSubject(r *http.Request, body Subject) (subjectType, subjectID string, err error) {
	jwtType, jwtID := SubjectFromContext(r.Context())
	store := h.store(r)
	st, sid, err := h.resolveSubjectPair(body.Type, body.ID, jwtType, jwtID, h.mayAssertSubject(r, store), authenticated(r))
	if errors.Is(err, errSubjectForbidden) {
		return "", "", h.assertionDenied(r, store)
	}
	return st, sid, err
}

// requireSearchRole gates the reverse-search endpoints: if SearchRequiredRole is
// configured, the caller must hold it (these queries enumerate the access graph).
// Returns false and writes 403 when the caller lacks it; true when allowed or when
// no role is required.
func (h *Handler) requireSearchRole(w http.ResponseWriter, r *http.Request) bool {
	if h.cfg.SearchRequiredRole == "" {
		return true
	}
	for _, role := range RolesFromContext(r.Context()) {
		if role == h.cfg.SearchRequiredRole {
			return true
		}
	}
	metrics.AuthzDenied.WithLabelValues("search_role").Inc()
	writeForbidden(w, "search requires the '"+h.cfg.SearchRequiredRole+"' role")
	return false
}

// requireWatchRole gates the native changefeed on the public listener —
// DENY BY DEFAULT (review #10): the feed exposes authorization topology, and
// the connection role's authz_auditor grant exists to serve it, so HTTP must
// decide who may ask. Unset = 403; "*" = explicitly open; else JWT role.
func (h *Handler) requireWatchRole(w http.ResponseWriter, r *http.Request) bool {
	if !h.gateDiagnostics {
		return true // trusted callback listener
	}
	required := h.cfg.WatchRequiredRole
	if required == "*" {
		return true
	}
	if required == "" {
		metrics.AuthzDenied.WithLabelValues("watch_role").Inc()
		writeForbidden(w, "the watch changefeed is disabled on this listener (set WATCH_REQUIRED_ROLE to enable it for a role, or \"*\" to open it)")
		return false
	}
	for _, role := range RolesFromContext(r.Context()) {
		if role == required {
			return true
		}
	}
	metrics.AuthzDenied.WithLabelValues("watch_role").Inc()
	writeForbidden(w, "watch requires the '"+required+"' role")
	return false
}

// requireExplainRole gates native explain on the public listener like search:
// empty = open (back-compat), else the caller must hold the role.
func (h *Handler) requireExplainRole(w http.ResponseWriter, r *http.Request) bool {
	if !h.gateDiagnostics || h.cfg.ExplainRequiredRole == "" {
		return true
	}
	for _, role := range RolesFromContext(r.Context()) {
		if role == h.cfg.ExplainRequiredRole {
			return true
		}
	}
	metrics.AuthzDenied.WithLabelValues("explain_role").Inc()
	writeForbidden(w, "explain requires the '"+h.cfg.ExplainRequiredRole+"' role")
	return false
}

// requireWriter gates the native write endpoints on the PUBLIC listener: the
// caller must hold the configured WRITER_ROLE. pgauthzd is the write front door
// and authorizes writes itself (no OPA needed). Returns false and writes 403
// when the caller lacks the role. On the service-token CALLBACK listener the
// gate is disabled (requireWriterRole=false) — that path trusts the upstream
// OPA's asserted X-PGAuthz-Role, which pgbackend validates against the DB role.
func (h *Handler) requireWriter(w http.ResponseWriter, r *http.Request) bool {
	if !h.requireWriterRole || h.cfg.WriterRole == "" {
		return true
	}
	for _, role := range RolesFromContext(r.Context()) {
		if role == h.cfg.WriterRole {
			return true
		}
	}
	metrics.AuthzDenied.WithLabelValues("writer_role").Inc()
	writeForbidden(w, "writes require the '"+h.cfg.WriterRole+"' role")
	return false
}

// requireRecorder gates the action-log endpoint (POST /pgauthz/v1/events,
// ADR 0012) on the PUBLIC listener the way requireWriter gates tuple writes:
// the caller must hold RECORDER_ROLE — or WRITER_ROLE, since a writer can
// record. Skipped on the service-token callback listener, exactly like the
// writer gate (the DB-role check in pgbackend still applies there).
func (h *Handler) requireRecorder(w http.ResponseWriter, r *http.Request) bool {
	if !h.requireWriterRole || h.cfg.RecorderRole == "" {
		return true
	}
	for _, role := range RolesFromContext(r.Context()) {
		if role == h.cfg.RecorderRole || (h.cfg.WriterRole != "" && role == h.cfg.WriterRole) {
			return true
		}
	}
	metrics.AuthzDenied.WithLabelValues("recorder_role").Inc()
	writeForbidden(w, "recording events requires the '"+h.cfg.RecorderRole+"' role")
	return false
}

// writeSubjectError maps a subject-resolution error to the right HTTP status:
// 403 for a rejected override attempt, 400 for a missing subject.
func writeSubjectError(w http.ResponseWriter, err error) {
	if errors.Is(err, errSubjectForbidden) {
		metrics.AuthzDenied.WithLabelValues("subject_override").Inc()
		writeForbidden(w, err.Error())
		return
	}
	writeBadRequest(w, err.Error())
}

// Evaluation handles POST /access/v1/evaluation
func (h *Handler) Evaluation(w http.ResponseWriter, r *http.Request) {
	if !h.requireDecisionLog(w) {
		return
	}
	var req EvalRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	h.evaluateSingle(w, r, req)
}

// requestContext is the context the engine's conditions see for a request:
// the caller's `context` plus, for every entity that carries AuthZEN
// `properties`, a block under the entity's own key in the request's shape —
//
//	{"subject":  {"type": …, "id": …, "properties": {…}},
//	 "resource": {"type": …, "id": …, "properties": {…}},
//	 "action":   {"name": …, "properties": {…}}}
//
// — so a SQL or CEL condition reads `$1 #>> '{action,properties,soft}'` exactly
// as it reads the wire request (MODEL_DESIGN §8). An entity WITHOUT properties
// adds nothing, which keeps today's context byte-identical for property-less
// requests. A caller key named like an entity (`context.action`) is replaced by
// the block; the documented collision rule. nil in, nothing to add → nil out.
func requestContext(callerContext map[string]any, subject Subject, resource Resource, action Action) map[string]any {
	var out map[string]any
	add := func(key string, block map[string]any) {
		if out == nil {
			out = make(map[string]any, len(callerContext)+3)
			for k, v := range callerContext {
				out[k] = v
			}
		}
		out[key] = block
	}
	if len(subject.Properties) > 0 {
		add("subject", map[string]any{"type": subject.Type, "id": subject.ID, "properties": subject.Properties})
	}
	if len(resource.Properties) > 0 {
		add("resource", map[string]any{"type": resource.Type, "id": resource.ID, "properties": resource.Properties})
	}
	if len(action.Properties) > 0 {
		add("action", map[string]any{"name": action.Name, "properties": action.Properties})
	}
	if out == nil {
		return callerContext
	}
	return out
}

// mergeContext layers an evaluation's own `context` over the batch's shared
// one (AuthZEN 1.0 §7.1: top-level context applies unless overridden per
// evaluation), top-level key by key; nil when both are nil.
func mergeContext(shared, item map[string]any) map[string]any {
	if len(item) == 0 {
		return shared
	}
	if len(shared) == 0 {
		return item
	}
	out := make(map[string]any, len(shared)+len(item))
	for k, v := range shared {
		out[k] = v
	}
	for k, v := range item {
		out[k] = v
	}
	return out
}

// evaluateSingle answers one access evaluation in the single-decision form
// ({"decision": …}). Shared by POST /access/v1/evaluation and by the batch
// endpoint for a request without an evaluations array, which AuthZEN 1.0 §7.1
// defines to behave exactly like the single Access Evaluation API.
func (h *Handler) evaluateSingle(w http.ResponseWriter, r *http.Request, req EvalRequestBody) {
	subjectType, subjectID, err := h.resolveSubject(r, req.Subject)
	if err != nil {
		writeSubjectError(w, err)
		return
	}
	if req.Action.Name == "" {
		writeBadRequest(w, "action.name is required")
		return
	}
	if req.Resource.Type == "" || req.Resource.ID == "" {
		writeBadRequest(w, "resource.type and resource.id are required")
		return
	}

	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	subject := req.Subject
	subject.Type, subject.ID = subjectType, subjectID
	evalReq := authz.EvalRequest{
		Store:       store,
		SubjectType: subjectType,
		SubjectID:   subjectID,
		Action:      req.Action.Name,
		ObjectType:  req.Resource.Type,
		ObjectID:    req.Resource.ID,
		Context:     requestContext(req.Context, subject, req.Resource, req.Action),
	}

	start := time.Now()
	entry := h.decisionEntry(r, "evaluation", evalReq, h.viaLabel())

	// Opt-in rich result (X-PGAuthz-Detail): backends that support it return
	// state/missing_context/model for the AuthZEN response context field.
	// DECISION_LOG_DETAIL runs the same evaluation for the LOG only — the
	// response then stays the plain decision.
	wantDetail := DetailFromContext(r.Context())
	if dc, ok := h.backend.(authz.DetailedChecker); ok && (wantDetail || h.wantDetailForLog()) {
		decision, detail, err := dc.CheckAccessDetailed(r.Context(), evalReq)
		recordDecisionDetail(store, metrics.APIAuthZEN, detail, err)
		h.logDecision(r.Context(), entry, start, decision, detail, err)
		if err != nil {
			writeDecisionError(w, err)
			return
		}
		if wantDetail {
			// The envelope says who decided: "engine" or "opa" — with OPA, the
			// detail also carries hooks_loaded / hook_denials from the policy.
			if detail == nil {
				detail = map[string]any{}
			}
			detail["via"] = h.viaLabel()
			writeJSON(w, http.StatusOK, EvalResponseBody{Decision: decision, Context: detail})
		} else {
			writeJSON(w, http.StatusOK, EvalResponseBody{Decision: decision})
		}
		return
	}

	decision, err := h.backend.CheckAccess(r.Context(), evalReq)
	recordDecision(store, metrics.APIAuthZEN, decision, err)
	h.logDecision(r.Context(), entry, start, decision, nil, err)
	if err != nil {
		writeDecisionError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, EvalResponseBody{Decision: decision})
}

// Evaluations handles POST /access/v1/evaluations
func (h *Handler) Evaluations(w http.ResponseWriter, r *http.Request) {
	if !h.requireDecisionLog(w) {
		return
	}
	var req EvalsBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	// §7.1: a request without an evaluations array (absent or empty) IS a
	// single Access Evaluation request — answered in the single-decision
	// form, never with an evaluations array.
	if len(req.Evaluations) == 0 {
		single := EvalRequestBody{Context: req.Context}
		if req.Subject != nil {
			single.Subject = *req.Subject
		}
		if req.Action != nil {
			single.Action = *req.Action
		}
		if req.Resource != nil {
			single.Resource = *req.Resource
		}
		h.evaluateSingle(w, r, single)
		return
	}

	semantic := req.semantic()
	switch semantic {
	case "execute_all", "deny_on_first_deny", "permit_on_first_permit":
	default:
		writeBadRequest(w, "invalid evaluations_semantic: "+semantic)
		return
	}

	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	jwtType, jwtID := SubjectFromContext(r.Context())
	assert := h.mayAssertSubject(r, store)

	// Build the per-evaluation requests, merging the shared subject/action/
	// resource defaults. An evaluation that cannot be resolved after merging
	// (no subject, action or resource) is NOT a request error: §7.1.1 and
	// certification profile 3.4.1 make it a {"decision": false} entry in the
	// response array, with the batch still answered 200 — only a rejected
	// subject override stays a 403 for the whole request (it is the caller's
	// authorization problem, not a malformed item). Under deny_on_first_deny
	// an unresolvable item is the first deny: nothing after it is evaluated.
	n := len(req.Evaluations)
	evals := make([]authz.EvalRequest, 0, n)
	unresolved := make([]bool, n)
	for i, e := range req.Evaluations {
		// Effective body subject: per-evaluation, falling back to the
		// batch-level subject. The override policy (vs the JWT subject) is
		// then applied centrally by resolveSubjectPair.
		bodyType := e.Subject.Type
		if bodyType == "" && req.Subject != nil {
			bodyType = req.Subject.Type
		}
		bodyID := e.Subject.ID
		if bodyID == "" && req.Subject != nil {
			bodyID = req.Subject.ID
		}

		subType, subID, serr := h.resolveSubjectPair(bodyType, bodyID, jwtType, jwtID, assert, authenticated(r))
		if serr != nil && errors.Is(serr, errSubjectForbidden) {
			writeForbidden(w, fmt.Sprintf("evaluation[%d]: %s", i, h.assertionDenied(r, store).Error()))
			return
		}
		subProps := e.Subject.Properties
		if subProps == nil && req.Subject != nil {
			subProps = req.Subject.Properties
		}

		action := e.Action.Name
		if action == "" && req.Action != nil {
			action = req.Action.Name
		}
		actProps := e.Action.Properties
		if actProps == nil && req.Action != nil {
			actProps = req.Action.Properties
		}

		resType := e.Resource.Type
		if resType == "" && req.Resource != nil {
			resType = req.Resource.Type
		}
		resID := e.Resource.ID
		if resID == "" && req.Resource != nil {
			resID = req.Resource.ID
		}
		resProps := e.Resource.Properties
		if resProps == nil && req.Resource != nil {
			resProps = req.Resource.Properties
		}

		if serr != nil || action == "" || resType == "" || resID == "" {
			unresolved[i] = true
			if semantic == "deny_on_first_deny" {
				break
			}
			continue
		}

		// The item's context: the shared one overridden per key by its own
		// (§7.1), then the entity properties as condition input.
		itemCtx := requestContext(mergeContext(req.Context, e.Context),
			Subject{Type: subType, ID: subID, Properties: subProps},
			Resource{Type: resType, ID: resID, Properties: resProps},
			Action{Name: action, Properties: actProps})

		evals = append(evals, authz.EvalRequest{
			Store:       store,
			SubjectType: subType,
			SubjectID:   subID,
			Action:      action,
			ObjectType:  resType,
			ObjectID:    resID,
			Context:     itemCtx,
		})
	}

	var (
		results []authz.EvalResult
		err     error
	)
	start := time.Now()
	if len(evals) > 0 {
		results, err = h.backend.CheckAccessBatch(r.Context(), store, evals, req.Context, semantic)
		h.logBatch(r, "evaluations", h.viaLabel(), evals, req.Context, results, start, err)
	}
	if err != nil {
		// A policy-hook veto (ADR 0011) rejects the whole batch: 403, never a
		// fake all-false result. The structured `denials` disclose hook
		// identities/reasons, so they are returned ONLY when the caller is
		// authorized for detail (X-PGAuthz-Detail) — same rule as allow_detailed;
		// otherwise just the error code.
		var hookErr *authz.PolicyHookDeniedError
		if errors.As(err, &hookErr) {
			body := map[string]any{"status": http.StatusForbidden, "error": "denied_by_policy_hook"}
			if DetailFromContext(r.Context()) {
				body["denials"] = hookErr.Denials
				body["denial_count"] = hookErr.Count // after per-hook caps
				if hookErr.Truncated {
					body["denials_truncated"] = true
					body["denials_dropped"] = hookErr.Dropped
				}
			}
			writeJSON(w, http.StatusForbidden, body)
			return
		}
		writeDecisionError(w, err)
		return
	}

	// Merge the decisions back in request order (unresolved items are false),
	// then apply the short-circuit on the wire (§7.1.2.1): the response array
	// ends with the decision that stopped processing — the engine evaluates
	// nothing past it, and the caller must not mistake its placeholders for
	// decisions.
	resp := EvalsBatchResponse{Evaluations: make([]EvalResponseBody, 0, n)}
	next := 0
	for i := 0; i < n; i++ {
		decision := false
		if !unresolved[i] {
			if next >= len(results) {
				break // past the point the batch was cut short
			}
			decision = results[next].Decision
			next++
		}
		resp.Evaluations = append(resp.Evaluations, EvalResponseBody{Decision: decision})
		if (semantic == "deny_on_first_deny" && !decision) || (semantic == "permit_on_first_permit" && decision) {
			break
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// SearchSubject handles POST /access/v1/search/subject
func (h *Handler) SearchSubject(w http.ResponseWriter, r *http.Request) {
	if !h.requireSearchRole(w, r) || !h.requireSearchLog(w) {
		return
	}
	var req SearchSubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	if req.Subject.Type == "" {
		writeBadRequest(w, "subject.type is required for subject search")
		return
	}
	if req.Action.Name == "" {
		writeBadRequest(w, "action.name is required")
		return
	}
	if req.Resource.Type == "" || req.Resource.ID == "" {
		writeBadRequest(w, "resource.type and resource.id are required")
		return
	}

	freshTok, ok := h.pageFreshness(w, r, req.Page)
	if !ok {
		return
	}
	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	// Sealed cursors are bound to the query context INCLUDING the verified
	// actor — the AAD here must mirror the minting side (opabackend.ListSubjects).
	// Entity properties become condition input (requestContext); the sealed
	// cursor's AAD hashes the SAME context the backend evaluates with.
	reqCtx := requestContext(req.Context, req.Subject, req.Resource, req.Action)
	_, actorID := SubjectFromContext(r.Context())
	page := decodePage(req.Page, SealedCursorAAD("subjects", store, actorID,
		req.Subject.Type, "", req.Action.Name, req.Resource.Type, req.Resource.ID,
		CanonicalContextHash(reqCtx)))
	if page != nil && page.After == invalidCursorSentinel {
		writeBadRequest(w, "invalid page token: sealed cursor failed verification (wrong query context, or replicas without a shared CURSOR_SEAL_KEY)")
		return
	}
	start := time.Now()
	subjects, pageResp, err := h.backend.ListSubjects(r.Context(), store,
		req.Subject.Type, req.Action.Name, req.Resource.Type, req.Resource.ID,
		reqCtx, page)
	recordSearch(store, "subjects", len(subjects), err)
	h.logSearch(r, "search/subject", h.viaLabel(), store, decisionlog.Ref{Type: req.Subject.Type}, req.Action.Name,
		decisionlog.Ref{Type: req.Resource.Type, ID: req.Resource.ID}, reqCtx, len(subjects), start, err)
	if err != nil {
		writeSearchError(w, err)
		return
	}

	resp := SearchSubjectResponse{
		Results: make([]Subject, len(subjects)),
	}
	for i, id := range subjects {
		resp.Results[i] = Subject{Type: req.Subject.Type, ID: id}
	}
	if pageResp != nil && pageResp.HasMore {
		resp.Page = &PageResult{NextToken: bindCursor(pageResp.NextToken, freshTok)}
	}

	writeJSON(w, http.StatusOK, resp)
}

// SearchResource handles POST /access/v1/search/resource
func (h *Handler) SearchResource(w http.ResponseWriter, r *http.Request) {
	if !h.requireSearchRole(w, r) || !h.requireSearchLog(w) {
		return
	}
	var req SearchResourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	subjectType, subjectID, err := h.resolveSubject(r, req.Subject)
	if err != nil {
		writeSubjectError(w, err)
		return
	}
	if req.Action.Name == "" {
		writeBadRequest(w, "action.name is required")
		return
	}
	if req.Resource.Type == "" {
		writeBadRequest(w, "resource.type is required")
		return
	}

	freshTok, ok := h.pageFreshness(w, r, req.Page)
	if !ok {
		return
	}
	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	// AAD mirrors the minting side (opabackend.ListResources), actor included,
	// over the context the backend evaluates with (entity properties included).
	subject := req.Subject
	subject.Type, subject.ID = subjectType, subjectID
	reqCtx := requestContext(req.Context, subject, req.Resource, req.Action)
	_, actorID := SubjectFromContext(r.Context())
	page := decodePage(req.Page, SealedCursorAAD("objects", store, actorID,
		subjectType, subjectID, req.Action.Name, req.Resource.Type, "",
		CanonicalContextHash(reqCtx)))
	if page != nil && page.After == invalidCursorSentinel {
		writeBadRequest(w, "invalid page token: sealed cursor failed verification (wrong query context, or replicas without a shared CURSOR_SEAL_KEY)")
		return
	}
	start := time.Now()
	resources, pageResp, err := h.backend.ListResources(r.Context(), store,
		subjectType, subjectID, req.Action.Name, req.Resource.Type,
		reqCtx, page)
	recordSearch(store, "objects", len(resources), err)
	h.logSearch(r, "search/resource", h.viaLabel(), store, decisionlog.Ref{Type: subjectType, ID: subjectID}, req.Action.Name,
		decisionlog.Ref{Type: req.Resource.Type}, reqCtx, len(resources), start, err)
	if err != nil {
		writeSearchError(w, err)
		return
	}

	resp := SearchResourceResponse{
		Results: make([]Resource, len(resources)),
	}
	for i, id := range resources {
		resp.Results[i] = Resource{Type: req.Resource.Type, ID: id}
	}
	if pageResp != nil && pageResp.HasMore {
		resp.Page = &PageResult{NextToken: bindCursor(pageResp.NextToken, freshTok)}
	}

	writeJSON(w, http.StatusOK, resp)
}

// SearchAction handles POST /access/v1/search/action
func (h *Handler) SearchAction(w http.ResponseWriter, r *http.Request) {
	if !h.requireSearchRole(w, r) || !h.requireSearchLog(w) {
		return
	}
	var req SearchActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	subjectType, subjectID, err := h.resolveSubject(r, req.Subject)
	if err != nil {
		writeSubjectError(w, err)
		return
	}
	if req.Resource.Type == "" || req.Resource.ID == "" {
		writeBadRequest(w, "resource.type and resource.id are required")
		return
	}

	store, ok := h.storeChecked(w, r)
	if !ok {
		return
	}
	subject := req.Subject
	subject.Type, subject.ID = subjectType, subjectID
	reqCtx := requestContext(req.Context, subject, req.Resource, Action{})
	start := time.Now()
	actions, err := h.backend.ListActions(r.Context(), store,
		subjectType, subjectID, req.Resource.Type, req.Resource.ID,
		reqCtx)
	h.logSearch(r, "search/action", h.viaLabel(), store, decisionlog.Ref{Type: subjectType, ID: subjectID}, "",
		decisionlog.Ref{Type: req.Resource.Type, ID: req.Resource.ID}, reqCtx, len(actions), start, err)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	resp := SearchActionResponse{
		Results: make([]Action, len(actions)),
	}
	for i, a := range actions {
		resp.Results[i] = Action{Name: a}
	}

	writeJSON(w, http.StatusOK, resp)
}

// WellKnown handles GET /.well-known/authzen-configuration
func (h *Handler) WellKnown(w http.ResponseWriter, r *http.Request) {
	base := h.publicBaseURL(r)

	// Store-scoped (tenant) discovery: the PDP identifier and every endpoint
	// carry the /stores/{store} path, so each store presents as its own
	// AuthZEN PDP (AuthZEN 1.0 §9.2 tenant model). The path-insertion
	// discovery URL is /.well-known/authzen-configuration/stores/{store}
	// (see the route); the store is the same PathValue either way.
	if s := r.PathValue("store"); s != "" {
		base += "/stores/" + s
	}

	writeJSON(w, http.StatusOK, WellKnownResponse{
		PolicyDecisionPoint:    base,
		AccessEvaluationEndpt:  base + "/access/v1/evaluation",
		AccessEvaluationsEndpt: base + "/access/v1/evaluations",
		SearchSubjectEndpoint:  base + "/access/v1/search/subject",
		SearchResourceEndpoint: base + "/access/v1/search/resource",
		SearchActionEndpoint:   base + "/access/v1/search/action",
		Capabilities:           []string{"evaluation", "evaluations", "subject-search", "resource-search", "action-search"},
	})
}

// publicBaseURL is the scheme and host the PDP is reachable under, for the
// discovery document (AuthZEN 1.0 §9.2.3: the advertised policy_decision_point
// must be identical to the URL the caller fetched the metadata from):
// BASE_URL when set; else, with TRUST_FORWARDED_HEADERS, what a TLS-terminating
// proxy reports in X-Forwarded-Proto / X-Forwarded-Host; else the request's own
// scheme and host.
func (h *Handler) publicBaseURL(r *http.Request) string {
	if h.cfg.BaseURL != "" {
		return strings.TrimRight(h.cfg.BaseURL, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if h.cfg.TrustForwardedHeaders {
		// A proxy chain may append values; the first is the client-facing one.
		if p := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); p == "http" || p == "https" {
			scheme = p
		}
		if fh := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); fh != "" {
			host = fh
		}
	}
	return scheme + "://" + host
}

// Healthz handles GET /healthz
// Livez — GET /livez: process liveness ONLY, no dependency checks (review #7).
// A PostgreSQL/OPA outage must NOT make Kubernetes restart healthy pgauthzd
// processes in a loop — dependency health is readiness's job (/readyz), which
// takes the instance out of rotation without killing it.
func (h *Handler) Livez(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyzProbeTimeout bounds the readiness backend ping server-side: a
// black-holed dependency must fail the probe promptly, not hang it until the
// kubelet's own timeout (review #9).
const readyzProbeTimeout = 5 * time.Second

// Readyz — GET /readyz: readiness — the backend (PostgreSQL, or OPA on an
// OPA-fronted instance) must be reachable and answering.
func (h *Handler) Readyz(w http.ResponseWriter, r *http.Request) {
	// The callback listener's handler has a nil AuthZEN backend (it only serves
	// the native surface), so fall back to whichever backend is present.
	b := h.backend
	if b == nil {
		b = h.raw
	}
	if b == nil {
		b = h.rawWrite
	}
	// DECISION_LOG_REQUIRED: a failed evidence write makes the instance
	// not ready until a write succeeds again (decisions are refused meanwhile).
	if h.cfg != nil && h.cfg.DecisionLogRequired && (h.decisions == nil || (!h.decisions.Healthy() && !h.decisions.Probe())) {
		slog.Warn("readiness check failed", "error", "decision log unavailable (DECISION_LOG_REQUIRED)")
		writeError(w, http.StatusServiceUnavailable, "unhealthy")
		return
	}
	if b != nil {
		ctx, cancel := context.WithTimeout(r.Context(), readyzProbeTimeout)
		defer cancel()
		if err := b.Healthz(ctx); err != nil {
			// The probe endpoints are UNAUTHENTICATED — backend error text can
			// carry hostnames/DSN fragments, so the caller gets a generic body
			// (review #8) and the cause goes to the server log only.
			slog.Warn("readiness check failed", "error", err)
			writeError(w, http.StatusServiceUnavailable, "unhealthy")
			return
		}
	}
	out := map[string]any{"status": "ok"}
	if h.issuers != nil && h.cfg != nil && h.cfg.IssuersSource == "env+db" {
		// the applied revision of the database issuer bindings (fleet view)
		out["issuers_revision"] = h.issuers.Revision()
	}
	writeJSON(w, http.StatusOK, out)
}

// Healthz — GET /healthz: DEPRECATED alias of /readyz, kept for existing
// deployments/probes. Use /livez for livenessProbe and /readyz for
// readinessProbe.
func (h *Handler) Healthz(w http.ResponseWriter, r *http.Request) {
	h.Readyz(w, r)
}

// --- Pagination helpers ---

// pageState is the decoded form of the opaque next_token. A is the keyset
// cursor (last id of the previous page); O is the legacy offset, still decoded
// so tokens minted before the keyset switch keep working.
type pageState struct {
	A string `json:"a,omitempty"`
	O int    `json:"o,omitempty"`
	// S is a SEALED keyset cursor (filtered enumeration): AES-GCM over the
	// (padded) raw id, since that id may be one the hooks removed from the
	// results. V is the envelope's cursor-format version (1) — the same
	// version is bound into the AAD; the envelope copy enables a future
	// multi-format migration window.
	S string `json:"s,omitempty"`
	V int    `json:"v,omitempty"`
}

// jsonMarshal indirection so cursorseal.go stays import-light.
var jsonMarshal = json.Marshal

// invalidCursorSentinel flags a sealed cursor that failed to unseal (wrong
// replica key, tampering); the search handlers turn it into a 400. Contains a
// NUL so it can never collide with a real id.
const invalidCursorSentinel = "\x00invalid-sealed-cursor"

func decodePage(p *PageToken, aad string) *authz.PageRequest {
	if p == nil {
		return nil
	}
	size := p.size()
	if size <= 0 {
		size = defaultPageSize
	}
	var state pageState
	if p.Token != "" {
		data, err := base64.RawURLEncoding.DecodeString(p.Token)
		if err == nil {
			_ = json.Unmarshal(data, &state)
		}
	}
	if state.S != "" {
		if state.V != 1 {
			// unknown envelope format — fail closed, never guess
			return &authz.PageRequest{Limit: size, After: invalidCursorSentinel}
		}
		// Sealed (filtered-enumeration) cursor: unseal or fail — never fall
		// back to treating sealed bytes as a plain id.
		after, err := unsealCursorValue(state.S, aad)
		if err != nil {
			return &authz.PageRequest{Limit: size, After: invalidCursorSentinel}
		}
		return &authz.PageRequest{Limit: size, After: after}
	}
	return &authz.PageRequest{Limit: size, Offset: state.O, After: state.A}
}

// EncodePage mints a legacy offset cursor. Retained for back-compat; new pages
// use EncodePageAfter (keyset).
func EncodePage(offset int) string {
	data, _ := json.Marshal(pageState{O: offset})
	return base64.RawURLEncoding.EncodeToString(data)
}

// EncodePageAfter mints a keyset cursor carrying the last id of the page.
func EncodePageAfter(after string) string {
	data, _ := json.Marshal(pageState{A: after})
	return base64.RawURLEncoding.EncodeToString(data)
}

// --- JSON helpers ---

// writeRawJSON writes pre-serialized JSON (from the engine) verbatim.
func writeRawJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// SpanName names a request's span (OpenTelemetry) after the route PATTERN
// the mux matched — "POST /stores/{store}/pgauthz/v1/check" — and, before
// the match or for an unmatched route, the bare method. otelhttp evaluates
// it at the start and again after the handler, when r.Pattern is set, so
// names stay bounded (one per route) and a path's identifiers never become
// a span name (review #19).
func SpanName(_ string, r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	return r.Method
}

// spanNamed sits directly around the mux: the ServeMux sets r.Pattern on the
// request it is handed, and every middleware in between hands it a fresh
// copy (WithContext), so otelhttp's own post-handler renaming — which looks
// at ITS copy — never sees the pattern in production. This wrapper does,
// and names the request's span after it.
func spanNamed(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
		if r.Pattern != "" {
			trace.SpanFromContext(r.Context()).SetName(SpanName("", r))
		}
	})
}
