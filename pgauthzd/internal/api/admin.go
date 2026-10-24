package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"crypto/x509"
	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
	"thomasdarimont.de/authz/pgauthzd/pkg/issuers"
)

// The admin API (scratch/notes/issuer-management.md, "configuration as
// code"): the privileged management surface a Terraform provider, the CLI
// and the console use. Its own path component, /pgauthz/v1/admin/…, so a
// gateway allows or denies it by prefix; its own listener when
// ADMIN_LISTEN_ADDR is set; off unless ADMIN_API_ENABLED=true; only on a
// full instance whose DB role holds authz_admin. Every call passes the
// admin gate: the token's issuer must carry an `admin` binding whose
// scopes / claims / clients the token satisfies, or — the single-issuer
// shorthand — the token must hold ADMIN_ROLE. Writes are recorded with the
// token's subject and client (performed_by).
//
// Multi-tenancy: a fleet trusts many identity providers, one per tenant,
// each bound to its stores; a tenant must never see or touch another's.
// So management is SCOPED: an admin binding grants, by default, the
// issuer's own binding only (`scope: issuer` — a tenant admin narrows,
// pauses, re-enables their own identity provider), and the whole fleet
// only with `scope: platform` (the operator's admin identity provider;
// ADMIN_ROLE means platform). Reads follow the same scope.

// IssuerBindingAdmin is what the admin API needs from the backend (the
// direct pgx backend of a full instance).
type IssuerBindingAdmin interface {
	IssuerBindings(ctx context.Context) ([]issuers.Binding, error)
	SetIssuerBinding(ctx context.Context, b issuers.Binding, performedBy string) (int64, error)
	DeleteIssuerBinding(ctx context.Context, issuer, performedBy string) (bool, error)
}

// adminScope is what a passing credential may manage: every issuer and
// store (platform), or one issuer and the stores that issuer is bound to.
type adminScope struct {
	platform bool             // every issuer, every store, the registry
	issuer   string           // else: this issuer (the credential's own, or the certificate's mapped one)
	stores   []*regexp.Regexp // the issuer's stores binding; nil = unbound (no store is managed)
}

func (s adminScope) covers(issuer string) bool { return s.platform || issuer == s.issuer }

// coversStore: a platform admin manages every store; a tenant admin the
// stores its issuer is bound to (an unbound issuer manages none — bind it).
func (s adminScope) coversStore(store string) bool {
	if s.platform {
		return true
	}
	for _, p := range s.stores {
		if p.MatchString(store) {
			return true
		}
	}
	return false
}

// issuerScope: the scope of a tenant admin of issuer iss.
func (h *Handler) issuerScope(iss string) adminScope {
	return adminScope{issuer: iss, stores: h.issuers.current().stores[iss]}
}

// adminGate decides whether the request's credential may manage, and what:
// a token passing its issuer's admin binding or ADMIN_ROLE, or — on the
// mTLS admin listener — a client certificate mapped by ADMIN_CLIENT_CERTS.
func (h *Handler) adminGate(r *http.Request) (adminScope, error) {
	if cert := ClientCertFromContext(r.Context()); cert != nil {
		if h.cfg != nil {
			for _, e := range h.cfg.AdminClientCerts {
				if certMatches(cert, e) {
					if e.Scope == issuers.AdminScopeIssuer {
						return h.issuerScope(e.Issuer), nil
					}
					return adminScope{platform: true, issuer: ""}, nil
				}
			}
		}
		return adminScope{}, errors.New("the client certificate " + certIdentity(cert) + " is not mapped to an admin scope (ADMIN_CLIENT_CERTS)")
	}
	iss := IssuerFromContext(r.Context())
	if iss == "" {
		return adminScope{}, errors.New("management needs a verified token of an issuer with an admin binding, or a mapped client certificate")
	}
	var reasons []string
	if ab := h.issuers.current().admin[iss]; ab != nil {
		if err := ab.satisfiedBy(r.Context()); err == nil {
			if ab.platform {
				return adminScope{platform: true, issuer: iss}, nil
			}
			return h.issuerScope(iss), nil
		} else {
			reasons = append(reasons, err.Error())
		}
	} else {
		reasons = append(reasons, "issuer "+iss+" has no admin binding (JWT_ISSUERS: admin.scopes / claims / clients)")
	}
	if h.cfg != nil && h.cfg.AdminRole != "" {
		for _, have := range RolesFromContext(r.Context()) {
			if have == h.cfg.AdminRole {
				return adminScope{platform: true, issuer: iss}, nil
			}
		}
		reasons = append(reasons, "the token does not hold the admin role (ADMIN_ROLE)")
	}
	return adminScope{}, errors.New(strings.Join(reasons, "; "))
}

// certMatches: the entry names the certificate by its full subject (RFC
// 2253 as Go prints it), its common name, or a SAN URI.
func certMatches(cert *x509.Certificate, e config.AdminClientCert) bool {
	switch {
	case e.Subject != "":
		return cert.Subject.String() == e.Subject
	case e.CN != "":
		return cert.Subject.CommonName == e.CN
	case e.URI != "":
		for _, u := range cert.URIs {
			if u.String() == e.URI {
				return true
			}
		}
	}
	return false
}

// certIdentity names a certificate for the audit trail and the logs: the
// first SAN URI when there is one (a mesh identity), else the subject.
func certIdentity(cert *x509.Certificate) string {
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}
	return cert.Subject.String()
}

// requireAdmin writes the 403 and says why; the scope when the caller may manage.
func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) (adminScope, bool) {
	scope, err := h.adminGate(r)
	if err != nil {
		metrics.AuthzDenied.WithLabelValues("admin_gate").Inc()
		writeForbidden(w, "management refused: "+err.Error())
		return adminScope{}, false
	}
	return scope, true
}

// compiledAdmin is an issuer's admin binding, ready to check a token.
type compiledAdmin struct {
	scopes   []string
	claims   map[string][]string
	clients  map[string]bool
	platform bool
}

func compileAdmin(ab *issuers.AdminBinding) *compiledAdmin {
	if ab == nil {
		return nil
	}
	c := &compiledAdmin{scopes: ab.Scopes, claims: ab.Claims, platform: ab.Scope == issuers.AdminScopePlatform}
	if len(ab.Clients) > 0 {
		c.clients = map[string]bool{}
		for _, id := range ab.Clients {
			c.clients[id] = true
		}
	}
	return c
}

// satisfiedBy: every listed scope present in the token's `scope`; for every
// listed claim, every listed value present (string or array claim, a
// dot-separated path); the client (azp / client_id) listed when clients are.
func (c *compiledAdmin) satisfiedBy(ctx context.Context) error {
	claims := ClaimsFromContext(ctx)
	if claims == nil {
		return errors.New("no verified token")
	}
	for _, s := range c.scopes {
		if !hasScope(claims, s) {
			return errors.New("the token lacks the admin scope " + s)
		}
	}
	for claim, want := range c.claims {
		have := claimValues(claims, claim)
		for _, v := range want {
			if !have[v] {
				return errors.New("the token's " + claim + " claim lacks " + v)
			}
		}
	}
	if c.clients != nil && !c.clients[ClientFromContext(ctx)] {
		return errors.New("the token's client is not an admin client")
	}
	return nil
}

// visibleIssuers: the effective issuers a scope may see — every one for a
// platform admin, else the scope's issuer (a token's own, or the issuer a
// certificate mapping names — review #20: a certificate carries no iss).
func (h *Handler) visibleIssuers(scope adminScope) []IssuerConfig {
	all := h.issuers.current().configs
	if scope.platform {
		return all
	}
	own := scope.issuer
	var out []IssuerConfig
	for _, ic := range all {
		if ic.Issuer == own {
			out = append(out, ic)
		}
	}
	return out
}

// ── the management resources ────────────────────────────────────────────

// adminIssuers — GET /pgauthz/v1/admin/issuers: the effective set within
// the caller's scope.
func (h *Handler) adminIssuers(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	h.writeIssuers(w, h.visibleIssuers(scope))
}

// WithAdminBackend runs the management resources on their own backend
// (ADMIN_DATABASE_URL), leaving the instance's main pool at the writer tier.
func WithAdminBackend(b authz.Backend) Option {
	return func(h *Handler) { h.admin = b }
}

// adminBackend is the backend management runs on.
func (h *Handler) adminBackend() authz.Backend {
	if h.admin != nil {
		return h.admin
	}
	return h.rawWrite
}

func (h *Handler) bindingAdmin(w http.ResponseWriter) (IssuerBindingAdmin, bool) {
	a, ok := h.adminBackend().(IssuerBindingAdmin)
	if !ok {
		writeError(w, http.StatusNotImplemented, "issuer bindings need the direct PostgreSQL backend of a full instance")
		return nil, false
	}
	return a, true
}

// adminIssuerBindings — GET /pgauthz/v1/admin/issuer-bindings[?issuer=…]:
// the database rows within the caller's scope (all of them, or one).
func (h *Handler) adminIssuerBindings(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	a, ok := h.bindingAdmin(w)
	if !ok {
		return
	}
	rows, err := a.IssuerBindings(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	visible := []issuers.Binding{}
	for _, b := range rows {
		if scope.covers(b.Issuer) {
			visible = append(visible, b)
		}
	}
	if want := strings.TrimSpace(r.URL.Query().Get("issuer")); want != "" {
		for _, b := range visible {
			if b.Issuer == want {
				writeJSON(w, http.StatusOK, b)
				return
			}
		}
		writeError(w, http.StatusNotFound, "no binding for issuer "+want)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bindings": visible})
}

// adminSetIssuerBinding — PUT /pgauthz/v1/admin/issuer-bindings: create or
// replace one binding (the whole row) within the caller's scope, validated
// as the daemon validates, and the revision the fleet will apply.
func (h *Handler) adminSetIssuerBinding(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	a, ok := h.bindingAdmin(w)
	if !ok {
		return
	}
	var b issuers.Binding
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		writeBadRequest(w, "invalid JSON: "+err.Error())
		return
	}
	b.Issuer = strings.TrimSpace(b.Issuer)
	if b.Issuer == "" {
		writeBadRequest(w, "issuer is required (the token's iss)")
		return
	}
	if !scope.covers(b.Issuer) {
		metrics.AuthzDenied.WithLabelValues("admin_scope").Inc()
		writeForbidden(w, "management refused: this token manages the issuer "+scope.issuer+" only")
		return
	}
	if err := issuers.ValidateBindings(issuers.Issuer{Stores: b.Stores, DBRoles: b.DBRoles, ClientDBRoles: b.ClientDBRoles, PEPClients: b.PEPClients}); err != nil {
		writeBadRequest(w, err.Error())
		return
	}
	// the narrowing rule against the environment, so a PUT the fleet would
	// reject fails here instead of silently falling back; an issuer the
	// environment does not trust is refused for the same reason
	trusted := false
	for _, ic := range h.issuers.current().configs {
		if ic.Issuer != b.Issuer {
			continue
		}
		trusted = true
		envStores := ic.Stores
		if ic.BindingSource == "db" {
			envStores = ic.EnvStores
		}
		if _, problems := issuers.Merge([]issuers.Issuer{{Issuer: ic.Issuer, Stores: envStores}}, []issuers.Binding{b}); len(problems) > 0 {
			writeBadRequest(w, problems[0])
			return
		}
	}
	if !trusted {
		writeBadRequest(w, "issuer "+b.Issuer+" is not trusted by this instance (JWT_ISSUERS): a binding cannot add trust")
		return
	}
	rev, err := a.SetIssuerBinding(r.Context(), b, actorLabel(r))
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"issuer": b.Issuer, "revision": rev})
}

// adminDeleteIssuerBinding — DELETE /pgauthz/v1/admin/issuer-bindings?issuer=…
func (h *Handler) adminDeleteIssuerBinding(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	a, ok := h.bindingAdmin(w)
	if !ok {
		return
	}
	iss := strings.TrimSpace(r.URL.Query().Get("issuer"))
	if iss == "" {
		writeBadRequest(w, "issuer query parameter is required")
		return
	}
	if !scope.covers(iss) {
		metrics.AuthzDenied.WithLabelValues("admin_scope").Inc()
		writeForbidden(w, "management refused: this token manages the issuer "+scope.issuer+" only")
		return
	}
	existed, err := a.DeleteIssuerBinding(r.Context(), iss, actorLabel(r))
	if err != nil {
		writeDecisionError(w, err)
		return
	}
	if !existed {
		writeError(w, http.StatusNotFound, "no binding for issuer "+iss)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"issuer": iss, "deleted": true})
}

// actorLabel is who a management write is recorded as: the token's subject,
// and its client when it has one.
func actorLabel(r *http.Request) string {
	if cert := ClientCertFromContext(r.Context()); cert != nil {
		return "cert:" + certIdentity(cert)
	}
	st, sid := SubjectFromContext(r.Context())
	label := ""
	if sid != "" {
		label = st + ":" + sid
	}
	if c := ClientFromContext(r.Context()); c != "" {
		if label != "" {
			label += " via " + c
		} else {
			label = "client:" + c
		}
	}
	return label
}

// newAdminMux: the admin listener's routes — management and the probes.
func newAdminMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()
	registerAdmin(mux, h)
	mux.HandleFunc("GET /livez", h.Livez)
	mux.HandleFunc("GET /readyz", h.Readyz)
	return mux
}

// registerAdmin mounts the management routes under /pgauthz/v1/admin/.
func registerAdmin(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("GET /pgauthz/v1/admin/issuers", h.adminIssuers)
	mux.HandleFunc("GET /pgauthz/v1/admin/issuer-bindings", h.adminIssuerBindings)
	mux.HandleFunc("PUT /pgauthz/v1/admin/issuer-bindings", h.adminSetIssuerBinding)
	mux.HandleFunc("DELETE /pgauthz/v1/admin/issuer-bindings", h.adminDeleteIssuerBinding)
	registerAdminStores(mux, h)
}

// NewAdminRouter is the dedicated admin listener (ADMIN_LISTEN_ADDR): the
// management routes and the health probes, behind the same JWT middleware
// as the public listener (the admin gate is per route), without CORS. Under
// mTLS a verified client certificate passes the middleware without a token
// (AllowClientCert) and the gate matches it against ADMIN_CLIENT_CERTS.
func NewAdminRouter(h *Handler, jwtMW *JWTMiddleware) http.Handler {
	h.listener = "admin"
	mux := newAdminMux(h)
	var handler http.Handler = spanNamed(mux)
	handler = MaxBody(h.cfg.HTTPMaxBodyBytes)(handler)
	if h.cfg.AdminClientCA != "" {
		cfg := jwtMW.cfg
		cfg.AllowClientCert = true
		jwtMW = &JWTMiddleware{cfg: cfg, set: jwtMW.set}
	}
	handler = jwtMW.Middleware(handler)
	handler = RequestID(handler)
	handler = Logging(handler)
	handler = Recovery(handler)
	return Metrics(mux, handler)
}

// NewManagementRouter is the management listener (MANAGEMENT_LISTEN_ADDR,
// ADR 0010): the operator surface — Prometheus /metrics and the probes —
// on a separate, non-public port. No authentication (bind it to the pod or
// mesh network), no request metrics (a scrape must not count itself), no
// tracing (newServer leaves the probes out).
func NewManagementRouter(h *Handler, metricsHandler http.Handler) http.Handler {
	h.listener = "management"
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metricsHandler)
	mux.HandleFunc("GET /healthz", h.Healthz) // deprecated alias of /readyz
	mux.HandleFunc("GET /livez", h.Livez)
	mux.HandleFunc("GET /readyz", h.Readyz)
	return Recovery(mux)
}
