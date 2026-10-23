package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

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

// adminScope is what a passing token may manage.
type adminScope struct {
	platform bool   // every issuer
	issuer   string // else: this one (the token's own)
}

func (s adminScope) covers(issuer string) bool { return s.platform || issuer == s.issuer }

// adminGate decides whether the request's token may manage, and what.
func (h *Handler) adminGate(r *http.Request) (adminScope, error) {
	iss := IssuerFromContext(r.Context())
	if iss == "" {
		return adminScope{}, errors.New("management needs a verified token of an issuer with an admin binding")
	}
	var reasons []string
	if ab := h.issuers.Current().admin[iss]; ab != nil {
		if err := ab.satisfiedBy(r.Context()); err == nil {
			return adminScope{platform: ab.platform, issuer: iss}, nil
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

// visibleIssuers: the effective issuers the caller may see — its own, or
// every one for a platform admin.
func (h *Handler) visibleIssuers(r *http.Request, platform bool) []IssuerConfig {
	all := h.issuers.Current().configs
	if platform {
		return all
	}
	own := IssuerFromContext(r.Context())
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
	h.writeIssuers(w, h.visibleIssuers(r, scope.platform))
}

func (h *Handler) bindingAdmin(w http.ResponseWriter) (IssuerBindingAdmin, bool) {
	a, ok := h.rawWrite.(IssuerBindingAdmin)
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
	for _, ic := range h.issuers.Current().configs {
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
}

// NewAdminRouter is the dedicated admin listener (ADMIN_LISTEN_ADDR): the
// management routes and the health probes, behind the same JWT middleware
// as the public listener (the admin gate is per route), without CORS.
func NewAdminRouter(h *Handler, jwtMW *JWTMiddleware) http.Handler {
	h.listener = "admin"
	mux := newAdminMux(h)
	var handler http.Handler = spanNamed(mux)
	handler = MaxBody(h.cfg.HTTPMaxBodyBytes)(handler)
	handler = jwtMW.Middleware(handler)
	handler = RequestID(handler)
	handler = Logging(handler)
	handler = Recovery(handler)
	return Metrics(mux, handler)
}
