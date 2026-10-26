package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
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
	IssuerBindingsRevision(ctx context.Context) (int64, error)
	// IssuerBindingsAudit is one page of the history, newest first, keyset
	// by seq (before = the previous page's last seq), and the total.
	IssuerBindingsAudit(ctx context.Context, issuer string, limit int, before *int64) ([]issuers.AuditRow, int64, error)
	SetIssuerBinding(ctx context.Context, b issuers.Binding, performedBy string) (int64, error)
	DeleteIssuerBinding(ctx context.Context, issuer, performedBy string) (bool, error)
}

// adminScope is what a passing credential may manage: every issuer and
// store (platform), or one issuer and the stores that issuer is bound to —
// narrowed, when the rule says so, to some of those stores and to some
// capabilities (a CI credential: test, on one store, nothing else).
type adminScope struct {
	platform bool             // every issuer, every store, the registry
	issuer   string           // else: this issuer (the credential's own, or the certificate's mapped one)
	stores   []*regexp.Regexp // the issuer's stores binding; nil = unbound (no store is managed)
	only     []*regexp.Regexp // the rule's stores, within the binding; nil = the whole binding
	caps     []string         // the rule's capabilities; nil = manage
	decide   *delegated       // a delegated rule: the store answers instead of the fields above
}

// delegated is a credential whose rights an authorization store decides —
// the management console's: the subject the token became, the contextual
// memberships its roles and scopes give it, and the relations THIS request
// needs (admin verb → console relation, decided once in delegatedNeeds).
// check asks the store on the admin pool; an error (no such store, the
// pool down) is a refusal with the reason.
type delegated struct {
	store, subjType, subjID   string
	ctxTuples                 json.RawMessage
	scopes                    map[string]bool // the token's pgauthz:* scopes: its own cap on the store's grants
	check                     func(relation, objType, objID string) (bool, error)
	storeRel                  string // what the request needs on store:{store}, "" = nothing store-level
	platRel, platType, platID string // what it needs platform-wide (platform:default / registry:default)
	why                       string // the last refusal's reason, for the 403
}

// allowed asks the store, remembering the reason of a refusal.
func (d *delegated) allowed(relation, objType, objID string) bool {
	ok, err := d.check(relation, objType, objID)
	switch {
	case err != nil:
		d.why = fmt.Sprintf("the %s store could not decide %s %s on %s:%s: %v", d.store, d.subjType+":"+d.subjID, relation, objType, objID, err)
		return false
	case !ok:
		d.why = fmt.Sprintf("the %s store does not grant %s %s on %s:%s", d.store, d.subjType+":"+d.subjID, relation, objType, objID)
		return false
	}
	return true
}

// platformWide: the credential reaches every issuer and store — a platform
// rule, or (delegated) the platform-level relation this request needs.
func (s adminScope) platformWide() bool {
	if s.decide != nil {
		return s.decide.platRel != "" && s.decide.allowed(s.decide.platRel, s.decide.platType, s.decide.platID)
	}
	return s.platform
}

func (s adminScope) covers(issuer string) bool { return s.platformWide() || issuer == s.issuer }

// coversStore: a platform admin manages every store; a tenant admin the
// stores its issuer is bound to (an unbound issuer manages none — bind it),
// and of those only the rule's when it names some; a delegated credential
// the stores on which the deciding store grants it this request's relation.
func (s adminScope) coversStore(store string) bool {
	if s.decide != nil {
		return s.decide.storeRel != "" && s.decide.allowed(s.decide.storeRel, "store", store)
	}
	if s.only != nil && !matchesAny(s.only, store) {
		return false
	}
	if s.platform {
		return true
	}
	return matchesAny(s.stores, store)
}

// refusal: why the scope does not cover what was asked — the deciding
// store's answer for a delegated credential, the binding for the rest.
func (s adminScope) refusal(what string) string {
	if s.decide != nil && s.decide.why != "" {
		return "management refused: " + s.decide.why
	}
	return "management refused: " + what
}

func matchesAny(patterns []*regexp.Regexp, store string) bool {
	for _, p := range patterns {
		if p.MatchString(store) {
			return true
		}
	}
	return false
}

// can: the credential holds the capability — manage (the default) implies
// every one; a delegated credential's verbs are the store's relations.
func (s adminScope) can(capability string) bool {
	if len(s.caps) == 0 || s.decide != nil {
		return true
	}
	for _, c := range s.caps {
		if c == issuers.AdminCapManage || c == capability {
			return true
		}
	}
	return false
}

// neededCapability: what a request needs — test for the fixture runner,
// read for the GET verbs, manage for everything else. Decided here, once,
// for every admin route.
func neededCapability(r *http.Request) string {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/pgauthz/v1/admin/models/test":
		return issuers.AdminCapTest
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		return issuers.AdminCapRead
	default:
		return issuers.AdminCapManage
	}
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
					scope := adminScope{platform: true}
					if e.Scope == issuers.AdminScopeIssuer {
						scope = h.issuerScope(e.Issuer)
					}
					scope.caps = e.Capabilities
					if len(e.Stores) > 0 {
						scope.only = compileAnchored(e.Stores)
					}
					return scope, nil
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
	if rules := h.issuers.current().admin[iss]; len(rules) > 0 {
		// the first satisfied rule decides; an unsatisfied one explains
		for _, ab := range rules {
			if err := ab.satisfiedBy(r.Context()); err != nil {
				reasons = append(reasons, err.Error())
				continue
			}
			if ab.decide != nil {
				d, err := h.delegate(r.Context(), ab.decide)
				if err != nil {
					reasons = append(reasons, err.Error())
					continue
				}
				d.storeRel, d.platType, d.platID, d.platRel = delegatedNeeds(r)
				return adminScope{issuer: iss, decide: d}, nil
			}
			scope := adminScope{platform: true, issuer: iss}
			if !ab.platform {
				scope = h.issuerScope(iss)
			}
			scope.caps = ab.caps
			scope.only = ab.stores
			return scope, nil
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
	need := neededCapability(r)
	if !scope.can(need) {
		metrics.AuthzDenied.WithLabelValues("admin_scope").Inc()
		writeForbidden(w, "management refused: this credential may only "+strings.Join(scope.caps, ", ")+" (its admin rule's capabilities); this call needs "+need)
		return adminScope{}, false
	}
	if d := scope.decide; d != nil {
		if want := d.scopeFor(r, need); !d.covers(want) {
			metrics.AuthzDenied.WithLabelValues("admin_scope").Inc()
			msg := "management refused: the token's pgauthz scopes (" + d.scopeList() + ") do not cover this call; it needs pgauthz:" + want
			if want != "admin" {
				msg += " (or pgauthz:admin)"
			}
			writeForbidden(w, msg)
			return adminScope{}, false
		}
	}
	return scope, true
}

// scopeFor: the pgauthz scope a request needs — test for the fixture
// runner, read for a GET on a store or the registry, manage for a store
// write; the platform itself — the issuers, reading included, a registry
// write, creating a store — needs admin.
func (d *delegated) scopeFor(r *http.Request, need string) string {
	if strings.HasPrefix(r.URL.Path, "/pgauthz/v1/admin/issuer") {
		return "admin"
	}
	if need == issuers.AdminCapManage && d.storeRel == "" {
		return "admin"
	}
	return need
}

// covers: admin covers everything, manage covers test and read as well.
func (d *delegated) covers(want string) bool {
	if d.scopes["admin"] || d.scopes[want] {
		return true
	}
	return d.scopes["manage"] && (want == issuers.AdminCapTest || want == issuers.AdminCapRead)
}

func (d *delegated) scopeList() string {
	var out []string
	for s := range d.scopes {
		out = append(out, "pgauthz:"+s)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// delegatedNeeds maps an admin request onto the management console's
// model (examples/models/console): the relation it needs on store:{store}
// and the platform-wide one — platform:default for the fleet, registry:default
// for the model registry. The console checks the same relations for the
// same actions, so a person has the same rights through the console and
// through pgauthzctl with their own token.
func delegatedNeeds(r *http.Request) (storeRel, platType, platID, platRel string) {
	p := strings.TrimPrefix(r.URL.Path, "/pgauthz/v1/admin/")
	get := r.Method == http.MethodGet || r.Method == http.MethodHead
	switch {
	case strings.HasPrefix(p, "issuer"):
		return "", "platform", "default", "can_manage_issuers"
	case p == "models/test":
		// a live store's fixture: run tests on it; a model of its own: read the registry
		return "can_run_tests", "registry", "default", "can_view"
	case strings.HasPrefix(p, "models"):
		if get {
			return "", "registry", "default", "can_view"
		}
		return "", "registry", "default", "can_publish"
	case p == "stores":
		return "can_view", "platform", "default", "can_view_all_stores"
	case strings.HasPrefix(p, "stores/"):
		rest := ""
		if i := strings.Index(p[len("stores/"):], "/"); i >= 0 {
			rest = p[len("stores/")+i:]
		}
		switch {
		case strings.HasPrefix(rest, "/subjects"):
			storeRel = "can_export"
		case get:
			storeRel = "can_view"
		case rest == "/model":
			storeRel = "can_rollout"
		default: // the store itself, its decisions, recorders, namespaces
			storeRel = "can_manage_access"
		}
		// creating a store is the platform's (PUT on a store nobody owns yet)
		return storeRel, "platform", "default", "can_create_store"
	}
	return "", "platform", "default", "admin"
}

// compiledAdmin is an issuer's admin binding, ready to check a token.
type compiledAdmin struct {
	scopes   []string
	claims   map[string][]string
	clients  map[string]bool
	platform bool
	caps     []string         // nil = manage
	stores   []*regexp.Regexp // nil = the issuer's whole binding
	decide   *issuers.AdminDecision
}

// delegate turns the token into a subject of the deciding store: the id
// from the rule's claim (a token without it does not satisfy the rule, so
// the next rule is tried), the roles and scopes as contextual team
// memberships, and the check bound to the admin pool.
func (h *Handler) delegate(ctx context.Context, d *issuers.AdminDecision) (*delegated, error) {
	claims := ClaimsFromContext(ctx)
	claim := d.SubjectClaim
	if claim == "" && h.cfg != nil {
		claim = h.cfg.SubjectIDClaim
	}
	if claim == "" {
		claim = "preferred_username"
	}
	id := strings.TrimSpace(claimStringPath(claims, claim))
	if id == "" {
		return nil, errors.New("the token has no " + claim + " claim (the admin rule's decide.subject_claim)")
	}
	typ := d.SubjectType
	if typ == "" {
		typ = "user"
	}
	type tuple struct {
		UserType   string `json:"user_type"`
		UserID     string `json:"user_id"`
		Relation   string `json:"relation"`
		ObjectType string `json:"object_type"`
		ObjectID   string `json:"object_id"`
	}
	var memberships []tuple
	for _, role := range RolesFromContext(ctx) {
		memberships = append(memberships, tuple{typ, id, "member", "team", "role_" + role})
	}
	for _, s := range strings.Fields(claimString(claims, "scope")) {
		memberships = append(memberships, tuple{typ, id, "member", "team", "scope_" + s})
	}
	ctxTuples, _ := json.Marshal(memberships)
	// The token's own statement of what it is for caps the store's grants:
	// pgauthz:test (fixtures), pgauthz:read (GETs), pgauthz:manage (store
	// writes), pgauthz:admin (everything, the platform included).
	scopes := map[string]bool{}
	for _, s := range strings.Fields(claimString(claims, "scope")) {
		if strings.HasPrefix(s, "pgauthz:") {
			scopes[strings.TrimPrefix(s, "pgauthz:")] = true
		}
	}
	if len(scopes) == 0 {
		return nil, errors.New("the token carries no pgauthz scope (pgauthz:test, pgauthz:read, pgauthz:manage or pgauthz:admin): it was not issued for this API's management")
	}
	checker, _ := h.adminBackend().(authz.ContextualChecker)
	return &delegated{store: d.Store, subjType: typ, subjID: id, ctxTuples: ctxTuples, scopes: scopes,
		check: func(relation, objType, objID string) (bool, error) {
			if checker == nil {
				return false, errors.New("the backend cannot check with contextual tuples (a full instance's direct backend does)")
			}
			return checker.CheckWithContextualTuples(ctx, authz.EvalRequest{Store: d.Store, SubjectType: typ, SubjectID: id, Action: relation, ObjectType: objType, ObjectID: objID}, ctxTuples)
		}}, nil
}

func compileAdmin(ab *issuers.AdminBinding) *compiledAdmin {
	if ab == nil {
		return nil
	}
	c := &compiledAdmin{scopes: ab.Scopes, claims: ab.Claims, platform: ab.Scope == issuers.AdminScopePlatform, caps: ab.Capabilities, decide: ab.Decide}
	if len(ab.Clients) > 0 {
		c.clients = map[string]bool{}
		for _, id := range ab.Clients {
			c.clients[id] = true
		}
	}
	if len(ab.Stores) > 0 {
		c.stores = compileAnchored(ab.Stores)
	}
	return c
}

func compileAdminRules(rules issuers.AdminRules) []*compiledAdmin {
	out := make([]*compiledAdmin, 0, len(rules))
	for i := range rules {
		out = append(out, compileAdmin(&rules[i]))
	}
	return out
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
	if scope.platformWide() {
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
	rev, err := a.IssuerBindingsRevision(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bindings": visible, "revision": rev})
}

// adminIssuerBindingsAudit — GET /pgauthz/v1/admin/issuer-bindings/audit
// ?issuer=&limit=&before=<seq>: one page of the rows' history within the
// caller's scope — a tenant admin reads its own issuer's history only (the
// filter is set for it; asking for another is refused).
func (h *Handler) adminIssuerBindingsAudit(w http.ResponseWriter, r *http.Request) {
	scope, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	a, ok := h.bindingAdmin(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	issuer := strings.TrimSpace(q.Get("issuer"))
	if !scope.platform {
		if issuer == "" {
			issuer = scope.issuer
		} else if issuer != scope.issuer {
			metrics.AuthzDenied.WithLabelValues("admin_scope").Inc()
			writeForbidden(w, "management refused: this credential reads the history of the issuer "+scope.issuer+" only")
			return
		}
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 25
	}
	var before *int64
	if b := q.Get("before"); b != "" {
		n, err := strconv.ParseInt(b, 10, 64)
		if err != nil || n <= 0 {
			writeBadRequest(w, "before must be the previous page's next (a sequence number)")
			return
		}
		before = &n
	}
	rows, total, err := a.IssuerBindingsAudit(r.Context(), issuer, limit, before)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if rows == nil {
		rows = []issuers.AuditRow{}
	}
	next := ""
	if len(rows) == limit {
		next = strconv.FormatInt(rows[len(rows)-1].Seq, 10)
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows, "next": next, "total": total, "limit": limit, "issuer": issuer})
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
	mux.HandleFunc("GET /pgauthz/v1/admin/issuer-bindings/audit", h.adminIssuerBindingsAudit)
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
