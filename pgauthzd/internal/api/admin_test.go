package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
	"thomasdarimont.de/authz/pgauthzd/pkg/issuers"
)

// adminStub is the binding store behind the admin API in these tests.
// grantStub answers delegated checks (a console store) from a map keyed
// "type:id relation objtype:objid" and remembers every check with its
// contextual tuples; the key "err" makes every check fail.
type grantStub struct {
	grants map[string]bool
	checks []string
}

func (g *grantStub) CheckWithContextualTuples(_ context.Context, req authz.EvalRequest, ctxTuples json.RawMessage) (bool, error) {
	key := fmt.Sprintf("%s:%s %s %s:%s", req.SubjectType, req.SubjectID, req.Action, req.ObjectType, req.ObjectID)
	g.checks = append(g.checks, req.Store+" "+key+" "+string(ctxTuples))
	if g.grants["err"] {
		return false, errors.New("store " + req.Store + " not found")
	}
	return g.grants[key], nil
}

type adminStub struct {
	authz.Backend
	grantStub
	rows map[string]issuers.Binding
	rev  int64
	by   []string // performed_by of every write
}

func (s *adminStub) IssuerBindings(context.Context) ([]issuers.Binding, error) {
	out := []issuers.Binding{}
	for _, b := range s.rows {
		out = append(out, b)
	}
	return out, nil
}

func (s *adminStub) IssuerBindingsRevision(context.Context) (int64, error) { return s.rev, nil }

func (s *adminStub) IssuerBindingsAudit(_ context.Context, issuer string, groups []string, limit int, _ *int64) ([]issuers.AuditRow, int64, error) {
	out := []issuers.AuditRow{}
	seq := int64(100)
	// tenant-a and tenant-b as platform rows; the group issuer's history: one
	// row under tenant_x (before a transfer), one under tenant_c
	all := []issuers.AuditRow{
		{Issuer: "https://tenant-a"}, {Issuer: "https://tenant-b"},
		{Issuer: "https://group-idp", StoreGroup: "tenant_x"}, {Issuer: "https://group-idp", StoreGroup: "tenant_c"},
	}
	for _, row := range all {
		if (issuer == "" || issuer == row.Issuer) && (groups == nil || slices.Contains(groups, row.StoreGroup)) {
			out = append(out, issuers.AuditRow{Seq: seq, Action: "set", PerformedBy: "test", Issuer: row.Issuer, Stores: []string{}, StoreGroup: row.StoreGroup})
		}
		seq--
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, int64(len(out)), nil
}

func (s *adminStub) SetIssuerBinding(_ context.Context, b issuers.Binding, by, expectGroup string) (int64, error) {
	if err := s.expect(b.Issuer, expectGroup); err != nil {
		return 0, err
	}
	s.rows[b.Issuer] = b
	s.rev++
	s.by = append(s.by, by)
	return s.rev, nil
}

// expect is the engine's ownership precondition (authz.set_issuer_binding
// p_expect_group): the row must still be owned as the caller authorized.
func (s *adminStub) expect(issuer, expectGroup string) error {
	if expectGroup == issuers.ExpectAny {
		return nil
	}
	cur, exists := s.rows[issuer]
	if (exists && cur.StoreGroup != expectGroup) || (!exists && expectGroup != "") {
		return issuers.ErrOwnership
	}
	return nil
}

func (s *adminStub) DeleteIssuerBinding(_ context.Context, issuer, by, expectGroup string) (bool, error) {
	if err := s.expect(issuer, expectGroup); err != nil {
		return false, err
	}
	_, ok := s.rows[issuer]
	delete(s.rows, issuer)
	s.by = append(s.by, by)
	return ok, nil
}

// adminFixture: a platform identity provider (admin binding with platform
// scope, by scope + claim), two tenant identity providers — one with a
// tenant-scoped admin binding (by client) — and ADMIN_ROLE as the shorthand.
func adminFixture(t *testing.T) (*Handler, *adminStub) {
	t.Helper()
	env := []issuers.Issuer{
		{Issuer: "https://platform-idp", Audience: "api", JWKSURL: "https://platform-idp/jwks",
			Admin: issuers.AdminRules{{Scopes: []string{"pgauthz:admin"}, Claims: map[string][]string{"realm_access.roles": {"platform-admin"}}, Scope: issuers.AdminScopePlatform}}},
		// two rules: terraform-a manages the tenant's stores; ci-a may only
		// run fixtures, and only against a_docs (a CI credential)
		{Issuer: "https://tenant-a", Audience: "api", JWKSURL: "https://tenant-a/jwks", Stores: []string{"a_.*"},
			Admin: issuers.AdminRules{{Clients: []string{"terraform-a"}}, {Clients: []string{"ci-a"}, Capabilities: []string{issuers.AdminCapTest}, Stores: []string{"a_docs"}}}},
		{Issuer: "https://tenant-b", Alias: "tenant-b", Audience: "api", JWKSURL: "https://tenant-b/jwks", Stores: []string{"b_.*"}},
		// delegated: the console store decides — the ci-c client as
		// service_account:ci-c, everyone else as user:<preferred_username>
		{Issuer: "https://tenant-c", Audience: "api", JWKSURL: "https://tenant-c/jwks", Stores: []string{"c_.*"},
			Admin: issuers.AdminRules{
				{Clients: []string{"ci-c"}, Decide: &issuers.AdminDecision{Store: "console", SubjectType: "service_account", SubjectClaim: "azp"}},
				{Decide: &issuers.AdminDecision{Store: "console"}}}},
	}
	cfg := &config.Config{Profile: config.ProfileFull, Issuers: env, IssuersSource: "env+db", AdminAPIEnabled: true, AdminRole: "pgauthz_admin",
		GroupIssuerHosts: []string{"new-idp", "carol-idp", "other-idp", "x-idp", "c-idp", "race-idp", "group-idp"}, OutboundHostPolicy: config.OutboundHostPolicyAllowlist} // the tenant IdP hosts the platform admits (GROUP_ISSUER_HOSTS)
	stub := &adminStub{rows: map[string]issuers.Binding{
		"https://tenant-a": {Issuer: "https://tenant-a", Alias: "tenant-a", Stores: []string{"a_docs"}, Enabled: true},
		"https://tenant-b": {Issuer: "https://tenant-b", Stores: []string{"b_docs"}, Enabled: true},
	}}
	h := NewHandler(nil, nil, stub, cfg, WithIssuers(NewIssuers(IssuerConfigsFrom(env))))
	return h, stub
}

// token puts a verified token's facts into the request context the way the
// JWT middleware does.
type token struct {
	iss, sub, client, scope string
	roles                   []string
	claims                  jwt.MapClaims
}

func (tk token) request(method, url, body string) *http.Request {
	r := httptest.NewRequest(method, url, strings.NewReader(body))
	ctx := r.Context()
	claims := jwt.MapClaims{"iss": tk.iss, "sub": tk.sub}
	for k, v := range tk.claims {
		claims[k] = v
	}
	if tk.scope != "" {
		claims["scope"] = tk.scope
	}
	if tk.client != "" {
		claims["azp"] = tk.client
		ctx = context.WithValue(ctx, ctxClient, tk.client)
	}
	ctx = context.WithValue(ctx, ctxClaims, claims)
	ctx = context.WithValue(ctx, ctxIssuer, tk.iss)
	ctx = context.WithValue(ctx, ctxSubjectType, "user")
	ctx = context.WithValue(ctx, ctxSubjectID, tk.sub)
	if len(tk.roles) > 0 {
		ctx = context.WithValue(ctx, ctxRoles, tk.roles)
	}
	return r.WithContext(ctx)
}

var (
	platformAdmin  = token{iss: "https://platform-idp", sub: "ops", scope: "openid pgauthz:admin", claims: jwt.MapClaims{"realm_access": map[string]any{"roles": []any{"platform-admin"}}}}
	tenantAAdmin   = token{iss: "https://tenant-a", sub: "alice", client: "terraform-a"}
	tenantACI      = token{iss: "https://tenant-a", sub: "ci", client: "ci-a"} // test on a_docs, nothing else
	tenantCUser    = token{iss: "https://tenant-c", sub: "carol-uuid", scope: "openid pgauthz:admin", roles: []string{"console_admin"}, claims: jwt.MapClaims{"preferred_username": "carol"}}
	tenantCCI      = token{iss: "https://tenant-c", sub: "ci-uuid", client: "ci-c", scope: "pgauthz:test"}
	tenantCNobody  = token{iss: "https://tenant-c", sub: "nobody-uuid"} // no preferred_username, not the ci client
	tenantCManage  = token{iss: "https://tenant-c", sub: "dave-uuid", scope: "pgauthz:manage", claims: jwt.MapClaims{"preferred_username": "dave"}}
	tenantCNoScope = token{iss: "https://tenant-c", sub: "erin-uuid", scope: "openid profile", claims: jwt.MapClaims{"preferred_username": "erin"}}
	tenantCPipe    = token{iss: "https://tenant-c", sub: "pipe-uuid", client: "ci-c", scope: "pgauthz:ci"} // a pipeline: stores and the registry, never the issuers
	tenantAUser    = token{iss: "https://tenant-a", sub: "bob", client: "docs-app"}
	tenantBUser    = token{iss: "https://tenant-b", sub: "carol"}
	roleAdmin      = token{iss: "https://tenant-b", sub: "root", roles: []string{"pgauthz_admin"}}
)

func do(h *Handler, fn http.HandlerFunc, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	fn(w, r)
	return w
}

// The gate: an admin binding's scopes, claims and clients; ADMIN_ROLE; and
// what each admits — the issuer's own binding or the platform.
func TestAdminGate(t *testing.T) {
	h, _ := adminFixture(t)
	cases := []struct {
		name     string
		tk       token
		platform bool
		refused  string
	}{
		{"platform admin by scope + claim", platformAdmin, true, ""},
		{"platform admin without the scope", token{iss: "https://platform-idp", sub: "ops", scope: "openid", claims: platformAdmin.claims}, false, "lacks the admin scope pgauthz:admin"},
		{"platform admin without the claim value", token{iss: "https://platform-idp", sub: "ops", scope: "pgauthz:admin", claims: jwt.MapClaims{"realm_access": map[string]any{"roles": []any{"viewer"}}}}, false, "realm_access.roles claim lacks platform-admin"},
		{"tenant admin by client", tenantAAdmin, false, ""},
		{"a tenant's other client", tenantAUser, false, "not an admin client"},
		{"an issuer without an admin binding", tenantBUser, false, "has no admin binding (JWT_ISSUERS: admin.scopes / claims / clients); the token does not hold the admin role (ADMIN_ROLE)"},
		{"ADMIN_ROLE is a platform admin", roleAdmin, true, ""},
		{"no token", token{}, false, "needs a verified token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope, err := h.adminGate(tc.tk.request("GET", "/pgauthz/v1/admin/issuers", ""))
			if tc.refused != "" {
				if err == nil || !strings.Contains(err.Error(), tc.refused) {
					t.Fatalf("want refusal %q, got %v (scope %+v)", tc.refused, err, scope)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if scope.platform != tc.platform || scope.issuer != tc.tk.iss {
				t.Fatalf("scope %+v", scope)
			}
		})
	}
	// without any gate configured nothing passes
	h.cfg.AdminRole = ""
	if _, err := h.adminGate(roleAdmin.request("GET", "/", "")); err == nil {
		t.Fatal("ADMIN_ROLE unset must not admit by role")
	}
}

// The resources, scoped per tenant: a tenant admin sees and manages its own
// issuer only; a platform admin every issuer; the narrowing rule and the
// environment's trust are enforced before the store sees a row.
func TestAdminIssuerBindings(t *testing.T) {
	h, stub := adminFixture(t)

	// reads within scope
	w := do(h, h.adminIssuerBindings, tenantAAdmin.request("GET", "/pgauthz/v1/admin/issuer-bindings", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "tenant-a") || strings.Contains(w.Body.String(), "tenant-b") {
		t.Fatalf("tenant admin's list: %d %s", w.Code, w.Body.String())
	}
	w = do(h, h.adminIssuerBindings, platformAdmin.request("GET", "/pgauthz/v1/admin/issuer-bindings", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "tenant-a") || !strings.Contains(w.Body.String(), "tenant-b") {
		t.Fatalf("platform admin's list: %d %s", w.Code, w.Body.String())
	}
	w = do(h, h.adminIssuerBindings, tenantAAdmin.request("GET", "/pgauthz/v1/admin/issuer-bindings?issuer=https://tenant-b", ""))
	if w.Code != http.StatusNotFound {
		t.Fatalf("another tenant's binding must read as absent: %d %s", w.Code, w.Body.String())
	}
	w = do(h, h.adminIssuerBindings, tenantAUser.request("GET", "/pgauthz/v1/admin/issuer-bindings", ""))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a non-admin: %d", w.Code)
	}
	w = do(h, h.adminIssuers, tenantAAdmin.request("GET", "/pgauthz/v1/admin/issuers", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "tenant-a") || strings.Contains(w.Body.String(), "platform-idp") {
		t.Fatalf("tenant admin's issuers: %d %s", w.Code, w.Body.String())
	}
	// the history: a tenant admin reads its own issuer's, the filter is set
	// for it, another issuer's is refused; a platform admin reads every one
	w = do(h, h.adminIssuerBindingsAudit, tenantAAdmin.request("GET", "/pgauthz/v1/admin/issuer-bindings/audit", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"issuer":"https://tenant-a"`) || strings.Contains(w.Body.String(), "tenant-b") || !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("tenant admin's history: %d %s", w.Code, w.Body.String())
	}
	if w := do(h, h.adminIssuerBindingsAudit, tenantAAdmin.request("GET", "/pgauthz/v1/admin/issuer-bindings/audit?issuer=https://tenant-b", "")); w.Code != http.StatusForbidden {
		t.Fatalf("another tenant's history: %d", w.Code)
	}
	w = do(h, h.adminIssuerBindingsAudit, platformAdmin.request("GET", "/pgauthz/v1/admin/issuer-bindings/audit?limit=1", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"next":"100"`) || !strings.Contains(w.Body.String(), `"limit":1`) {
		t.Fatalf("platform admin's history page: %d %s", w.Code, w.Body.String())
	}
	if w := do(h, h.adminIssuerBindingsAudit, platformAdmin.request("GET", "/pgauthz/v1/admin/issuer-bindings/audit?before=x", "")); w.Code != 400 {
		t.Fatalf("bad cursor: %d", w.Code)
	}
	w = do(h, h.adminIssuerBindings, platformAdmin.request("GET", "/pgauthz/v1/admin/issuer-bindings", ""))
	if !strings.Contains(w.Body.String(), `"revision":`) {
		t.Fatalf("the list carries the database revision: %s", w.Body.String())
	}
	w = do(h, h.adminIssuers, platformAdmin.request("GET", "/pgauthz/v1/admin/issuers", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"admin":[{"scopes":["pgauthz:admin"]`) || !strings.Contains(w.Body.String(), "tenant-b") {
		t.Fatalf("platform admin's issuers: %d %s", w.Code, w.Body.String())
	}

	// writes: own issuer, narrowing the environment
	put := func(tk token, body string) *httptest.ResponseRecorder {
		return do(h, h.adminSetIssuerBinding, tk.request("PUT", "/pgauthz/v1/admin/issuer-bindings", body))
	}
	w = put(tenantAAdmin, `{"issuer":"https://tenant-a","stores":["a_mail"],"enabled":true,"description":"mail only"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"revision":1`) {
		t.Fatalf("tenant admin narrows its own issuer: %d %s", w.Code, w.Body.String())
	}
	if got := stub.rows["https://tenant-a"].Stores; len(got) != 1 || got[0] != "a_mail" {
		t.Fatalf("stored row: %+v", stub.rows["https://tenant-a"])
	}
	if stub.by[0] != "user:alice via terraform-a" {
		t.Fatalf("performed_by: %q", stub.by[0])
	}
	w = put(tenantAAdmin, `{"issuer":"https://tenant-b","stores":["b_mail"],"enabled":true}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "manages the issuer https://tenant-a only") {
		t.Fatalf("another tenant's issuer: %d %s", w.Code, w.Body.String())
	}
	w = put(tenantAAdmin, `{"issuer":"https://tenant-a","stores":["b_docs"],"enabled":true}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "may only narrow") {
		t.Fatalf("widening past the environment: %d %s", w.Code, w.Body.String())
	}
	w = put(tenantAAdmin, `{"issuer":"https://tenant-a","stores":[],"enabled":true}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "stay bound") {
		t.Fatalf("unbinding: %d %s", w.Code, w.Body.String())
	}
	w = put(tenantAAdmin, `{"issuer":"https://tenant-a","stores":["a_("],"enabled":true}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid store pattern") {
		t.Fatalf("bad pattern: %d %s", w.Code, w.Body.String())
	}
	w = put(tenantAAdmin, `{"issuer":"https://tenant-a","stores":["a_docs"],"enabled":true,"bogus":1}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "bogus") {
		t.Fatalf("unknown field: %d %s", w.Code, w.Body.String())
	}
	w = put(platformAdmin, `{"issuer":"https://nobody","stores":["x"],"enabled":true}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "cannot add trust") {
		t.Fatalf("an untrusted issuer: %d %s", w.Code, w.Body.String())
	}
	w = put(platformAdmin, `{"issuer":"https://tenant-b","stores":["b_docs"],"enabled":false}`)
	if w.Code != 200 || stub.rows["https://tenant-b"].Enabled {
		t.Fatalf("platform admin pauses tenant b: %d %s", w.Code, w.Body.String())
	}
	w = put(roleAdmin, `{"issuer":"https://tenant-a","stores":["a_docs"],"enabled":true}`)
	if w.Code != 200 || stub.by[len(stub.by)-1] != "user:root" {
		t.Fatalf("ADMIN_ROLE manages every issuer: %d %s (by %q)", w.Code, w.Body.String(), stub.by[len(stub.by)-1])
	}

	// deletes
	del := func(tk token, q string) *httptest.ResponseRecorder {
		return do(h, h.adminDeleteIssuerBinding, tk.request("DELETE", "/pgauthz/v1/admin/issuer-bindings"+q, ""))
	}
	if w := del(tenantAAdmin, "?issuer=https://tenant-b"); w.Code != http.StatusForbidden {
		t.Fatalf("another tenant's binding: %d", w.Code)
	}
	if w := del(tenantAAdmin, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("no issuer: %d", w.Code)
	}
	if w := del(tenantAAdmin, "?issuer=https://tenant-a"); w.Code != 200 || !strings.Contains(w.Body.String(), `"deleted":true`) {
		t.Fatalf("own binding: %d %s", w.Code, w.Body.String())
	}
	if w := del(tenantAAdmin, "?issuer=https://tenant-a"); w.Code != http.StatusNotFound {
		t.Fatalf("gone: %d", w.Code)
	}
	if w := del(platformAdmin, "?issuer=https://tenant-b"); w.Code != 200 {
		t.Fatalf("platform admin deletes tenant b: %d", w.Code)
	}
	if len(stub.rows) != 0 {
		t.Fatalf("rows left: %v", stub.rows)
	}

	// a backend without the binding store
	h2 := NewHandler(nil, nil, freshStub{}, h.cfg, WithIssuers(h.issuers))
	if w := do(h2, h2.adminIssuerBindings, platformAdmin.request("GET", "/", "")); w.Code != http.StatusNotImplemented {
		t.Fatalf("without the direct backend: %d", w.Code)
	}
}

// Routing: the public mux mounts the admin routes only with the admin API
// on the public listener; the admin router serves management and health
// and nothing else.
func TestAdminRouting(t *testing.T) {
	h, _ := adminFixture(t)
	mux := newPublicMux(h, false)
	if !routeExists(mux, "GET", "/pgauthz/v1/admin/issuers") || !routeExists(mux, "PUT", "/pgauthz/v1/admin/issuer-bindings") {
		t.Fatal("admin API enabled without ADMIN_LISTEN_ADDR: the public mux must mount it")
	}
	h.cfg.AdminListenAddr = ":9093"
	if routeExists(newPublicMux(h, false), "GET", "/pgauthz/v1/admin/issuers") {
		t.Fatal("with ADMIN_LISTEN_ADDR the public mux must not mount the admin routes")
	}
	h.cfg.AdminListenAddr = ""
	h.cfg.AdminAPIEnabled = false
	if routeExists(newPublicMux(h, false), "GET", "/pgauthz/v1/admin/issuers") {
		t.Fatal("ADMIN_API_ENABLED=false: no admin routes")
	}
	h.cfg.AdminAPIEnabled = true
	h.cfg.HTTPMaxBodyBytes = 1 << 20
	amux := newAdminMux(h)
	for _, route := range []string{"POST /pgauthz/v1/check", "POST /access/v1/evaluation", "POST /pgauthz/v1/tuples", "GET /pgauthz/v1/issuers", "GET /metrics"} {
		m, p, _ := strings.Cut(route, " ")
		if routeExists(amux, m, p) {
			t.Errorf("the admin mux must not serve %s", route)
		}
	}
	mw := NewJWTMiddleware(JWTConfig{Set: h.issuers})
	adm := NewAdminRouter(h, mw)
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/livez", 200},
		{"GET", "/pgauthz/v1/admin/issuers", 401}, // the JWT middleware: no token
		{"POST", "/pgauthz/v1/check", 401},        // no native surface here, and no hint of it without a token
	} {
		w := httptest.NewRecorder()
		adm.ServeHTTP(w, httptest.NewRequest(c.method, c.path, nil))
		if w.Code != c.want {
			t.Errorf("%s %s: %d (want %d) %s", c.method, c.path, w.Code, c.want, w.Body.String())
		}
	}
}

// claimValues: a string, an array, a dotted path, and nothing.
func TestClaimValues(t *testing.T) {
	claims := jwt.MapClaims{"role": "ops", "realm_access": map[string]any{"roles": []any{"a", "b"}}, "groups": []string{"g1"}}
	if v := claimValues(claims, "role"); !v["ops"] || len(v) != 1 {
		t.Fatalf("string: %v", v)
	}
	if v := claimValues(claims, "realm_access.roles"); !v["a"] || !v["b"] {
		t.Fatalf("path: %v", v)
	}
	if v := claimValues(claims, "groups"); !v["g1"] {
		t.Fatalf("[]string: %v", v)
	}
	if v := claimValues(claims, "realm_access.nope.x"); len(v) != 0 {
		t.Fatalf("missing: %v", v)
	}
	var b strings.Builder
	json.NewEncoder(&b).Encode(claims)
	if ClaimsFromContext(context.Background()) != nil {
		t.Fatal("no claims without a token")
	}
}

// A client certificate the listener verified is a credential of its own:
// the JWT middleware lets the token-less request through, the gate maps it
// by cn / uri / subject to a scope, and writes are recorded as cert:<id>.
func TestAdminGateClientCertificate(t *testing.T) {
	h, stub := adminFixture(t)
	h.cfg.AdminClientCA = "/ca.pem" // set in the config; the TLS layer is the app's
	h.cfg.AdminClientCerts = []config.AdminClientCert{
		{CN: "terraform", Scope: "platform"},
		{URI: "spiffe://acme/ci/tenant-a", Scope: "issuer", Issuer: "https://tenant-a"},
		{Subject: "CN=auditor,O=acme"},
	}
	cert := func(cn string, org []string, uris ...string) *x509.Certificate {
		c := &x509.Certificate{Subject: pkix.Name{CommonName: cn, Organization: org}}
		for _, u := range uris {
			parsed, _ := url.Parse(u)
			c.URIs = append(c.URIs, parsed)
		}
		return c
	}
	withCert := func(c *x509.Certificate, method, target, body string) *http.Request {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		return r.WithContext(context.WithValue(r.Context(), ctxClientCert, c))
	}

	// cn → platform
	scope, err := h.adminGate(withCert(cert("terraform", nil), "GET", "/", ""))
	if err != nil || !scope.platform {
		t.Fatalf("cn mapping: %+v %v", scope, err)
	}
	// uri → one tenant
	scope, err = h.adminGate(withCert(cert("ci", nil, "spiffe://acme/ci/tenant-a"), "GET", "/", ""))
	if err != nil || scope.platform || scope.issuer != "https://tenant-a" {
		t.Fatalf("uri mapping: %+v %v", scope, err)
	}
	// full subject → platform (the default scope)
	scope, err = h.adminGate(withCert(cert("auditor", []string{"acme"}), "GET", "/", ""))
	if err != nil || !scope.platform {
		t.Fatalf("subject mapping: %+v %v", scope, err)
	}
	// an unmapped certificate is refused, and never falls back to the token gate
	if _, err := h.adminGate(withCert(cert("stranger", nil), "GET", "/", "")); err == nil || !strings.Contains(err.Error(), "not mapped") {
		t.Fatalf("unmapped: %v", err)
	}

	// a tenant certificate sees its issuer — it carries no iss, the mapping names it (review #20)
	w := do(h, h.adminIssuers, withCert(cert("ci", nil, "spiffe://acme/ci/tenant-a"), "GET", "/pgauthz/v1/admin/issuers", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "https://tenant-a") || strings.Contains(w.Body.String(), "tenant-b") || strings.Contains(w.Body.String(), "platform-idp") {
		t.Fatalf("tenant cert's issuer listing: %d %s", w.Code, w.Body.String())
	}
	w = do(h, h.adminIssuers, withCert(cert("terraform", nil), "GET", "/pgauthz/v1/admin/issuers", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "tenant-b") {
		t.Fatalf("platform cert's issuer listing: %d %s", w.Code, w.Body.String())
	}

	// a tenant certificate manages its own issuer only; the actor is the certificate
	w = do(h, h.adminSetIssuerBinding, withCert(cert("ci", nil, "spiffe://acme/ci/tenant-a"), "PUT", "/pgauthz/v1/admin/issuer-bindings",
		`{"issuer":"https://tenant-a","stores":["a_docs"],"enabled":true}`))
	if w.Code != 200 || stub.by[len(stub.by)-1] != "cert:spiffe://acme/ci/tenant-a" {
		t.Fatalf("tenant cert write: %d %s (by %v)", w.Code, w.Body.String(), stub.by)
	}
	w = do(h, h.adminSetIssuerBinding, withCert(cert("ci", nil, "spiffe://acme/ci/tenant-a"), "PUT", "/pgauthz/v1/admin/issuer-bindings",
		`{"issuer":"https://tenant-b","stores":["b_docs"],"enabled":true}`))
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant cert reaching another tenant: %d", w.Code)
	}
	w = do(h, h.adminIssuerBindings, withCert(cert("terraform", nil), "GET", "/pgauthz/v1/admin/issuer-bindings", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "tenant-b") {
		t.Fatalf("platform cert reads every binding: %d %s", w.Code, w.Body.String())
	}

	// the middleware: a token-less request passes only with AllowClientCert and a peer certificate
	mw := NewJWTMiddleware(JWTConfig{Set: h.issuers, AllowClientCert: true})
	seen := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = ClientCertFromContext(r.Context()) != nil })
	r := httptest.NewRequest("GET", "/pgauthz/v1/admin/issuers", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert("terraform", nil)}}
	rec := httptest.NewRecorder()
	mw.Middleware(next).ServeHTTP(rec, r)
	if rec.Code != 200 || !seen {
		t.Fatalf("verified certificate without a token: %d seen=%v", rec.Code, seen)
	}
	rec = httptest.NewRecorder()
	mw.Middleware(next).ServeHTTP(rec, httptest.NewRequest("GET", "/pgauthz/v1/admin/issuers", nil))
	if rec.Code != 401 {
		t.Fatalf("no certificate, no token: %d", rec.Code)
	}
	mw = NewJWTMiddleware(JWTConfig{Set: h.issuers}) // the public listener never accepts a certificate as a credential
	rec = httptest.NewRecorder()
	mw.Middleware(next).ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Fatalf("certificate on a listener without AllowClientCert: %d", rec.Code)
	}
}

// Group issuers over the admin API (ADR 0017): an unknown issuer is still
// refused as a plain binding, admitted as a group issuer (store group +
// anchor + audience) by platform scope or by a delegated credential the
// console store grants can_manage_issuers on that group; a static tenant
// admin never; the group's admins see and delete the row; a row for an
// environment issuer may not carry admin rules.
func TestAdminGroupIssuers(t *testing.T) {
	h, stub := storesFixture(t)
	stub.grants = map[string]bool{"user:carol can_manage_issuers group:tenant_c": true}
	plain := `{"issuer":"https://new-idp","stores":["x"],"enabled":true}`
	group := `{"issuer":"https://new-idp","store_group":"tenant_c","jwks_url":"https://new-idp/jwks","audience":"authz-api","enabled":true,"admin":[{"decide":{"store":"console"}}]}`
	if w := serveAdmin(h, platformAdmin.request("PUT", "/pgauthz/v1/admin/issuer-bindings", plain)); w.Code != 400 || !strings.Contains(w.Body.String(), "cannot add trust") {
		t.Fatalf("plain unknown: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, platformAdmin.request("PUT", "/pgauthz/v1/admin/issuer-bindings", group)); w.Code != 200 {
		t.Fatalf("platform adds a group issuer: %d %s", w.Code, w.Body.String())
	}
	if row := stub.rows["https://new-idp"]; row.StoreGroup != "tenant_c" || row.JWKSURL != "https://new-idp/jwks" || len(row.Admin) != 1 {
		t.Fatalf("the row keeps its group and anchor: %+v", row)
	}
	if w := serveAdmin(h, tenantAAdmin.request("PUT", "/pgauthz/v1/admin/issuer-bindings", group)); w.Code != http.StatusForbidden {
		t.Fatalf("static tenant adds a group issuer: %d %s", w.Code, w.Body.String())
	}
	// carol (delegated, tenant-c): the console store grants her the group's issuers
	if w := serveAdmin(h, tenantCUser.request("PUT", "/pgauthz/v1/admin/issuer-bindings", strings.Replace(group, "https://new-idp", "https://carol-idp", 2))); w.Code != 200 {
		t.Fatalf("group admin adds a group issuer: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCUser.request("PUT", "/pgauthz/v1/admin/issuer-bindings", strings.Replace(strings.Replace(group, "https://new-idp", "https://other-idp", 2), "tenant_c", "tenant_x", 1))); w.Code != http.StatusForbidden {
		t.Fatalf("group admin adds for another group: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCUser.request("GET", "/pgauthz/v1/admin/issuer-bindings", "")); w.Code != 200 || !strings.Contains(w.Body.String(), "https://carol-idp") || strings.Contains(w.Body.String(), "https://tenant-a") {
		t.Fatalf("group admin lists its group's rows: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCUser.request("DELETE", "/pgauthz/v1/admin/issuer-bindings?issuer=https://carol-idp", "")); w.Code != 200 {
		t.Fatalf("group admin deletes its row: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCUser.request("DELETE", "/pgauthz/v1/admin/issuer-bindings?issuer=https://tenant-a", "")); w.Code != http.StatusForbidden {
		t.Fatalf("group admin deletes another's row: %d %s", w.Code, w.Body.String())
	}
	// an anchor-less unknown issuer, and a group row without an audience
	// a host outside GROUP_ISSUER_HOSTS: the daemon would fetch keys from it (SSRF) — refused, even for the platform admin
	if w := serveAdmin(h, platformAdmin.request("PUT", "/pgauthz/v1/admin/issuer-bindings", strings.Replace(group, "https://new-idp/jwks", "https://10.0.0.5/jwks", 1))); w.Code != 400 || !strings.Contains(w.Body.String(), "not in GROUP_ISSUER_HOSTS") {
		t.Fatalf("jwks host outside the allow-list: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, platformAdmin.request("PUT", "/pgauthz/v1/admin/issuer-bindings", strings.Replace(group, "https://new-idp", "https://metadata.internal", 2))); w.Code != 400 || !strings.Contains(w.Body.String(), "not in GROUP_ISSUER_HOSTS") {
		t.Fatalf("issuer host outside the allow-list: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, platformAdmin.request("PUT", "/pgauthz/v1/admin/issuer-bindings", `{"issuer":"https://x","store_group":"tenant_c","enabled":true}`)); w.Code != 400 {
		t.Fatalf("group row without anchor for an unknown issuer: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, platformAdmin.request("PUT", "/pgauthz/v1/admin/issuer-bindings", `{"issuer":"https://tenant-a","stores":["a_docs"],"enabled":true,"admin":[{"clients":["tf"]}]}`)); w.Code != 400 || !strings.Contains(w.Body.String(), "delegate only") {
		t.Fatalf("static admin rules on a row: %d %s", w.Code, w.Body.String())
	}
}

// Aliases on the admin API: an issuer is referenced by its URL or its alias
// — the environment's (tenant-b) or a row's (tenant-a) — on the binding
// read, the audit filter and the delete; a PUT may name an existing issuer
// by alias and sets the alias; a taken alias is refused.
func TestAdminIssuerAlias(t *testing.T) {
	h, stub := adminFixture(t)
	w := do(h, h.adminIssuerBindings, platformAdmin.request("GET", "/pgauthz/v1/admin/issuer-bindings?issuer=TENANT-A", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"issuer":"https://tenant-a"`) {
		t.Fatalf("row alias: %d %s", w.Code, w.Body.String())
	}
	w = do(h, h.adminIssuerBindings, platformAdmin.request("GET", "/pgauthz/v1/admin/issuer-bindings?issuer=tenant-b", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"issuer":"https://tenant-b"`) {
		t.Fatalf("env alias: %d %s", w.Code, w.Body.String())
	}
	w = do(h, h.adminIssuerBindingsAudit, platformAdmin.request("GET", "/pgauthz/v1/admin/issuer-bindings/audit?issuer=tenant-b", ""))
	if w.Code != 200 || strings.Contains(w.Body.String(), "https://tenant-a") {
		t.Fatalf("audit by alias: %d %s", w.Code, w.Body.String())
	}
	// PUT by alias, setting a new alias; then the alias is taken
	w = do(h, h.adminSetIssuerBinding, platformAdmin.request("PUT", "/pgauthz/v1/admin/issuer-bindings", `{"issuer":"tenant-b","alias":"B-Corp","stores":["b_docs"],"enabled":true}`))
	if w.Code != 200 || stub.rows["https://tenant-b"].Alias != "b-corp" {
		t.Fatalf("put by alias: %d %s %+v", w.Code, w.Body.String(), stub.rows["https://tenant-b"])
	}
	w = do(h, h.adminSetIssuerBinding, platformAdmin.request("PUT", "/pgauthz/v1/admin/issuer-bindings", `{"issuer":"https://tenant-a","alias":"b-corp","stores":["a_docs"],"enabled":true}`))
	if w.Code != 400 || !strings.Contains(w.Body.String(), "already names") {
		t.Fatalf("taken alias: %d %s", w.Code, w.Body.String())
	}
	w = do(h, h.adminSetIssuerBinding, platformAdmin.request("PUT", "/pgauthz/v1/admin/issuer-bindings", `{"issuer":"no-such-alias","stores":["a_docs"],"enabled":true}`))
	if w.Code != 400 || !strings.Contains(w.Body.String(), "neither an issuer URL nor a known alias") {
		t.Fatalf("unknown alias: %d %s", w.Code, w.Body.String())
	}
	w = do(h, h.adminDeleteIssuerBinding, platformAdmin.request("DELETE", "/pgauthz/v1/admin/issuer-bindings?issuer=b-corp", ""))
	if w.Code != 200 {
		t.Fatalf("delete by alias: %d %s", w.Code, w.Body.String())
	}
	if _, still := stub.rows["https://tenant-b"]; still {
		t.Fatal("the row named by alias was not deleted")
	}
}

// Review P1/P2 — ownership of a binding row. A group's admins write the
// rows of THEIR group as they are: taking a row that belongs to another
// group by submitting their own group is refused, moving a row between
// groups is the platform's alone, a platform (environment) issuer cannot
// be claimed for a group, the engine's precondition turns a concurrent
// transfer into a 409, and a group's admins read the audit history of
// their group's issuer — only the rows written while it was theirs.
func TestAdminBindingOwnership(t *testing.T) {
	h, stub := storesFixture(t)
	stub.grants = map[string]bool{"user:carol can_manage_issuers group:tenant_c": true}
	put := func(tk token, body string) *httptest.ResponseRecorder {
		return serveAdmin(h, tk.request("PUT", "/pgauthz/v1/admin/issuer-bindings", body))
	}
	// a group issuer of tenant_x (another group), written by the platform
	stub.rows["https://x-idp"] = issuers.Binding{Issuer: "https://x-idp", StoreGroup: "tenant_x", JWKSURL: "https://x-idp/jwks", Audience: "a", Enabled: true}
	// carol (tenant_c) submits it with her own group: a takeover — refused
	if w := put(tenantCUser, `{"issuer":"https://x-idp","store_group":"tenant_c","jwks_url":"https://x-idp/jwks","audience":"a","enabled":true}`); w.Code != http.StatusForbidden {
		t.Fatalf("cross-group takeover: %d %s", w.Code, w.Body.String())
	}
	if stub.rows["https://x-idp"].StoreGroup != "tenant_x" {
		t.Fatal("the row must be untouched")
	}
	// the platform's own issuer (environment): carol cannot bind it to her group
	if w := put(tenantCUser, `{"issuer":"https://tenant-a","store_group":"tenant_c","enabled":true}`); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "platform") {
		t.Fatalf("claiming a platform issuer: %d %s", w.Code, w.Body.String())
	}
	// her own group's row she may change — but not move to another group
	stub.rows["https://c-idp"] = issuers.Binding{Issuer: "https://c-idp", StoreGroup: "tenant_c", JWKSURL: "https://c-idp/jwks", Audience: "a", Enabled: true}
	if w := put(tenantCUser, `{"issuer":"https://c-idp","store_group":"tenant_c","jwks_url":"https://c-idp/jwks","audience":"a","enabled":false}`); w.Code != 200 || stub.rows["https://c-idp"].Enabled {
		t.Fatalf("own row: %d %s", w.Code, w.Body.String())
	}
	if w := put(tenantCUser, `{"issuer":"https://c-idp","store_group":"tenant_x","jwks_url":"https://c-idp/jwks","audience":"a","enabled":true}`); w.Code != http.StatusForbidden || stub.rows["https://c-idp"].StoreGroup != "tenant_c" {
		t.Fatalf("moving own row away: %d %s", w.Code, w.Body.String())
	}
	// the platform moves it, having read it as tenant_c's
	if w := put(platformAdmin, `{"issuer":"https://c-idp","store_group":"tenant_x","jwks_url":"https://c-idp/jwks","audience":"a","enabled":true}`); w.Code != 200 || stub.rows["https://c-idp"].StoreGroup != "tenant_x" {
		t.Fatalf("platform transfer: %d %s", w.Code, w.Body.String())
	}
	// … after which carol's write of "her" row is refused (it is tenant_x's now)
	if w := put(tenantCUser, `{"issuer":"https://c-idp","store_group":"tenant_c","jwks_url":"https://c-idp/jwks","audience":"a","enabled":true}`); w.Code != http.StatusForbidden {
		t.Fatalf("after the transfer: %d %s", w.Code, w.Body.String())
	}
	// a concurrent transfer between the handler's read and the engine's write: 409, nothing written
	stub.rows["https://race-idp"] = issuers.Binding{Issuer: "https://race-idp", StoreGroup: "tenant_c", JWKSURL: "https://race-idp/jwks", Audience: "a", Enabled: true}
	racing := &racingStub{storeStub: stub, flip: "https://race-idp"}
	hr := NewHandler(nil, nil, racing, h.cfg, WithIssuers(h.issuers))
	if w := serveAdmin(hr, tenantCUser.request("PUT", "/pgauthz/v1/admin/issuer-bindings", `{"issuer":"https://race-idp","store_group":"tenant_c","jwks_url":"https://race-idp/jwks","audience":"a","enabled":false}`)); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "ownership_changed") {
		t.Fatalf("race: %d %s", w.Code, w.Body.String())
	}
	if !stub.rows["https://race-idp"].Enabled || stub.rows["https://race-idp"].StoreGroup != "tenant_x" {
		t.Fatalf("the racing write must not land: %+v", stub.rows["https://race-idp"])
	}
	// the delete carries the same precondition
	stub.rows["https://race-idp"] = issuers.Binding{Issuer: "https://race-idp", StoreGroup: "tenant_c", Enabled: true}
	if w := serveAdmin(hr, tenantCUser.request("DELETE", "/pgauthz/v1/admin/issuer-bindings?issuer=https://race-idp", "")); w.Code != http.StatusConflict {
		t.Fatalf("racing delete: %d %s", w.Code, w.Body.String())
	}
	// P2: carol reads her group's issuer's history — the tenant_c rows only, not what tenant_x did with it
	stub.rows["https://group-idp"] = issuers.Binding{Issuer: "https://group-idp", StoreGroup: "tenant_c", Enabled: true}
	w := serveAdmin(h, tenantCUser.request("GET", "/pgauthz/v1/admin/issuer-bindings/audit?issuer=https://group-idp", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"store_group":"tenant_c"`) || strings.Contains(w.Body.String(), `"store_group":"tenant_x"`) || !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("group admin reads its history: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, tenantCUser.request("GET", "/pgauthz/v1/admin/issuer-bindings/audit?issuer=https://x-idp", "")); w.Code != http.StatusForbidden {
		t.Fatalf("another group's history: %d %s", w.Code, w.Body.String())
	}
	// no issuer named: her own issuer's history (the delegated scope's), as before
	if w := serveAdmin(h, tenantCUser.request("GET", "/pgauthz/v1/admin/issuer-bindings/audit", "")); w.Code != 200 || !strings.Contains(w.Body.String(), `"issuer":"https://tenant-c"`) {
		t.Fatalf("no issuer named: %d %s", w.Code, w.Body.String())
	}
	if w := serveAdmin(h, platformAdmin.request("GET", "/pgauthz/v1/admin/issuer-bindings/audit?issuer=https://group-idp", "")); w.Code != 200 || !strings.Contains(w.Body.String(), `"total":2`) {
		t.Fatalf("platform reads all of it: %d %s", w.Code, w.Body.String())
	}
}

// racingStub flips one row to another group between the handler's read and
// the engine's write — the concurrent transfer the precondition catches.
type racingStub struct {
	*storeStub
	flip string
}

func (r *racingStub) SetIssuerBinding(ctx context.Context, b issuers.Binding, by, expectGroup string) (int64, error) {
	if b.Issuer == r.flip {
		row := r.rows[r.flip]
		row.StoreGroup = "tenant_x"
		r.rows[r.flip] = row
	}
	return r.storeStub.SetIssuerBinding(ctx, b, by, expectGroup)
}

func (r *racingStub) DeleteIssuerBinding(ctx context.Context, issuer, by, expectGroup string) (bool, error) {
	if issuer == r.flip {
		row := r.rows[r.flip]
		row.StoreGroup = "tenant_x"
		r.rows[r.flip] = row
	}
	return r.storeStub.DeleteIssuerBinding(ctx, issuer, by, expectGroup)
}
