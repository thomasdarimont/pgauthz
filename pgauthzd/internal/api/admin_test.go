package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
	"thomasdarimont.de/authz/pgauthzd/pkg/issuers"
)

// adminStub is the binding store behind the admin API in these tests.
type adminStub struct {
	authz.Backend
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

func (s *adminStub) SetIssuerBinding(_ context.Context, b issuers.Binding, by string) (int64, error) {
	s.rows[b.Issuer] = b
	s.rev++
	s.by = append(s.by, by)
	return s.rev, nil
}

func (s *adminStub) DeleteIssuerBinding(_ context.Context, issuer, by string) (bool, error) {
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
			Admin: &issuers.AdminBinding{Scopes: []string{"pgauthz:admin"}, Claims: map[string][]string{"realm_access.roles": {"platform-admin"}}, Scope: issuers.AdminScopePlatform}},
		{Issuer: "https://tenant-a", Audience: "api", JWKSURL: "https://tenant-a/jwks", Stores: []string{"a_.*"},
			Admin: &issuers.AdminBinding{Clients: []string{"terraform-a"}}},
		{Issuer: "https://tenant-b", Audience: "api", JWKSURL: "https://tenant-b/jwks", Stores: []string{"b_.*"}},
	}
	cfg := &config.Config{Profile: config.ProfileFull, Issuers: env, IssuersSource: "env+db", AdminAPIEnabled: true, AdminRole: "pgauthz_admin"}
	stub := &adminStub{rows: map[string]issuers.Binding{
		"https://tenant-a": {Issuer: "https://tenant-a", Stores: []string{"a_docs"}, Enabled: true},
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
	platformAdmin = token{iss: "https://platform-idp", sub: "ops", scope: "openid pgauthz:admin", claims: jwt.MapClaims{"realm_access": map[string]any{"roles": []any{"platform-admin"}}}}
	tenantAAdmin  = token{iss: "https://tenant-a", sub: "alice", client: "terraform-a"}
	tenantAUser   = token{iss: "https://tenant-a", sub: "bob", client: "docs-app"}
	tenantBUser   = token{iss: "https://tenant-b", sub: "carol"}
	roleAdmin     = token{iss: "https://tenant-b", sub: "root", roles: []string{"pgauthz_admin"}}
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
	w = do(h, h.adminIssuers, platformAdmin.request("GET", "/pgauthz/v1/admin/issuers", ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"admin":{"scopes":["pgauthz:admin"]`) || !strings.Contains(w.Body.String(), "tenant-b") {
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

	// a tenant certificate manages its own issuer only; the actor is the certificate
	w := do(h, h.adminSetIssuerBinding, withCert(cert("ci", nil, "spiffe://acme/ci/tenant-a"), "PUT", "/pgauthz/v1/admin/issuer-bindings",
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
