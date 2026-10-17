package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

// The embedded Swagger UI is a developer convenience behind SWAGGER_UI_ENABLED:
// off, the routes do not exist; on, the page and exactly the vendored assets
// are served, same-origin, with a CSP that allows no foreign scripts.
func TestSwaggerUI(t *testing.T) {
	get := func(enabled bool, p string) *httptest.ResponseRecorder {
		h := NewHandler(nil, nil, nil, &config.Config{OpenAPIEnabled: true, SwaggerUIEnabled: enabled})
		w := httptest.NewRecorder()
		newPublicMux(h, false).ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		return w
	}

	// disabled: not registered at all
	for _, p := range []string{"/pgauthz/v1/docs", "/pgauthz/v1/docs/swagger-ui.css"} {
		if w := get(false, p); w.Code != http.StatusNotFound {
			t.Fatalf("disabled %s: want 404, got %d", p, w.Code)
		}
	}

	// the page: html, strict CSP, references only our own assets
	w := get(true, "/pgauthz/v1/docs")
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("page: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("CSP must allow only same-origin scripts: %q", csp)
	}
	body := w.Body.String()
	for _, ref := range []string{"/pgauthz/v1/docs/swagger-ui.css", "/pgauthz/v1/docs/swagger-ui-bundle.js", "/pgauthz/v1/docs/pgauthz-initializer.js"} {
		if !strings.Contains(body, ref) {
			t.Fatalf("page does not reference %s", ref)
		}
	}
	if strings.Contains(body, "http://") || strings.Contains(body, "https://") || strings.Contains(body, "<script>") {
		t.Fatalf("page must load nothing remote and run no inline script:\n%s", body)
	}

	// the assets: vendored files with their types, the initializer pointing at
	// the served document, licence files along for the ride
	for p, ct := range map[string]string{
		"/pgauthz/v1/docs/swagger-ui.css":                   "text/css",
		"/pgauthz/v1/docs/swagger-ui-bundle.js":             "application/javascript",
		"/pgauthz/v1/docs/pgauthz-initializer.js":           "application/javascript",
		"/pgauthz/v1/docs/favicon-32x32.png":                "image/png",
		"/pgauthz/v1/docs/LICENSE":                          "text/plain",
		"/pgauthz/v1/docs/swagger-ui-bundle.js.LICENSE.txt": "text/plain",
	} {
		w := get(true, p)
		if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), ct) || w.Body.Len() == 0 {
			t.Fatalf("%s: %d %s %d bytes", p, w.Code, w.Header().Get("Content-Type"), w.Body.Len())
		}
	}
	if w := get(true, "/pgauthz/v1/docs/pgauthz-initializer.js"); !strings.Contains(w.Body.String(), `url: "/pgauthz/v1/openapi.json"`) {
		t.Fatalf("initializer must load the served document: %s", w.Body.String())
	}
	if w := get(true, "/pgauthz/v1/docs/swagger-ui-bundle.js"); w.Body.Len() < 1_000_000 {
		t.Fatalf("bundle looks truncated: %d bytes", w.Body.Len())
	}

	// nothing but the vendored files
	for _, p := range []string{"/pgauthz/v1/docs/nope.js", "/pgauthz/v1/docs/..%2Fopenapi.go", "/pgauthz/v1/docs/.hidden"} {
		if w := get(true, p); w.Code != http.StatusNotFound {
			t.Fatalf("%s: want 404, got %d", p, w.Code)
		}
	}

	// public: served without a token
	if !isPublicPath("/pgauthz/v1/docs") || !isPublicPath("/pgauthz/v1/docs/swagger-ui.css") {
		t.Fatal("the UI and its assets must be public, like the document they render")
	}
}

// The served document names this instance as its server, so a UI that loaded
// it calls pgauthzd, not its own origin.
func TestOpenAPIServersAreStamped(t *testing.T) {
	h := NewHandler(nil, nil, nil, &config.Config{OpenAPIEnabled: true, TrustForwardedHeaders: true})
	r := httptest.NewRequest(http.MethodGet, "http://pgauthzd.internal:8080/pgauthz/v1/openapi.json", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "pdp.example.com")
	w := httptest.NewRecorder()
	h.OpenAPIJSON(w, r)
	if !strings.Contains(w.Body.String(), `"url":"https://pdp.example.com"`) {
		t.Fatalf("servers not stamped: %s", snippet(w.Body.String(), `"servers"`))
	}
	w = httptest.NewRecorder()
	h.OpenAPIYAML(w, httptest.NewRequest(http.MethodGet, "http://localhost:8090/pgauthz/v1/openapi.yaml", nil))
	if !strings.Contains(w.Body.String(), "url: http://localhost:8090\n") {
		t.Fatalf("yaml servers not stamped: %s", snippet(w.Body.String(), "servers:"))
	}
}

func snippet(s, around string) string {
	i := strings.Index(s, around)
	if i < 0 {
		return "(no " + around + " in document)"
	}
	end := i + 200
	if end > len(s) {
		end = len(s)
	}
	return s[i:end]
}

// With SWAGGER_UI_OIDC_* configured, the served document offers an `oidc`
// security scheme (the issuer's discovery URL) next to the bearer token on
// every authenticated operation, public operations stay public, and the UI's
// initializer wires the authorization code + PKCE login with the same-origin
// redirect page. Without it, nothing of that appears.
func TestSwaggerUIOIDC(t *testing.T) {
	oidc := &config.Config{OpenAPIEnabled: true, SwaggerUIEnabled: true,
		SwaggerUIOIDCIssuer: "https://id.pgauthz.test/realms/pgauthz", SwaggerUIOIDCClientID: "swagger-ui", SwaggerUIOIDCScopes: "openid"}
	plain := &config.Config{OpenAPIEnabled: true, SwaggerUIEnabled: true}

	get := func(cfg *config.Config, p string) string {
		h := NewHandler(nil, nil, nil, cfg)
		w := httptest.NewRecorder()
		newPublicMux(h, false).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://localhost:8091"+p, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", p, w.Code)
		}
		return w.Body.String()
	}

	var doc struct {
		Security   []map[string]any `json:"security"`
		Components struct {
			SecuritySchemes map[string]map[string]any `json:"securitySchemes"`
		} `json:"components"`
		Paths map[string]map[string]struct {
			Security []map[string]any `json:"security"`
		} `json:"paths"`
	}
	if err := json.Unmarshal([]byte(get(oidc, "/pgauthz/v1/openapi.json")), &doc); err != nil {
		t.Fatal(err)
	}
	scheme := doc.Components.SecuritySchemes["oidc"]
	if scheme["type"] != "openIdConnect" || scheme["openIdConnectUrl"] != "https://id.pgauthz.test/realms/pgauthz/.well-known/openid-configuration" {
		t.Fatalf("oidc scheme: %v", scheme)
	}
	// with the endpoints configured: ONE flow, authorization code, the requested scopes
	explicit := *oidc
	explicit.SwaggerUIOIDCAuthorizationURL = "https://id.pgauthz.test/realms/pgauthz/protocol/openid-connect/auth"
	explicit.SwaggerUIOIDCTokenURL = "https://id.pgauthz.test/realms/pgauthz/protocol/openid-connect/token"
	explicit.SwaggerUIOIDCScopes = "openid profile"
	var doc2 struct {
		Components struct {
			SecuritySchemes map[string]struct {
				Type  string `json:"type"`
				Flows map[string]struct {
					AuthorizationURL string            `json:"authorizationUrl"`
					TokenURL         string            `json:"tokenUrl"`
					Scopes           map[string]string `json:"scopes"`
				} `json:"flows"`
			} `json:"securitySchemes"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(get(&explicit, "/pgauthz/v1/openapi.json")), &doc2); err != nil {
		t.Fatal(err)
	}
	sch := doc2.Components.SecuritySchemes["oidc"]
	flow, ok := sch.Flows["authorizationCode"]
	if sch.Type != "oauth2" || len(sch.Flows) != 1 || !ok || flow.TokenURL != explicit.SwaggerUIOIDCTokenURL || len(flow.Scopes) != 2 {
		t.Fatalf("explicit oauth2 scheme: %+v", sch)
	}
	hasOIDC := func(sec []map[string]any) bool {
		for _, s := range sec {
			if _, ok := s["oidc"]; ok {
				return true
			}
		}
		return false
	}
	// most operations inherit the root requirement; it must now offer oidc too
	if !hasOIDC(doc.Security) {
		t.Fatalf("root security must offer oidc: %v", doc.Security)
	}
	for p, ops := range doc.Paths {
		for m, op := range ops {
			if len(op.Security) > 0 && !hasOIDC(op.Security) {
				t.Fatalf("%s %s names its own requirements but not oidc: %v", m, p, op.Security)
			}
		}
	}
	if len(doc.Paths["/.well-known/authzen-configuration"]["get"].Security) != 0 {
		t.Fatalf("public operations stay public: %v", doc.Paths["/.well-known/authzen-configuration"]["get"].Security)
	}
	// the YAML form too
	if y := get(oidc, "/pgauthz/v1/openapi.yaml"); !strings.Contains(y, "openIdConnectUrl: https://id.pgauthz.test/realms/pgauthz/.well-known/openid-configuration") {
		t.Fatalf("yaml lacks the oidc scheme")
	}
	// without the configuration: no scheme, no alternative
	if j := get(plain, "/pgauthz/v1/openapi.json"); strings.Contains(j, `"oidc"`) {
		t.Fatal("oidc scheme must not appear unconfigured")
	}

	// the page's CSP must let the UI reach the issuer (discovery + token endpoint)
	{
		h := NewHandler(nil, nil, nil, oidc)
		w := httptest.NewRecorder()
		newPublicMux(h, false).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/pgauthz/v1/docs", nil))
		if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "connect-src 'self' https://id.pgauthz.test") {
			t.Fatalf("CSP must allow the issuer origin: %q", csp)
		}
	}

	init := get(oidc, "/pgauthz/v1/docs/pgauthz-initializer.js")
	for _, want := range []string{`oauth2RedirectUrl: "http://localhost:8091/pgauthz/v1/docs/oauth2-redirect.html"`, `clientId: "swagger-ui"`, `scopes: "openid"`, "usePkceWithAuthorizationCodeGrant: true"} {
		if !strings.Contains(init, want) {
			t.Fatalf("initializer lacks %s:\n%s", want, init)
		}
	}
	if init := get(plain, "/pgauthz/v1/docs/pgauthz-initializer.js"); strings.Contains(init, "initOAuth") || strings.Contains(init, "oauth2RedirectUrl") {
		t.Fatalf("unconfigured initializer must not set up OAuth:\n%s", init)
	}
	// the redirect page and its script are served (vendored with the UI)
	for _, p := range []string{"/pgauthz/v1/docs/oauth2-redirect.html", "/pgauthz/v1/docs/oauth2-redirect.js"} {
		if body := get(oidc, p); !strings.Contains(body, "oauth2-redirect.js") && !strings.Contains(body, "swaggerUIRedirectOauth2") {
			t.Fatalf("%s: unexpected content %q", p, body[:min(60, len(body))])
		}
	}
}
