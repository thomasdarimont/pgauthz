package api

import (
	"embed"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// Swagger UI for the served OpenAPI document, embedded (SWAGGER_UI_ENABLED,
// default off): GET /pgauthz/v1/docs renders the UI, GET /pgauthz/v1/docs/{asset}
// serves its vendored assets (internal/api/swaggerui — swagger-ui-dist pinned
// by scripts/vendor-swagger-ui.sh, Apache-2.0). Same origin as the API, so
// "Try it out" needs no CORS; the page's CSP allows scripts and styles from
// this origin only (Swagger UI needs inline STYLES, not inline scripts — the
// initializer is a separate file). Public like the document it renders. With
// SWAGGER_UI_OIDC_ISSUER/CLIENT_ID the Authorize dialog also offers an OIDC
// login (authorization code + PKCE) whose redirect page, oauth2-redirect.html,
// is served from here as well.

//go:embed swaggerui/*
var swaggerUIFiles embed.FS

const swaggerUIPath = "/pgauthz/v1/docs"

// swaggerUIIndex is the page; absolute paths so that /pgauthz/v1/docs and
// /pgauthz/v1/docs/ resolve the same assets.
const swaggerUIIndex = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>pgauthzd API</title>
  <link rel="icon" type="image/png" href="/pgauthz/v1/docs/favicon-32x32.png">
  <link rel="stylesheet" href="/pgauthz/v1/docs/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="/pgauthz/v1/docs/swagger-ui-bundle.js" charset="UTF-8"></script>
  <script src="/pgauthz/v1/docs/pgauthz-initializer.js" charset="UTF-8"></script>
</body>
</html>
`

// swaggerUIInitializer configures the UI: this instance's served document (its
// `servers` entry is stamped with the public base URL), deep links, and the
// credentials kept across reloads so Authorize is a one-time step. With
// SWAGGER_UI_OIDC_* set it also wires the authorization code + PKCE login:
// the redirect page is the vendored oauth2-redirect.html on this origin and
// initOAuth names the public client — rendered per request, since the redirect
// URL carries the public base.
func (h *Handler) swaggerUIInitializer(r *http.Request) string {
	var b strings.Builder
	b.WriteString("window.onload = function () {\n  window.ui = SwaggerUIBundle({\n")
	b.WriteString("    url: \"/pgauthz/v1/openapi.json\",\n    dom_id: \"#swagger-ui\",\n")
	b.WriteString("    deepLinking: true,\n    persistAuthorization: true,\n    tryItOutEnabled: true,\n")
	b.WriteString("    displayRequestDuration: true,\n    defaultModelsExpandDepth: 0,\n")
	if h.cfg.SwaggerUIOIDC() {
		b.WriteString("    oauth2RedirectUrl: " + jsString(h.publicBaseURL(r)+swaggerUIPath+"/oauth2-redirect.html") + ",\n")
	}
	b.WriteString("    presets: [SwaggerUIBundle.presets.apis],\n    layout: \"BaseLayout\"\n  });\n")
	if h.cfg.SwaggerUIOIDC() {
		b.WriteString("  window.ui.initOAuth({\n")
		b.WriteString("    clientId: " + jsString(h.cfg.SwaggerUIOIDCClientID) + ",\n")
		b.WriteString("    scopes: " + jsString(h.cfg.SwaggerUIOIDCScopes) + ",\n")
		b.WriteString("    usePkceWithAuthorizationCodeGrant: true\n  });\n")
	}
	b.WriteString("};\n")
	return b.String()
}

// jsString is a JSON string literal, which is also a JavaScript one.
func jsString(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}

var swaggerUIContentTypes = map[string]string{
	".css":  "text/css; charset=utf-8",
	".js":   "application/javascript; charset=utf-8",
	".png":  "image/png",
	".txt":  "text/plain; charset=utf-8",
	"":      "text/plain; charset=utf-8", // LICENSE, NOTICE, VERSION
	".html": "text/html; charset=utf-8",
}

// SwaggerUI — GET /pgauthz/v1/docs: the page. Its CSP lets the UI talk to this
// origin only — plus, with the OIDC login configured, the issuer: the UI
// fetches the provider's discovery document and calls its token endpoint from
// the browser (the login itself is a popup, not a fetch).
func (h *Handler) SwaggerUI(w http.ResponseWriter, r *http.Request) {
	connect := "'self'"
	if h.cfg.SwaggerUIOIDC() {
		if u, err := url.Parse(h.cfg.SwaggerUIOIDCIssuer); err == nil && u.Scheme != "" && u.Host != "" {
			connect += " " + u.Scheme + "://" + u.Host
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src "+connect)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(swaggerUIIndex))
}

// SwaggerUIAsset — GET /pgauthz/v1/docs/{asset}: the vendored files and the
// initializer. Only plain file names are served (no path separators), so the
// embedded directory is the whole exposure.
func (h *Handler) SwaggerUIAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("asset")
	if name == "" || strings.ContainsAny(name, "/\\") || strings.HasPrefix(name, ".") {
		http.NotFound(w, r)
		return
	}
	var data []byte
	if name == "pgauthz-initializer.js" {
		data = []byte(h.swaggerUIInitializer(r))
	} else {
		var err error
		if data, err = swaggerUIFiles.ReadFile("swaggerui/" + name); err != nil {
			http.NotFound(w, r)
			return
		}
	}
	ct, ok := swaggerUIContentTypes[strings.ToLower(path.Ext(name))]
	if !ok {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
