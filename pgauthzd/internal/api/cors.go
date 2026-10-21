package api

import (
	"net/http"
	"strings"
)

// isPublicPath reports whether a path is served without authentication: the
// health probes, AuthZEN discovery (both tenant forms), the OpenAPI document
// and the Swagger UI that renders it. The JWT middleware exempts exactly these,
// and CORS answers any origin for them.
func isPublicPath(path string) bool {
	return isHealthPath(path) ||
		strings.HasPrefix(path, "/.well-known/") ||
		path == "/pgauthz/v1/openapi.json" || path == "/pgauthz/v1/openapi.yaml" ||
		path == swaggerUIPath || strings.HasPrefix(path, swaggerUIPath+"/") ||
		(strings.HasPrefix(path, "/stores/") && strings.HasSuffix(path, "/.well-known/authzen-configuration"))
}

// corsExposedHeaders are the response headers a browser client may read.
const corsExposedHeaders = "X-Request-ID, X-PGAuthz-Served-By, X-PGAuthz-Revision, X-PGAuthz-Revision-Status, X-PGAuthz-Stale"

// corsDefaultRequestHeaders is what a preflight is allowed when it does not
// ask for specific headers.
const corsDefaultRequestHeaders = "Authorization, Content-Type, X-Request-ID, X-PGAuthz-Store, X-PGAuthz-Detail, X-PGAuthz-Consistency, X-PGAuthz-Revision"

// CORS answers browser cross-origin requests. The PUBLIC endpoints
// (isPublicPath — discovery, health, the OpenAPI document) answer any origin:
// they carry no credentials and are public by design, which is what lets a
// Swagger UI on another port load the document and try discovery. The
// AUTHENTICATED surface answers only the configured origins
// (CORS_ALLOWED_ORIGINS; "*" for any) — a browser-based PEP, or Swagger UI's
// "Try it out" — echoing the origin and answering the preflight before the
// JWT middleware sees it (a preflight carries no Authorization). An origin
// not on the list gets no CORS headers at all, so the browser refuses the
// response; the request itself is still authenticated and answered as usual.
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, o := range allowedOrigins {
		allowed[strings.TrimRight(strings.TrimSpace(o), "/")] = true
	}
	any := allowed["*"]
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			preflight := r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
			h := w.Header()
			switch {
			case isPublicPath(r.URL.Path):
				h.Set("Access-Control-Allow-Origin", "*")
				h.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Accept, Content-Type")
			case any || allowed[strings.TrimRight(origin, "/")]:
				h.Set("Access-Control-Allow-Origin", origin)
				h.Add("Vary", "Origin")
				h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				requested := r.Header.Get("Access-Control-Request-Headers")
				if requested == "" {
					requested = corsDefaultRequestHeaders
				}
				h.Set("Access-Control-Allow-Headers", requested)
				h.Set("Access-Control-Expose-Headers", corsExposedHeaders)
				h.Set("Access-Control-Max-Age", "600")
			default:
				next.ServeHTTP(w, r)
				return
			}
			if preflight {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
