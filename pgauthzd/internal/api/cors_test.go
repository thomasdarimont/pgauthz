package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Public endpoints answer any origin (no credentials, public by design); the
// authenticated surface answers only configured origins, and a preflight for
// one is answered before authentication. Anything else gets no CORS headers.
func TestCORS(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	serve := func(allowed []string, method, path, origin, requestMethod string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if requestMethod != "" {
			r.Header.Set("Access-Control-Request-Method", requestMethod)
			r.Header.Set("Access-Control-Request-Headers", "authorization, x-pgauthz-store")
		}
		w := httptest.NewRecorder()
		CORS(allowed)(inner).ServeHTTP(w, r)
		return w
	}

	// no Origin: not a cross-origin request, untouched
	if w := serve(nil, http.MethodGet, "/.well-known/authzen-configuration", "", ""); w.Header().Get("Access-Control-Allow-Origin") != "" || w.Code != http.StatusTeapot {
		t.Fatalf("no origin: %v %d", w.Header(), w.Code)
	}
	// public endpoints: any origin, even with no allow-list
	for _, p := range []string{"/.well-known/authzen-configuration", "/.well-known/authzen-configuration/stores/t1", "/stores/t1/.well-known/authzen-configuration", "/pgauthz/v1/openapi.json", "/readyz"} {
		if w := serve(nil, http.MethodGet, p, "http://localhost:8095", ""); w.Header().Get("Access-Control-Allow-Origin") != "*" || w.Code != http.StatusTeapot {
			t.Fatalf("public %s: %v %d", p, w.Header(), w.Code)
		}
	}
	// authenticated surface, origin not allowed: no CORS headers, request still served
	if w := serve(nil, http.MethodPost, "/access/v1/evaluation", "http://localhost:8095", ""); w.Header().Get("Access-Control-Allow-Origin") != "" || w.Code != http.StatusTeapot {
		t.Fatalf("disallowed origin: %v %d", w.Header(), w.Code)
	}
	// allowed origin: echoed, with Vary and the exposed headers
	w := serve([]string{"http://localhost:8095"}, http.MethodPost, "/access/v1/evaluation", "http://localhost:8095", "")
	if w.Header().Get("Access-Control-Allow-Origin") != "http://localhost:8095" || w.Header().Get("Vary") != "Origin" || w.Header().Get("Access-Control-Expose-Headers") == "" || w.Code != http.StatusTeapot {
		t.Fatalf("allowed origin: %v %d", w.Header(), w.Code)
	}
	// preflight for an allowed origin: 204 before the handler, requested headers echoed
	w = serve([]string{"http://localhost:8095"}, http.MethodOptions, "/access/v1/evaluation", "http://localhost:8095", "POST")
	if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Headers") != "authorization, x-pgauthz-store" || w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatalf("preflight: %v %d", w.Header(), w.Code)
	}
	// preflight for a disallowed origin falls through (the mux answers it, not us)
	if w := serve([]string{"http://localhost:8095"}, http.MethodOptions, "/access/v1/evaluation", "https://evil.example", "POST"); w.Code != http.StatusTeapot || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("disallowed preflight: %v %d", w.Header(), w.Code)
	}
	// "*" allows any origin on the authenticated surface too
	if w := serve([]string{"*"}, http.MethodPost, "/access/v1/evaluation", "https://app.example", ""); w.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("wildcard: %v", w.Header())
	}
}

// The JWT middleware's exemption list and CORS's notion of "public" are the
// same predicate.
func TestPublicPaths(t *testing.T) {
	for p, want := range map[string]bool{
		"/healthz": true, "/livez": true, "/readyz": true,
		"/.well-known/authzen-configuration":              true,
		"/.well-known/authzen-configuration/stores/demo":  true,
		"/stores/demo/.well-known/authzen-configuration":  true,
		"/pgauthz/v1/openapi.json":                        true,
		"/pgauthz/v1/openapi.yaml":                        true,
		"/access/v1/evaluation":                           false,
		"/stores/demo/access/v1/evaluation":               false,
		"/pgauthz/v1/check":                               false,
		"/stores/demo/.well-known/authzen-configurationx": false,
	} {
		if got := isPublicPath(p); got != want {
			t.Fatalf("isPublicPath(%q) = %v, want %v", p, got, want)
		}
	}
}
