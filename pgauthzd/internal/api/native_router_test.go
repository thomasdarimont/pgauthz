package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

// routeExists reports whether mux has a handler registered for method+path
// (ServeMux.Handler returns an empty pattern when nothing matches).
func routeExists(mux *http.ServeMux, method, path string) bool {
	_, pattern := mux.Handler(httptest.NewRequest(method, path, nil))
	return pattern != ""
}

// The compat-opa listener split must hold structurally: the EXTERNAL surface
// carries AuthZEN (policy-wrapped) but never the native raw endpoints, and the
// INTERNAL surface carries the native raw endpoints (policy-free) but never
// AuthZEN. This is what keeps the raw graph path from being an external policy
// bypass and prevents OPA re-entering its own policy-wrapped surface.
func TestCompatRouterSeparation(t *testing.T) {
	h := &Handler{cfg: &config.Config{}}

	ext := http.NewServeMux()
	registerAuthZEN(ext, h)
	if !routeExists(ext, "POST", "/access/v1/evaluation") {
		t.Error("external: /access/v1/evaluation should be registered")
	}
	if routeExists(ext, "POST", "/pgauthz/v1/check") {
		t.Error("external: /pgauthz/v1/check must NOT be exposed (policy bypass)")
	}
	if routeExists(ext, "POST", "/pgauthz/v1/list-objects") {
		t.Error("external: /pgauthz/v1/list-objects must NOT be exposed")
	}

	intl := http.NewServeMux()
	registerNativeRead(intl, h)
	if !routeExists(intl, "POST", "/pgauthz/v1/check") {
		t.Error("internal: /pgauthz/v1/check should be registered")
	}
	if !routeExists(intl, "POST", "/pgauthz/v1/list-subjects") {
		t.Error("internal: /pgauthz/v1/list-subjects should be registered")
	}
	if routeExists(intl, "POST", "/access/v1/evaluation") {
		t.Error("internal: /access/v1/evaluation must NOT be on the internal listener")
	}
}

// The callback listener's handler has a nil AuthZEN backend; /healthz must not
// panic dereferencing it (regression: Helm k3d probe on :8081).
func TestCallbackHealthzNilBackend(t *testing.T) {
	h := &Handler{cfg: &config.Config{}} // backend/raw/rawWrite all nil
	w := httptest.NewRecorder()
	h.Healthz(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("nil-backend healthz: got %d, want 200", w.Code)
	}
}
