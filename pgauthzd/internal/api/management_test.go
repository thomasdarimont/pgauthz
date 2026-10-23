package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

// The management listener serves /metrics and the probes; the public mux
// keeps the probes unless PUBLIC_HEALTH_ENABLED=false, and the served
// OpenAPI document says so.
func TestManagementListenerAndPublicHealth(t *testing.T) {
	h := &Handler{cfg: &config.Config{Profile: config.ProfileFull, OpenAPIEnabled: true}}
	mgmt := NewManagementRouter(h, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("# metrics")) }))
	for _, c := range []struct {
		path string
		want int
	}{{"/metrics", 200}, {"/livez", 200}, {"/readyz", 200}, {"/healthz", 200}, {"/pgauthz/v1/check", 404}, {"/access/v1/evaluation", 404}} {
		w := httptest.NewRecorder()
		mgmt.ServeHTTP(w, httptest.NewRequest("GET", c.path, nil))
		if w.Code != c.want {
			t.Errorf("management %s: %d (want %d)", c.path, w.Code, c.want)
		}
	}

	// the public mux: probes by default …
	pub := newPublicMux(h, false)
	for _, p := range []string{"/livez", "/readyz", "/healthz"} {
		if !routeExists(pub, "GET", p) {
			t.Errorf("public %s missing by default", p)
		}
	}
	// … and gone with PUBLIC_HEALTH_ENABLED=false, from the served document too
	h.cfg.PublicHealthDisabled = true
	h.cfg.MetricsListenAddr = ":9090"
	pub = newPublicMux(h, false)
	for _, p := range []string{"/livez", "/readyz", "/healthz"} {
		if routeExists(pub, "GET", p) {
			t.Errorf("public %s still registered with PUBLIC_HEALTH_ENABLED=false", p)
		}
	}
	w := httptest.NewRecorder()
	h.OpenAPIJSON(w, httptest.NewRequest("GET", "/pgauthz/v1/openapi.json", nil))
	var doc struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/livez", "/readyz", "/healthz"} {
		if _, there := doc.Paths[p]; there {
			t.Errorf("the served document still lists %s", p)
		}
	}
	if _, there := doc.Paths["/pgauthz/v1/openapi.json"]; !there {
		t.Error("the document must keep its own paths")
	}
}
