package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

// The discovery document's policy_decision_point must be identical to the URL
// the caller fetched it from (AuthZEN 1.0 §9.2.3). Behind a TLS-terminating
// proxy the daemon's own request says http://<internal host>, so an operator
// either pins BASE_URL or lets the proxy's X-Forwarded-* headers speak —
// explicitly, never by default.
func TestWellKnownBase(t *testing.T) {
	get := func(cfg *config.Config, path string, forwardedProto, forwardedHost string) map[string]any {
		t.Helper()
		h := NewHandler(nil, nil, nil, cfg)
		mux := newPublicMux(h, false)
		r := httptest.NewRequest(http.MethodGet, "http://pgauthzd.internal:8080"+path, nil)
		if forwardedProto != "" {
			r.Header.Set("X-Forwarded-Proto", forwardedProto)
		}
		if forwardedHost != "" {
			r.Header.Set("X-Forwarded-Host", forwardedHost)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Fatalf("Content-Type %q", ct)
		}
		var doc map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	const wk = "/.well-known/authzen-configuration"

	// Default: the request's own scheme and host, forwarded headers ignored.
	doc := get(&config.Config{}, wk, "https", "pdp.example.com")
	if doc["policy_decision_point"] != "http://pgauthzd.internal:8080" {
		t.Fatalf("default: %v", doc["policy_decision_point"])
	}

	// Opt-in: the proxy's scheme and host, the tenant path kept.
	doc = get(&config.Config{TrustForwardedHeaders: true}, wk+"/stores/authzen_cert", "https", "pdp.example.com:9445")
	if doc["policy_decision_point"] != "https://pdp.example.com:9445/stores/authzen_cert" {
		t.Fatalf("forwarded: %v", doc["policy_decision_point"])
	}
	if doc["access_evaluation_endpoint"] != "https://pdp.example.com:9445/stores/authzen_cert/access/v1/evaluation" {
		t.Fatalf("forwarded endpoint: %v", doc["access_evaluation_endpoint"])
	}
	// …and the first value of a proxy chain wins, an unknown scheme is ignored.
	doc = get(&config.Config{TrustForwardedHeaders: true}, wk, "https, http", "a.example, b.example")
	if doc["policy_decision_point"] != "https://a.example" {
		t.Fatalf("chain: %v", doc["policy_decision_point"])
	}
	doc = get(&config.Config{TrustForwardedHeaders: true}, wk, "gopher", "")
	if doc["policy_decision_point"] != "http://pgauthzd.internal:8080" {
		t.Fatalf("bad scheme: %v", doc["policy_decision_point"])
	}

	// BASE_URL wins over everything, trailing slash normalised.
	doc = get(&config.Config{BaseURL: "https://authz.example.org/", TrustForwardedHeaders: true}, wk+"/stores/t1", "https", "pdp.example.com")
	if doc["policy_decision_point"] != "https://authz.example.org/stores/t1" {
		t.Fatalf("base url: %v", doc["policy_decision_point"])
	}

	// §9.2.2: no null or empty parameters in the document.
	for name, value := range doc {
		if value == nil || value == "" {
			t.Fatalf("empty parameter %q in %v", name, doc)
		}
	}
}
