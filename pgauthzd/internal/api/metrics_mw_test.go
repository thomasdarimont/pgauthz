package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
)

func testMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /pgauthz/v1/check", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("POST /stores/{store}/pgauthz/v1/check", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return mux
}

func TestRouteLabelTemplated(t *testing.T) {
	mux := testMux()
	cases := map[string]string{
		"/pgauthz/v1/check":             "/pgauthz/v1/check",
		"/stores/acme/pgauthz/v1/check": "/stores/{store}/pgauthz/v1/check", // wildcard stays templated
		"/pgauthz/v1/nonexistent":       "unmatched",
	}
	for path, want := range cases {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		if got := routeLabel(mux, r); got != want {
			t.Errorf("routeLabel(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestMetricsMiddlewareCounts(t *testing.T) {
	mux := testMux()
	h := Metrics(mux, mux)

	before := testutil.ToFloat64(metrics.HTTPRequests.WithLabelValues("/pgauthz/v1/check", "POST", "200"))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/pgauthz/v1/check", nil))
	if got := testutil.ToFloat64(metrics.HTTPRequests.WithLabelValues("/pgauthz/v1/check", "POST", "200")); got != before+1 {
		t.Fatalf("http_requests_total: got %v, want %v", got, before+1)
	}
}
