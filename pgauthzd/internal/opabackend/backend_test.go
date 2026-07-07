package opabackend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
)

// fakeOPA serves /health and the deep-readiness rule with configurable answers.
func fakeOPA(t *testing.T, healthStatus int, callbackResult string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(healthStatus)
	})
	mux.HandleFunc("POST /v1/data/authz/pgauthz/callback_healthy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(callbackResult))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// Healthz is END-TO-END in OPA mode (review #8): OPA's own /health proves only
// the OPA process; readiness must also prove the decision path
// (OPA eval → native callback → PostgreSQL) via data.pgauthz.callback_healthy.
func TestHealthzDeepReadiness(t *testing.T) {
	cases := []struct {
		name           string
		healthStatus   int
		callbackResult string
		deepRequired   bool
		wantErr        string // "" = healthy
	}{
		{"OPA down fails fast", 503, `{"result": true}`, false, "OPA health check"},
		{"full path healthy", 200, `{"result": true}`, false, ""},
		{"callback/PG unreachable fails readiness", 200, `{"result": false}`, false, "authorization path unhealthy"},
		{"rule absent degrades to shallow (custom policy set)", 200, `{}`, false, ""},
		// Strict mode (review #9): a silent downgrade to shallow must not pass.
		{"rule absent + OPA_DEEP_READINESS_REQUIRED fails", 200, `{}`, true, "OPA_DEEP_READINESS_REQUIRED"},
		{"strict mode with the rule present is healthy", 200, `{"result": true}`, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeOPA(t, tc.healthStatus, tc.callbackResult)
			b := New(srv.URL, "authz", false, 5*time.Second, tc.deepRequired)
			err := b.Healthz(context.Background())
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected healthy, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// The mode gauge is one-hot: deep after a rule-backed probe, shallow after a
// rule-absent one — a downgrade is observable even without strict mode.
func TestOPAReadinessModeGauge(t *testing.T) {
	srv := fakeOPA(t, 200, `{"result": true}`)
	b := New(srv.URL, "authz", false, 5*time.Second, false)
	if err := b.Healthz(context.Background()); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(metrics.OPAReadinessMode.WithLabelValues("deep")) != 1 ||
		testutil.ToFloat64(metrics.OPAReadinessMode.WithLabelValues("shallow")) != 0 {
		t.Fatal("expected mode deep=1 shallow=0 after a rule-backed probe")
	}

	srv2 := fakeOPA(t, 200, `{}`)
	b2 := New(srv2.URL, "authz", false, 5*time.Second, false)
	if err := b2.Healthz(context.Background()); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(metrics.OPAReadinessMode.WithLabelValues("shallow")) != 1 {
		t.Fatal("expected mode shallow=1 after a rule-absent probe")
	}
}
