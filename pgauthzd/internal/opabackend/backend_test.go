package opabackend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
		wantErr        string // "" = healthy
	}{
		{"OPA down fails fast", 503, `{"result": true}`, "OPA health check"},
		{"full path healthy", 200, `{"result": true}`, ""},
		{"callback/PG unreachable fails readiness", 200, `{"result": false}`, "authorization path unhealthy"},
		{"rule absent degrades to shallow (custom policy set)", 200, `{}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeOPA(t, tc.healthStatus, tc.callbackResult)
			b := New(srv.URL, "authz", false)
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
