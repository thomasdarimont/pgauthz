package opabackend

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
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
			b := New(srv.URL, "authz", false, 5*time.Second, tc.deepRequired, "", true)
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
	b := New(srv.URL, "authz", false, 5*time.Second, false, "", true)
	if err := b.Healthz(context.Background()); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(metrics.OPAReadinessMode.WithLabelValues("deep")) != 1 ||
		testutil.ToFloat64(metrics.OPAReadinessMode.WithLabelValues("shallow")) != 0 {
		t.Fatal("expected mode deep=1 shallow=0 after a rule-backed probe")
	}

	srv2 := fakeOPA(t, 200, `{}`)
	b2 := New(srv2.URL, "authz", false, 5*time.Second, false, "", true)
	if err := b2.Healthz(context.Background()); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(metrics.OPAReadinessMode.WithLabelValues("shallow")) != 1 {
		t.Fatal("expected mode shallow=1 after a rule-absent probe")
	}
}

// A policy evaluation error (OPA 500, e.g. a broken hook under
// strict-builtin-errors) FAILS CLOSED on every path — the query returns an
// error, never a phantom allow/decision (ADR 0011).
func TestPolicyEvaluationErrorFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// OPA under strict-builtin-errors returns 500 on a runtime error.
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"code":"internal_error","message":"time.clock: eval_builtin_error"}`))
	}))
	defer srv.Close()
	b := New(srv.URL, "authz", false, 5*time.Second, false, "", true)

	// CheckAccess: must NOT return allow=true; must return an error.
	if ok, err := b.CheckAccess(context.Background(), authz.EvalRequest{Store: "demo"}); ok || err == nil {
		t.Fatalf("check must fail closed: ok=%v err=%v", ok, err)
	} else if !strings.Contains(err.Error(), "policy_evaluation_failed") {
		t.Fatalf("expected policy_evaluation_failed, got %v", err)
	}
	// Batch: same.
	if _, err := b.CheckAccessBatch(context.Background(), "demo", []authz.EvalRequest{{}}, nil, ""); err == nil {
		t.Fatal("batch must fail closed on eval error")
	}
	// Detailed / search: same.
	if _, _, err := b.CheckAccessDetailed(context.Background(), authz.EvalRequest{Store: "demo"}); err == nil {
		t.Fatal("allow_detailed must fail closed")
	}
	if _, err := b.ListActions(context.Background(), "demo", "u", "a", "d", "1", nil); err == nil {
		t.Fatal("permitted_actions/list must fail closed")
	}
}

// Enumeration refusal (ADR 0011): with hooks loaded and no operator opt-in,
// the search rules return {"error": "enumeration_refused_with_hooks"} — that
// must surface as the typed ErrEnumerationRefused (→ 403), never as a silent
// empty result or a 500.
func TestEnumerationRefusalSurfacesTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result": {"error": "enumeration_refused_with_hooks"}}`))
	}))
	defer srv.Close()
	b := New(srv.URL, "authz", false, 5*time.Second, false, "", true)

	if _, _, err := b.ListResources(context.Background(), "demo", "u", "a", "r", "d", nil, nil); !errors.Is(err, authz.ErrEnumerationRefused) {
		t.Fatalf("ListResources: want ErrEnumerationRefused, got %v", err)
	}
	if _, _, err := b.ListSubjects(context.Background(), "demo", "u", "r", "d", "1", nil, nil); !errors.Is(err, authz.ErrEnumerationRefused) {
		t.Fatalf("ListSubjects: want ErrEnumerationRefused, got %v", err)
	}
	page := &authz.PageRequest{Limit: 10}
	if _, _, err := b.ListResources(context.Background(), "demo", "u", "a", "r", "d", nil, page); !errors.Is(err, authz.ErrEnumerationRefused) {
		t.Fatalf("ListResources paged: want ErrEnumerationRefused, got %v", err)
	}
}

// Hook-FILTERED enumeration (ADR 0011): the paginated search rules return a
// protocol object {hook_filtered, ids, has_more, cursor} — ids are filtered
// but pagination stays in RAW keyset space, so a page that filters below the
// client limit must NOT read as exhausted.
func TestFilteredEnumerationPageProtocol(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result": {"hook_filtered": true, "ids": ["doc_a"], "has_more": true, "cursor": "doc_b"}}`))
	}))
	defer srv.Close()
	b := New(srv.URL, "authz", false, 5*time.Second, false, "", true)

	ids, pageResp, err := b.ListResources(context.Background(), "demo", "u", "alice", "r", "d", nil, &authz.PageRequest{Limit: 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 1 || ids[0] != "doc_a" {
		t.Fatalf("ids = %v, want [doc_a]", ids)
	}
	// One filtered id on a limit-2 page — WITHOUT the protocol this would look
	// exhausted; the raw-space peek says there is more, cursor = last RAW id.
	if pageResp == nil || !pageResp.HasMore {
		t.Fatalf("pagination must continue in raw keyset space: %+v", pageResp)
	}
	if pageResp.NextToken == "" {
		t.Fatal("expected a raw-space keyset cursor")
	}
}

// The fail-closed candidate cap surfaces as its own typed 403, never a
// partial result.
func TestFilteredEnumerationCapExceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result": {"error": "enumeration_refused_too_many_candidates"}}`))
	}))
	defer srv.Close()
	b := New(srv.URL, "authz", false, 5*time.Second, false, "", true)

	if _, _, err := b.ListResources(context.Background(), "demo", "u", "a", "r", "d", nil, nil); !errors.Is(err, authz.ErrEnumerationCapExceeded) {
		t.Fatalf("want ErrEnumerationCapExceeded, got %v", err)
	}
}
