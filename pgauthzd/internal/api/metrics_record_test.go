package api

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
)

func TestDecisionLabel(t *testing.T) {
	cases := []struct {
		allowed bool
		err     error
		want    string
	}{
		{true, nil, "allow"},
		{false, nil, "deny"},
		{true, errors.New("boom"), "error"},
		{false, errors.New("boom"), "error"},
	}
	for _, c := range cases {
		if got := decisionLabel(c.allowed, c.err); got != c.want {
			t.Errorf("decisionLabel(%v,%v)=%q want %q", c.allowed, c.err, got, c.want)
		}
	}
}

func TestRecordDecisionIncrements(t *testing.T) {
	before := testutil.ToFloat64(metrics.CheckDecisions.WithLabelValues("s1", "allow", metrics.APINative))
	recordDecision("s1", metrics.APINative, true, nil)
	if got := testutil.ToFloat64(metrics.CheckDecisions.WithLabelValues("s1", "allow", metrics.APINative)); got != before+1 {
		t.Fatalf("check_decisions_total: got %v want %v", got, before+1)
	}
}

func TestRecordDecisionDetailState(t *testing.T) {
	before := testutil.ToFloat64(metrics.CheckDecisions.WithLabelValues("s1", "conditional", metrics.APIAuthZEN))
	recordDecisionDetail("s1", metrics.APIAuthZEN, map[string]any{"state": "conditional"}, nil)
	if got := testutil.ToFloat64(metrics.CheckDecisions.WithLabelValues("s1", "conditional", metrics.APIAuthZEN)); got != before+1 {
		t.Fatalf("detail state: got %v want %v", got, before+1)
	}
}

func TestRecordSearch(t *testing.T) {
	before := testutil.ToFloat64(metrics.SearchRequests.WithLabelValues("s1", "objects", "ok"))
	recordSearch("s1", "objects", 5, nil)
	if got := testutil.ToFloat64(metrics.SearchRequests.WithLabelValues("s1", "objects", "ok")); got != before+1 {
		t.Fatalf("search_requests_total: got %v want %v", got, before+1)
	}
}
