package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
)

func TestRejectReason(t *testing.T) {
	cases := map[error]string{
		authz.ErrForbiddenRole:      "forbidden",
		authz.ErrInvalidRequest:     "invalid_request",
		authz.ErrInvalidConsistency: "invalid_request",
		context.DeadlineExceeded:    "error",
	}
	for err, want := range cases {
		if got := rejectReason(errors.New("wrap: " + err.Error())); got != "error" && err != context.DeadlineExceeded {
			// plain (unwrapped) message strings are not the sentinel
			t.Fatalf("string error should be 'error', got %q", got)
		}
		if got := rejectReason(err); got != want {
			t.Errorf("rejectReason(%v)=%q want %q", err, got, want)
		}
	}
}

func TestEventLags(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	raw := json.RawMessage(`[
		{"subject_type":"u","subject_id":"a","action":"x","occurred_at":"2026-09-28T11:59:30Z"},
		{"subject_type":"u","subject_id":"a","action":"x","kind":"response","occurred_at":"2026-09-28T11:00:00Z"},
		{"subject_type":"u","subject_id":"a","action":"x"},
		{"subject_type":"u","subject_id":"a","action":"x","occurred_at":"2026-09-28T12:00:05Z"},
		{"subject_type":"u","subject_id":"a","action":"x","occurred_at":"not a time"}
	]`)
	got := eventLags(raw, now)
	want := []lagSample{{"request", 30}, {"response", 3600}, {"request", 0}, {"request", 0}}
	if len(got) != len(want) {
		t.Fatalf("got %d samples %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sample %d: got %+v want %+v", i, got[i], want[i])
		}
	}
	if eventLags(json.RawMessage(`{"not":"an array"}`), now) != nil {
		t.Fatal("malformed body must record nothing")
	}
}

func TestRecordReserveOutcomeAndGateClauses(t *testing.T) {
	before := testutil.ToFloat64(metrics.ReserveDecisions.WithLabelValues("gate_denied"))
	shadowBefore := testutil.ToFloat64(metrics.GateClauses.WithLabelValues("reserve", "gate_denied", "true"))
	passBefore := testutil.ToFloat64(metrics.GateClauses.WithLabelValues("reserve", "gate_passed", "false"))
	var resp map[string]any
	_ = json.Unmarshal([]byte(`{"allowed":false,"reason":"gate_denied","gates":[
		{"gate":"cap","reason":"gate_passed","shadow":false},
		{"gate":"cap","reason":"gate_denied","shadow":true}]}`), &resp)
	recordReserveOutcome(resp)
	if got := testutil.ToFloat64(metrics.ReserveDecisions.WithLabelValues("gate_denied")); got != before+1 {
		t.Fatalf("reserve_decisions: got %v want %v", got, before+1)
	}
	if got := testutil.ToFloat64(metrics.GateClauses.WithLabelValues("reserve", "gate_denied", "true")); got != shadowBefore+1 {
		t.Fatalf("shadow clause: got %v want %v", got, shadowBefore+1)
	}
	if got := testutil.ToFloat64(metrics.GateClauses.WithLabelValues("reserve", "gate_passed", "false")); got != passBefore+1 {
		t.Fatalf("passed clause: got %v want %v", got, passBefore+1)
	}
}

func TestRecordExplainGateClauses(t *testing.T) {
	before := testutil.ToFloat64(metrics.GateClauses.WithLabelValues("explain", "gate_denied", "false"))
	recordExplainGateClauses(json.RawMessage(`{"trace":[
		{"rule_type":"direct","reason":"direct_tuple"},
		{"rule_type":"temporal_gate","reason":"gate_denied","shadow":false},
		{"rule_type":"temporal_gate","reason":"gate_denied","shadow":false}]}`))
	if got := testutil.ToFloat64(metrics.GateClauses.WithLabelValues("explain", "gate_denied", "false")); got != before+2 {
		t.Fatalf("explain gate clauses: got %v want %v", got, before+2)
	}
	recordExplainGateClauses(json.RawMessage(`garbage`)) // must not panic
}
