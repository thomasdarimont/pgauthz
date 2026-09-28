package api

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
)

// Action-log / temporal-gate metrics (ADR 0010 slice for ADR 0012). Everything
// here derives from data the handlers already hold — the request body and the
// engine's JSON result — so it adds no query and cannot fail a request.

// rejectReason maps a native events/reserve error to the EventsRejected label,
// mirroring writeWriteError's status mapping.
func rejectReason(err error) string {
	switch {
	case errors.Is(err, authz.ErrForbiddenRole):
		return "forbidden"
	case errors.Is(err, authz.ErrInvalidConsistency), errors.Is(err, authz.ErrInvalidRequest):
		return "invalid_request"
	default:
		return "error"
	}
}

// eventLags returns one lag per element of an accepted events array:
// now − occurred_at (clamped at 0), or 0 when occurred_at is absent (the
// engine then records the event as of now). Malformed elements are skipped —
// the engine already accepted the batch, so this is best-effort observation.
func eventLags(events json.RawMessage, now time.Time) []lagSample {
	var arr []struct {
		Kind       string `json:"kind"`
		OccurredAt string `json:"occurred_at"`
	}
	if err := json.Unmarshal(events, &arr); err != nil {
		return nil
	}
	out := make([]lagSample, 0, len(arr))
	for _, e := range arr {
		kind := e.Kind
		if kind == "" {
			kind = "request"
		}
		if e.OccurredAt == "" {
			out = append(out, lagSample{kind: kind, seconds: 0})
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, e.OccurredAt)
		if err != nil {
			continue
		}
		lag := now.Sub(t).Seconds()
		if lag < 0 {
			lag = 0
		}
		out = append(out, lagSample{kind: kind, seconds: lag})
	}
	return out
}

type lagSample struct {
	kind    string
	seconds float64
}

func observeEventLags(events json.RawMessage) {
	for _, l := range eventLags(events, time.Now()) {
		metrics.EventLag.WithLabelValues(l.kind).Observe(l.seconds)
	}
}

// recordGateClauses counts the temporal-gate clause outcomes in a list of
// gate steps (reserve_event's `gates`, or explain's trace filtered to
// rule_type = temporal_gate).
func recordGateClauses(path string, steps []map[string]any) {
	for _, st := range steps {
		reason, _ := st["reason"].(string)
		if reason == "" {
			continue
		}
		shadow, _ := st["shadow"].(bool)
		metrics.GateClauses.WithLabelValues(path, reason, strconv.FormatBool(shadow)).Inc()
	}
}

// recordReserveOutcome counts a reserve_event result and its clause outcomes.
func recordReserveOutcome(resp map[string]any) {
	if reason, ok := resp["reason"].(string); ok && reason != "" {
		metrics.ReserveDecisions.WithLabelValues(reason).Inc()
	}
	if gates, ok := resp["gates"].([]any); ok {
		steps := make([]map[string]any, 0, len(gates))
		for _, g := range gates {
			if m, ok := g.(map[string]any); ok {
				steps = append(steps, m)
			}
		}
		recordGateClauses("reserve", steps)
	}
}

// recordExplainGateClauses scans an explain_access result for temporal-gate
// steps. Best-effort: a result that does not parse records nothing.
func recordExplainGateClauses(raw json.RawMessage) {
	var doc struct {
		Trace []map[string]any `json:"trace"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return
	}
	steps := make([]map[string]any, 0)
	for _, st := range doc.Trace {
		if rt, _ := st["rule_type"].(string); rt == "temporal_gate" {
			steps = append(steps, st)
		}
	}
	recordGateClauses("explain", steps)
}
