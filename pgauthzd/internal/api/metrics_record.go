package api

import "thomasdarimont.de/authz/pgauthzd/internal/metrics"

// Slice-2 recording helpers (ADR 0010): keep the label mapping in one place.

func decisionLabel(allowed bool, err error) string {
	switch {
	case err != nil:
		return "error"
	case allowed:
		return "allow"
	default:
		return "deny"
	}
}

// recordDecision records a plain (boolean) access-check decision.
func recordDecision(store, apiLabel string, allowed bool, err error) {
	metrics.CheckDecisions.WithLabelValues(store, decisionLabel(allowed, err), apiLabel).Inc()
}

// recordDecisionDetail records a detailed decision, preferring its tri-state
// (`allow|deny|conditional`) over the boolean.
func recordDecisionDetail(store, apiLabel string, detail map[string]any, err error) {
	if err != nil {
		metrics.CheckDecisions.WithLabelValues(store, "error", apiLabel).Inc()
		return
	}
	state, _ := detail["state"].(string)
	if state == "" {
		state = "allow"
	}
	metrics.CheckDecisions.WithLabelValues(store, state, apiLabel).Inc()
}

// recordSearch records a search request + result-set size.
func recordSearch(store, kind string, n int, err error) {
	result := "ok"
	if err != nil {
		result = "error"
	}
	metrics.SearchRequests.WithLabelValues(store, kind, result).Inc()
	if err == nil {
		metrics.SearchResultSize.WithLabelValues(kind).Observe(float64(n))
	}
}
