package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

// hookVetoBackend fails a batch with a policy-hook veto (ADR 0011).
type hookVetoBackend struct{ authz.Backend }

func (hookVetoBackend) CheckAccessBatch(context.Context, string, []authz.EvalRequest, map[string]any, string) ([]authz.EvalResult, error) {
	return nil, &authz.PolicyHookDeniedError{
		Denials:   []map[string]any{{"tier": "global", "hook": "business_hours", "code": "denied", "message": "x"}},
		Count:     70,
		Truncated: true,
		Dropped:   6,
	}
}

// A batch hook veto is 403 denied_by_policy_hook; the structured `denials`
// (hook identities/reasons) are disclosed ONLY under X-PGAuthz-Detail
// (ADR 0011). denials_truncated/denial_count ride along when detailed.
func TestEvaluationsHookVetoDisclosureGated(t *testing.T) {
	b := &hookVetoBackend{}
	h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileDecisionOnly, DefaultStore: "demo"})
	body := `{"evaluations":[{"subject":{"type":"user","id":"a"},"action":{"name":"r"},"resource":{"type":"d","id":"1"}}]}`

	// Without X-PGAuthz-Detail: error code only, no denials.
	w := httptest.NewRecorder()
	h.Evaluations(w, jsonReq("POST", "/access/v1/evaluations", body))
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403; body=%s", w.Code, w.Body.String())
	}
	var plain map[string]any
	json.Unmarshal(w.Body.Bytes(), &plain)
	if plain["error"] != "denied_by_policy_hook" {
		t.Fatalf("error = %v", plain["error"])
	}
	if _, ok := plain["denials"]; ok {
		t.Fatalf("denials must NOT be disclosed without X-PGAuthz-Detail: %s", w.Body.String())
	}

	// With X-PGAuthz-Detail: denials + truncation metadata.
	w = httptest.NewRecorder()
	r := jsonReq("POST", "/access/v1/evaluations", body)
	r = r.WithContext(context.WithValue(r.Context(), ctxDetail, true))
	h.Evaluations(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("detail: got %d, want 403", w.Code)
	}
	var detailed map[string]any
	json.Unmarshal(w.Body.Bytes(), &detailed)
	ds, ok := detailed["denials"].([]any)
	if !ok || len(ds) != 1 {
		t.Fatalf("detail must disclose denials: %s", w.Body.String())
	}
	if detailed["denials_truncated"] != true || detailed["denial_count"].(float64) != 70 || detailed["denials_dropped"].(float64) != 6 {
		t.Fatalf("expected truncation metadata (count=70, dropped=6): %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "business_hours") {
		t.Fatalf("denial should name the hook: %s", w.Body.String())
	}
}
