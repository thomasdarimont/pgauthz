package decisionlog

import (
	"encoding/json"
	"strings"
	"testing"
)

// An OPA-fronted decision with policy hooks mounted: the log line names the
// hooks consulted and, on a veto, the hook that denied — otherwise "via: opa"
// says only that OPA sat in the path.
func TestFromDetailKeepsHooks(t *testing.T) {
	var e Entry
	e.FromDetail(map[string]any{
		"decision":     false,
		"state":        "deny",
		"reason":       "policy_hook",
		"hooks_loaded": []any{"geo_fence", "stores/demo/freeze"},
		"hook_denials": []any{
			map[string]any{"tier": "store", "store": "demo", "hook": "freeze", "code": "denied", "message": "store frozen for audit"},
			"not an object",
		},
	})
	if e.State != "deny" || e.Reason != "policy_hook" {
		t.Fatalf("state/reason = %q/%q", e.State, e.Reason)
	}
	if len(e.Hooks) != 2 || e.Hooks[1] != "stores/demo/freeze" {
		t.Fatalf("hooks = %v", e.Hooks)
	}
	if len(e.HookDenials) != 1 || e.HookDenials[0].Hook != "freeze" || e.HookDenials[0].Tier != "store" || e.HookDenials[0].Message != "store frozen for audit" {
		t.Fatalf("hook denials = %+v", e.HookDenials)
	}
	raw, _ := json.Marshal(e)
	for _, want := range []string{`"hooks":["geo_fence","stores/demo/freeze"]`, `"hook":"freeze"`, `"message":"store frozen for audit"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("line lacks %s: %s", want, raw)
		}
	}
}

// An engine-only decision has no hook fields at all (omitempty keeps the
// line unchanged for deployments without OPA).
func TestFromDetailWithoutHooksIsSilent(t *testing.T) {
	var e Entry
	e.FromDetail(map[string]any{"decision": true, "state": "allow"})
	raw, _ := json.Marshal(e)
	if strings.Contains(string(raw), "hook") {
		t.Fatalf("unexpected hook fields: %s", raw)
	}
}
