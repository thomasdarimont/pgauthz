package pgauthzadm

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// RenderPlan writes the plan the way pgauthzctl prints it: target, current
// state, +/~/- changes, blockers, rollback note and the verdict.
func RenderPlan(w io.Writer, plan Plan) {
	fmt.Fprintf(w, "plan: store %v ← %v@%v\n", plan["store"], plan["model"], plan["version"])
	if cur, ok := plan["current"].(map[string]any); ok && cur != nil {
		fmt.Fprintf(w, "current: %v@%v (in_sync: %v)\n", cur["model_name"], cur["model_version"], cur["in_sync"])
	} else {
		fmt.Fprintln(w, "current: unmanaged store")
	}
	if plan.NoOp() {
		fmt.Fprintln(w, "no-op: live model already matches the target")
	}
	RenderChanges(w, plan)
	if blockers := plan.Blockers(); len(blockers) > 0 {
		fmt.Fprintln(w, "BLOCKERS:")
		for _, b := range blockers {
			fmt.Fprintf(w, "  ! %s\n", CompactLine(b))
		}
	}
	if rb, ok := plan["rollback"].(map[string]any); ok && rb != nil {
		fmt.Fprintf(w, "rollback to @%v possible: %v", rb["to_version"], rb["possible"])
		if rm, ok := rb["type_removals_required"].([]any); ok && len(rm) > 0 {
			parts := make([]string, len(rm))
			for i, it := range rm {
				parts[i] = fmt.Sprint(it)
			}
			fmt.Fprintf(w, " (would require removing types: %s)", strings.Join(parts, ", "))
		}
		fmt.Fprintln(w)
	}
	verdict := "CAN APPLY"
	if !plan.CanApply() {
		verdict = "BLOCKED"
	}
	fmt.Fprintln(w, "verdict:", verdict)
}

// RenderChanges writes only the plan's changes as +/~/- lines.
func RenderChanges(w io.Writer, plan Plan) {
	sign := map[string]string{"add": "+", "update": "~", "remove": "-"}
	for _, c := range plan.Changes() {
		fmt.Fprintf(w, "%s %s %s\n", sign[c.Op], c.Section, CompactLine(c.Item))
	}
}

// CompactLine renders a plan item on one line: strings as-is, objects as JSON.
func CompactLine(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return strings.TrimSpace(string(b))
}
