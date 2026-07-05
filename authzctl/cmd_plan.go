package main

import (
	"context"
	"fmt"
	"os"
	"strings"
)

func fetchPlan(ctx context.Context, dsn, store, model string) (map[string]any, error) {
	name, version, err := parseModelRef(model)
	if err != nil {
		return nil, err
	}
	conn, err := connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)

	var plan map[string]any
	err = queryJSON(ctx, conn, &plan,
		"SELECT authz.plan_model_apply($1, $2, $3)", store, name, versionArg(version))
	return plan, err
}

// cmdPlan prints the dry-run verdict; exit 1 when the apply would be blocked
// (CI-gateable).
func cmdPlan(args []string) error {
	fs, dsn := newFlags("model plan")
	store := fs.String("store", "", "target store (required)")
	asJSON := fs.Bool("json", false, "raw plan JSON")
	pos := parseAll(fs, args)
	if *store == "" || len(pos) != 1 {
		return fmt.Errorf("usage: authzctl model plan <name[@version]> --store <store> [--json]")
	}

	plan, err := fetchPlan(context.Background(), *dsn, *store, pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		fmt.Println(prettyJSON(plan))
	} else {
		renderPlan(plan)
	}
	if plan["can_apply"] != true {
		os.Exit(1)
	}
	return nil
}

// cmdDiff prints only the plan's changes as +/- lines.
func cmdDiff(args []string) error {
	fs, dsn := newFlags("model diff")
	store := fs.String("store", "", "target store (required)")
	pos := parseAll(fs, args)
	if *store == "" || len(pos) != 1 {
		return fmt.Errorf("usage: authzctl model diff <name[@version]> --store <store>")
	}

	plan, err := fetchPlan(context.Background(), *dsn, *store, pos[0])
	if err != nil {
		return err
	}
	renderChanges(plan)
	return nil
}

func renderPlan(plan map[string]any) {
	fmt.Printf("plan: store %v ← %v@%v\n", plan["store"], plan["model"], plan["version"])
	if cur, ok := plan["current"].(map[string]any); ok && cur != nil {
		fmt.Printf("current: %v@%v (in_sync: %v)\n",
			cur["model_name"], cur["model_version"], cur["in_sync"])
	} else {
		fmt.Println("current: unmanaged store")
	}
	if plan["no_op"] == true {
		fmt.Println("no-op: live model already matches the target")
	}
	renderChanges(plan)
	if blockers, ok := plan["blockers"].([]any); ok && len(blockers) > 0 {
		fmt.Println("BLOCKERS:")
		for _, b := range blockers {
			fmt.Printf("  ! %s\n", compactLine(b))
		}
	}
	if rb, ok := plan["rollback"].(map[string]any); ok && rb != nil {
		fmt.Printf("rollback to @%v possible: %v", rb["to_version"], rb["possible"])
		if rm, ok := rb["type_removals_required"].([]any); ok && len(rm) > 0 {
			fmt.Printf(" (would require removing types: %s)", joinAny(rm))
		}
		fmt.Println()
	}
	verdict := "CAN APPLY"
	if plan["can_apply"] != true {
		verdict = "BLOCKED"
	}
	fmt.Println("verdict:", verdict)
}

func renderChanges(plan map[string]any) {
	changes, _ := plan["changes"].(map[string]any)
	for _, section := range []string{"types", "relations", "rules", "type_restrictions", "conditions"} {
		sec, _ := changes[section].(map[string]any)
		for _, op := range []string{"add", "update", "remove"} {
			items, _ := sec[op].([]any)
			sign := map[string]string{"add": "+", "update": "~", "remove": "-"}[op]
			for _, it := range items {
				fmt.Printf("%s %s %s\n", sign, section, compactLine(it))
			}
		}
	}
}

func compactLine(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return strings.TrimSpace(prettyJSONOneLine(v))
}

func joinAny(items []any) string {
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = fmt.Sprint(it)
	}
	return strings.Join(parts, ", ")
}
