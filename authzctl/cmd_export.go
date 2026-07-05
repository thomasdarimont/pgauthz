package main

import (
	"context"
	"encoding/json"
	"fmt"
)

func prettyJSONOneLine(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func cmdApply(args []string) error {
	fs, dsn := newFlags("model apply")
	store := fs.String("store", "", "target store")
	stores := fs.String("stores", "", "comma-separated store list (fleet variant, one transaction)")
	planFirst := fs.Bool("plan-first", false, "refuse when the plan reports blockers")
	pos := parseAll(fs, args)
	if (*store == "") == (*stores == "") || len(pos) != 1 {
		return fmt.Errorf("usage: authzctl model apply <name[@version]> --store <s> | --stores a,b,c [--plan-first]")
	}
	name, version, err := parseModelRef(pos[0])
	if err != nil {
		return err
	}

	ctx := context.Background()
	if *planFirst && *store != "" {
		plan, err := fetchPlan(ctx, *dsn, *store, pos[0])
		if err != nil {
			return err
		}
		if plan["can_apply"] != true {
			renderPlan(plan)
			return fmt.Errorf("apply refused: plan reports blockers")
		}
	}

	conn, err := connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	if *store != "" {
		var applied int
		if err := conn.QueryRow(ctx,
			"SELECT authz.apply_model($1, $2, $3)", *store, name, versionArg(version)).Scan(&applied); err != nil {
			return err
		}
		fmt.Printf("applied %s@%d to %s\n", name, applied, *store)
		return nil
	}

	rows, err := conn.Query(ctx,
		"SELECT store, version FROM authz.apply_model(string_to_array($1, ','), $2, $3)",
		*stores, name, versionArg(version))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		var v int
		if err := rows.Scan(&s, &v); err != nil {
			return err
		}
		fmt.Printf("applied %s@%d to %s\n", name, v, s)
	}
	return rows.Err()
}

func cmdExport(args []string) error {
	fs, dsn := newFlags("model export")
	store := fs.String("store", "", "source store (required)")
	dsl := fs.Bool("dsl", false, "human-readable DSL-flavored text (display only, not round-trippable)")
	_ = parseAll(fs, args)
	if *store == "" {
		return fmt.Errorf("usage: authzctl model export --store <store> [--dsl]")
	}

	ctx := context.Background()
	conn, err := connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	if *dsl {
		var text string
		if err := conn.QueryRow(ctx, "SELECT authz.describe_model($1)", *store).Scan(&text); err != nil {
			return err
		}
		fmt.Print(text)
		return nil
	}
	var def map[string]any
	if err := queryJSON(ctx, conn, &def, "SELECT authz.export_model($1)", *store); err != nil {
		return err
	}
	fmt.Println(prettyJSON(def))
	return nil
}

func cmdStatus(args []string) error {
	fs, dsn := newFlags("model status")
	store := fs.String("store", "", "store (required)")
	_ = parseAll(fs, args)
	if *store == "" {
		return fmt.Errorf("usage: authzctl model status --store <store>")
	}

	ctx := context.Background()
	conn, err := connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	var name, by *string
	var version *int
	var inSync *bool
	var live, expected *string
	var appliedAt *string
	err = conn.QueryRow(ctx, `SELECT model_name, model_version, applied_at::text, applied_by,
	                                 in_sync, live_checksum, expected_checksum
	                            FROM authz.model_status($1)`, *store).
		Scan(&name, &version, &appliedAt, &by, &inSync, &live, &expected)
	if err != nil {
		return err
	}
	if name == nil {
		fmt.Printf("store %s: unmanaged (live checksum %s)\n", *store, *live)
		return nil
	}
	fmt.Printf("store %s: %s@%d applied %s by %s — in_sync: %v\n",
		*store, *name, *version, *appliedAt, *by, *inSync)
	return nil
}

func cmdVersions(args []string) error {
	fs, dsn := newFlags("model versions")
	pos := parseAll(fs, args)
	name := any(nil)
	if len(pos) == 1 {
		name = pos[0]
	}

	ctx := context.Background()
	conn, err := connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	rows, err := conn.Query(ctx,
		`SELECT name, version, checksum, COALESCE(description,''), created_at::text, created_by
		   FROM authz.list_model_versions($1)`, name)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var n, sum, desc, at, by string
		var v int
		if err := rows.Scan(&n, &v, &sum, &desc, &at, &by); err != nil {
			return err
		}
		fmt.Printf("%s@%d  %s  %s  %s  %s\n", n, v, sum[:12], at, by, desc)
	}
	return rows.Err()
}

func cmdRollout(args []string) error {
	fs, dsn := newFlags("model rollout")
	pos := parseAll(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: authzctl model rollout <name>")
	}

	ctx := context.Background()
	conn, err := connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	rows, err := conn.Query(ctx,
		`SELECT store, model_version, latest_version, in_sync, applied_at::text
		   FROM authz.model_rollout_status($1)`, pos[0])
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var s, at string
		var v, latest int
		var inSync bool
		if err := rows.Scan(&s, &v, &latest, &inSync, &at); err != nil {
			return err
		}
		marker := ""
		if v < latest {
			marker = "  (outdated)"
		}
		if !inSync {
			marker += "  (DRIFTED)"
		}
		fmt.Printf("%s  @%d/latest %d  applied %s%s\n", s, v, latest, at, marker)
	}
	return rows.Err()
}
