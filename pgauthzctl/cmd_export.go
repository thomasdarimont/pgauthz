package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"thomasdarimont.de/authz/pgauthzadm"
)

// The registry verbs below are thin shells over pgauthzadm (the shared
// library the management console embeds); this file only parses flags and
// prints.

func cmdApply(args []string) error {
	fs, dsn := newFlags("model apply")
	store := fs.String("store", "", "target store")
	stores := fs.String("stores", "", "comma-separated store list (fleet variant, one transaction)")
	planFirst := fs.Bool("plan-first", false, "refuse when the plan reports blockers")
	pos := parseAll(fs, args)
	if (*store == "") == (*stores == "") || len(pos) != 1 {
		return fmt.Errorf("usage: pgauthzctl model apply <name[@version]> --store <s> | --stores a,b,c [--plan-first]")
	}
	name, version, err := pgauthzadm.ParseModelRef(pos[0])
	if err != nil {
		return err
	}

	ctx := context.Background()
	conn, err := connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	if *planFirst && *store != "" {
		plan, err := pgauthzadm.PlanApply(ctx, conn, *store, name, version)
		if err != nil {
			return err
		}
		if !plan.CanApply() {
			pgauthzadm.RenderPlan(os.Stdout, plan)
			return fmt.Errorf("apply refused: plan reports blockers")
		}
	}

	if *store != "" {
		applied, err := pgauthzadm.Apply(ctx, conn, *store, name, version)
		if err != nil {
			return err
		}
		fmt.Printf("applied %s@%d to %s\n", name, applied, *store)
		return nil
	}
	applied, err := pgauthzadm.ApplyMany(ctx, conn, strings.Split(*stores, ","), name, version)
	if err != nil {
		return err
	}
	for _, a := range applied {
		fmt.Printf("applied %s@%d to %s\n", name, a.Version, a.Store)
	}
	return nil
}

func cmdExport(args []string) error {
	fs, dsn := newFlags("model export")
	store := fs.String("store", "", "source store (required)")
	dsl := fs.Bool("dsl", false, "human-readable DSL-flavored text (display only, not round-trippable)")
	sql := fs.Bool("sql", false, "the engine calls that rebuild the model (complete, runnable in psql)")
	_ = parseAll(fs, args)
	if *store == "" || (*dsl && *sql) {
		return fmt.Errorf("usage: pgauthzctl model export --store <store> [--dsl | --sql]")
	}

	ctx := context.Background()
	conn, err := connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	switch {
	case *dsl:
		text, err := pgauthzadm.DescribeModel(ctx, conn, *store)
		if err != nil {
			return err
		}
		fmt.Print(text)
	case *sql:
		m, err := pgauthzadm.ExportModel(ctx, conn, *store)
		if err != nil {
			return err
		}
		fmt.Print(pgauthzadm.RenderSQL(*store, m))
	default:
		var def map[string]any
		if err := queryJSON(ctx, conn, &def, "SELECT authz.export_model($1)", *store); err != nil {
			return err
		}
		fmt.Println(prettyJSON(def))
	}
	return nil
}

func cmdStatus(args []string) error {
	fs, dsn := newFlags("model status")
	store := fs.String("store", "", "store (required)")
	_ = parseAll(fs, args)
	if *store == "" {
		return fmt.Errorf("usage: pgauthzctl model status --store <store>")
	}

	ctx := context.Background()
	conn, err := connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	st, err := pgauthzadm.ModelStatus(ctx, conn, *store)
	if err != nil {
		return err
	}
	if !st.Managed() {
		fmt.Printf("store %s: unmanaged (live checksum %s)\n", *store, st.LiveChecksum)
		return nil
	}
	fmt.Printf("store %s: %s@%d applied %s by %s — in_sync: %v\n",
		*store, *st.ModelName, *st.ModelVersion, st.AppliedAt.Format("2006-01-02 15:04:05-07"), *st.AppliedBy, *st.InSync)
	return nil
}

func cmdVersions(args []string) error {
	fs, dsn := newFlags("model versions")
	pos := parseAll(fs, args)
	name := ""
	if len(pos) == 1 {
		name = pos[0]
	}

	ctx := context.Background()
	conn, err := connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	versions, err := pgauthzadm.ListVersions(ctx, conn, name)
	if err != nil {
		return err
	}
	for _, v := range versions {
		fmt.Printf("%s@%d  %s  %s  %s  %s\n", v.Name, v.Version, v.Checksum[:12], v.CreatedAt.Format("2006-01-02 15:04:05-07"), v.CreatedBy, v.Description)
	}
	return nil
}

func cmdRollout(args []string) error {
	fs, dsn := newFlags("model rollout")
	pos := parseAll(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: pgauthzctl model rollout <name>")
	}

	ctx := context.Background()
	conn, err := connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	rows, err := pgauthzadm.RolloutStatus(ctx, conn, pos[0])
	if err != nil {
		return err
	}
	for _, r := range rows {
		marker := ""
		if r.Outdated() {
			marker = "  (outdated)"
		}
		if !r.InSync {
			marker += "  (DRIFTED)"
		}
		at := ""
		if r.AppliedAt != nil {
			at = r.AppliedAt.Format("2006-01-02 15:04:05-07")
		}
		fmt.Printf("%s  @%d/latest %d  applied %s%s\n", r.Store, r.ModelVersion, r.LatestVersion, at, marker)
	}
	return nil
}
