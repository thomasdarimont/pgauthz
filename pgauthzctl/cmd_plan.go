package main

import (
	"context"
	"fmt"
	"os"

	"thomasdarimont.de/authz/pgauthzadm"
)

func fetchPlan(ctx context.Context, sf serverFlags, dsn, store, model string) (pgauthzadm.Plan, error) {
	name, version, err := pgauthzadm.ParseModelRef(model)
	if err != nil {
		return nil, err
	}
	if m, err := apiModelFor(sf); err != nil || m != nil {
		if err != nil {
			return nil, err
		}
		return m.plan(ctx, store, name, version)
	}
	noteDSN("model plan")
	conn, err := connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	return pgauthzadm.PlanApply(ctx, conn, store, name, version)
}

// cmdPlan prints the dry-run verdict; exit 1 when the apply would be blocked
// (CI-gateable).
func cmdPlan(args []string) error {
	fs, dsn := newFlags("model plan")
	sf := newServerFlags(fs)
	store := fs.String("store", "", "target store (required)")
	asJSON := fs.Bool("json", false, "raw plan JSON")
	pos := parseAll(fs, args)
	if *store == "" || len(pos) != 1 {
		return fmt.Errorf("usage: pgauthzctl model plan <name[@version]> --store <store> [--json]")
	}

	plan, err := fetchPlan(context.Background(), sf, *dsn, *store, pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		fmt.Println(prettyJSON(plan))
	} else {
		pgauthzadm.RenderPlan(os.Stdout, plan)
	}
	if !plan.CanApply() {
		os.Exit(1)
	}
	return nil
}

// cmdDiff prints only the plan's changes as +/- lines.
func cmdDiff(args []string) error {
	fs, dsn := newFlags("model diff")
	sf := newServerFlags(fs)
	store := fs.String("store", "", "target store (required)")
	pos := parseAll(fs, args)
	if *store == "" || len(pos) != 1 {
		return fmt.Errorf("usage: pgauthzctl model diff <name[@version]> --store <store>")
	}

	plan, err := fetchPlan(context.Background(), sf, *dsn, *store, pos[0])
	if err != nil {
		return err
	}
	pgauthzadm.RenderChanges(os.Stdout, plan)
	return nil
}
