package main

import (
	"context"
	"encoding/json"
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
	sf := newServerFlags(fs)
	store := fs.String("store", "", "target store")
	stores := fs.String("stores", "", "comma-separated store list (fleet variant: one transaction over --dsn, one apply per store over --server)")
	planFirst := fs.Bool("plan-first", false, "refuse when the plan reports blockers (always on over --server: the daemon plans first)")
	pos := parseAll(fs, args)
	if (*store == "") == (*stores == "") || len(pos) != 1 {
		return fmt.Errorf("usage: pgauthzctl model apply <name[@version]> --store <s> | --stores a,b,c [--plan-first]")
	}
	name, version, err := pgauthzadm.ParseModelRef(pos[0])
	if err != nil {
		return err
	}

	ctx := context.Background()
	if m, err := apiModelFor(sf); err != nil || m != nil {
		if err != nil {
			return err
		}
		targets := []string{*store}
		if *stores != "" {
			targets = strings.Split(*stores, ",")
		}
		for _, s := range targets {
			applied, err := m.apply(ctx, strings.TrimSpace(s), name, version)
			if err != nil {
				return explain409(err)
			}
			fmt.Printf("applied %s@%d to %s\n", name, applied, strings.TrimSpace(s))
		}
		return nil
	}
	noteDSN("model apply")
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
	sf := newServerFlags(fs)
	store := fs.String("store", "", "source store (required)")
	dsl := fs.Bool("dsl", false, "human-readable DSL-flavored text (display only, not round-trippable)")
	sql := fs.Bool("sql", false, "the engine calls that rebuild the model (complete, runnable in psql)")
	_ = parseAll(fs, args)
	if *store == "" || (*dsl && *sql) {
		return fmt.Errorf("usage: pgauthzctl model export --store <store> [--dsl | --sql]")
	}

	ctx := context.Background()
	if m, err := apiModelFor(sf); err != nil || m != nil {
		if err != nil {
			return err
		}
		def, text, err := m.export(ctx, *store, *dsl)
		if err != nil {
			return err
		}
		switch {
		case *dsl:
			fmt.Print(text)
		case *sql:
			var model pgauthzadm.Model
			if err := json.Unmarshal(def, &model); err != nil {
				return err
			}
			fmt.Print(pgauthzadm.RenderSQL(*store, &model))
		default:
			var v map[string]any
			if err := json.Unmarshal(def, &v); err != nil {
				return err
			}
			fmt.Println(prettyJSON(v))
		}
		return nil
	}
	noteDSN("model export")
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
	sf := newServerFlags(fs)
	store := fs.String("store", "", "store (required)")
	_ = parseAll(fs, args)
	if *store == "" {
		return fmt.Errorf("usage: pgauthzctl model status --store <store>")
	}

	ctx := context.Background()
	var st *pgauthzadm.Status
	if m, err := apiModelFor(sf); err != nil || m != nil {
		if err != nil {
			return err
		}
		if st, err = m.status(ctx, *store); err != nil {
			return err
		}
	} else {
		noteDSN("model status")
		conn, err := connect(ctx, *dsn)
		if err != nil {
			return err
		}
		defer conn.Close(ctx)
		if st, err = pgauthzadm.ModelStatus(ctx, conn, *store); err != nil {
			return err
		}
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
	sf := newServerFlags(fs)
	pos := parseAll(fs, args)
	name := ""
	if len(pos) == 1 {
		name = pos[0]
	}

	ctx := context.Background()
	var versions []pgauthzadm.Version
	if m, err := apiModelFor(sf); err != nil || m != nil {
		if err != nil {
			return err
		}
		if versions, err = m.versions(ctx, name); err != nil {
			return err
		}
	} else {
		noteDSN("model versions")
		conn, err := connect(ctx, *dsn)
		if err != nil {
			return err
		}
		defer conn.Close(ctx)
		if versions, err = pgauthzadm.ListVersions(ctx, conn, name); err != nil {
			return err
		}
	}
	for _, v := range versions {
		owner := ""
		if v.OwnerGroup != "" {
			owner = "  [group " + v.OwnerGroup + "]"
		} else if v.OwnerStore != "" {
			owner = "  [store " + v.OwnerStore + "]"
		}
		fmt.Printf("%s@%d  %s  %s  %s  %s%s\n", v.Name, v.Version, v.Checksum[:12], v.CreatedAt.Format("2006-01-02 15:04:05-07"), v.CreatedBy, v.Description, owner)
	}
	return nil
}

func cmdRollout(args []string) error {
	fs, dsn := newFlags("model rollout")
	sf := newServerFlags(fs)
	pos := parseAll(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: pgauthzctl model rollout <name>")
	}

	ctx := context.Background()
	var rows []pgauthzadm.RolloutRow
	if m, err := apiModelFor(sf); err != nil || m != nil {
		if err != nil {
			return err
		}
		if rows, err = m.rollout(ctx, pos[0]); err != nil {
			return err
		}
	} else {
		noteDSN("model rollout")
		conn, err := connect(ctx, *dsn)
		if err != nil {
			return err
		}
		defer conn.Close(ctx)
		if rows, err = pgauthzadm.RolloutStatus(ctx, conn, pos[0]); err != nil {
			return err
		}
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
