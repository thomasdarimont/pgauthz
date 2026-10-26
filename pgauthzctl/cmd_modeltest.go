package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"thomasdarimont.de/authz/pgauthzadm"
)

// model test: runs a tests.authz.yaml fixture (pgauthzadm.Fixture — the
// format, runner and JUnit writer are the library's, shared with the
// console's saved scenarios) in an ephemeral store and reports per
// assertion; --junit writes the CI report, --keep-store retains the store.
// Over --server the daemon runs it (POST /pgauthz/v1/admin/models/test):
// the fixture text travels with the OpenFGA model a model_file parsed to,
// the report comes back — a CI job needs a token, no database access.
func cmdTest(args []string) error {
	fs, dsn := newFlags("model test")
	sf := newServerFlags(fs)
	junit := fs.String("junit", "", "write JUnit XML to this path")
	keep := fs.Bool("keep-store", false, "keep the ephemeral store for debugging")
	liveStore := fs.String("store", "", "test a live store's current model (a fixture without model_file / model; or its store: key)")
	pos := parseAll(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: pgauthzctl model test <tests.authz.yaml> [--store <live store>] [--junit out.xml]")
	}
	fixPath := pos[0]

	raw, err := os.ReadFile(fixPath)
	if err != nil {
		return err
	}
	var fix pgauthzadm.Fixture
	if err := pgauthzadm.UnmarshalFixture(raw, &fix); err != nil {
		return fmt.Errorf("%s: %w", fixPath, err)
	}
	if *liveStore != "" {
		if fix.ModelFile != "" || fix.Model != "" {
			return fmt.Errorf("--store: %s already names its model (model_file / model)", fixPath)
		}
		fix.Store = *liveStore
	}
	if err := fix.Validate(); err != nil {
		return fmt.Errorf("%s: %w", fixPath, err)
	}

	// The model file is the client's to read, over either transport: a
	// .fga parses here (pgauthzadm.ParseDSL), a .json is taken as is.
	var modelJSON []byte
	if fix.ModelFile != "" {
		mj, warnings, err := loadModelJSON(filepath.Join(filepath.Dir(fixPath), fix.ModelFile))
		if err != nil {
			return err
		}
		for _, w := range warnings {
			fmt.Println("WARN:", w)
		}
		modelJSON = mj
	}

	ctx := context.Background()
	var report *pgauthzadm.RunReport
	if m, err := apiModelFor(sf); err != nil || m != nil {
		if err != nil {
			return err
		}
		report, err = m.test(ctx, raw, modelJSON, *liveStore, *keep)
		if err != nil {
			return err
		}
	} else {
		report, err = runFixtureDirect(ctx, *dsn, &fix, modelJSON, *keep)
		if err != nil {
			return err
		}
	}
	if *keep {
		defer fmt.Println("kept store:", report.Store)
	}
	for _, r := range report.Results {
		if r.Failed {
			fmt.Printf("    FAIL  %s  (%s)\n", r.Name, r.Detail)
			if r.Note != "" {
				fmt.Printf("          note: %s\n", r.Note)
			}
		} else {
			fmt.Printf("    PASS  %s\n", r.Name)
		}
	}
	fmt.Printf("\n==> %d passed, %d failed (of %d checks)\n", len(report.Results)-report.Failed, report.Failed, len(report.Results))

	if *junit != "" {
		out, err := pgauthzadm.JUnit(fixPath, report)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*junit, out, 0o644); err != nil {
			return err
		}
	}
	if report.Failed > 0 {
		return fmt.Errorf("%d fixture checks failed", report.Failed)
	}
	return nil
}

// runFixtureDirect runs the fixture over the database connection: one
// transaction — the run's store is ephemeral (no partitions, no lock on
// the engine's tuples table) and gone with the rollback or commit, kept
// with --keep-store only through the commit.
func runFixtureDirect(ctx context.Context, dsn string, fix *pgauthzadm.Fixture, modelJSON []byte, keep bool) (*pgauthzadm.RunReport, error) {
	// Ephemeral store per run: fixtures are hermetic and repeatable.
	b := make([]byte, 4)
	rand.Read(b)
	opts := pgauthzadm.RunOptions{Store: "pgauthzctl_test_" + hex.EncodeToString(b), KeepStore: keep, ModelJSON: modelJSON}

	conn, err := connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // a no-op after Commit
	report, err := pgauthzadm.RunFixture(ctx, tx, fix, opts)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return report, nil
}
