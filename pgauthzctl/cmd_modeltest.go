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
func cmdTest(args []string) error {
	fs, dsn := newFlags("model test")
	junit := fs.String("junit", "", "write JUnit XML to this path")
	keep := fs.Bool("keep-store", false, "keep the ephemeral store for debugging")
	pos := parseAll(fs, args)
	if len(pos) != 1 {
		return fmt.Errorf("usage: pgauthzctl model test <tests.authz.yaml> [--junit out.xml]")
	}
	fixPath := pos[0]

	raw, err := os.ReadFile(fixPath)
	if err != nil {
		return err
	}
	fix, err := pgauthzadm.ParseFixture(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", fixPath, err)
	}

	// Ephemeral store per run: fixtures are hermetic and repeatable.
	b := make([]byte, 4)
	rand.Read(b)
	opts := pgauthzadm.RunOptions{Store: "pgauthzctl_test_" + hex.EncodeToString(b), KeepStore: *keep}
	if fix.ModelFile != "" {
		modelJSON, warnings, err := loadModelJSON(filepath.Join(filepath.Dir(fixPath), fix.ModelFile))
		if err != nil {
			return err
		}
		for _, w := range warnings {
			fmt.Println("WARN:", w)
		}
		opts.ModelJSON = modelJSON
	}

	ctx := context.Background()
	conn, err := connect(ctx, *dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	report, err := pgauthzadm.RunFixture(ctx, conn, fix, opts)
	if err != nil {
		return err
	}
	if *keep {
		defer fmt.Println("kept store:", report.Store)
	}
	for _, r := range report.Results {
		if r.Failed {
			fmt.Printf("    FAIL  %s  (%s)\n", r.Name, r.Detail)
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
