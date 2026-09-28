// pgauthzd — the unified pgauthz service (AuthZEN API + native /pgauthz/v1 over
// the PostgreSQL engine), capability-scoped by PGAUTHORIZER_PROFILE
// (decision-only | full). See internal/app for the entrypoint. The
// security guarantee comes from the DB connection ROLE, not the flag: a
// decision-only instance connects with a role that physically cannot write and
// asserts so at startup. This is the single binary — the former
// authzen-direct/authzen-opa commands are now just profiles of it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"thomasdarimont.de/authz/pgauthzd/internal/app"
	"thomasdarimont.de/authz/pgauthzd/internal/doctor"
)

var version = "dev" // -ldflags "-X main.version=..."

func main() {
	// Subcommand: `pgauthzd doctor` — preflight the deployment (config as the
	// daemon would load it, demo secrets, diagnostic gates, issuer bindings,
	// JWKS, DB role, callback listener, OPA, decision-log sink). Never serves.
	if len(os.Args) > 1 && os.Args[1] == "doctor" {
		os.Exit(runDoctor(os.Args[2:]))
	}
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("pgauthzd %s\n", version)
		return
	}
	if err := app.Run("pgauthzd", version); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	profile := fs.String("profile", "", "evaluate a deployment profile regardless of DEPLOYMENT_ENVIRONMENT: production")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	strict := fs.Bool("strict", false, "exit 2 on warnings, not only on failures")
	timeout := fs.Duration("timeout", 5*time.Second, "timeout for each network probe (JWKS, OPA, database)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch *profile {
	case "", "production", "prod":
	default:
		fmt.Fprintf(os.Stderr, "unknown profile %q (expected: production)\n", *profile)
		return 2
	}
	rep := doctor.Run(context.Background(), doctor.Options{
		ForceProduction: *profile != "", Timeout: *timeout, Version: version,
	})
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		rep.Print(os.Stdout)
	}
	return rep.ExitCode(*strict)
}
