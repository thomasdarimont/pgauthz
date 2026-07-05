// pgauthzd — the unified pgauthz service (AuthZEN API over the PostgreSQL
// engine), capability-scoped by PGAUTHORIZER_PROFILE (decision-only | full |
// compat-opa). See internal/app for the shared entrypoint. The security
// guarantee comes from the DB connection ROLE, not the flag: a decision-only
// instance connects with a role that physically cannot write and asserts so
// at startup. Consolidates the former authzen-direct/authzen-opa commands
// (kept as thin compat aliases).
package main

import (
	"flag"
	"fmt"
	"os"

	"thomasdarimont.de/authz/pgauthzd/internal/app"
)

var version = "dev" // -ldflags "-X main.version=..."

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("pgauthzd %s\n", version)
		return
	}
	// No forced profile: PGAUTHORIZER_PROFILE decides (default resolves in config).
	if err := app.Run("pgauthzd", ""); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
