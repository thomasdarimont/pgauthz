// pgauthzd — the unified pgauthz service (AuthZEN API + native /pgauthz/v1 over
// the PostgreSQL engine), capability-scoped by PGAUTHORIZER_PROFILE
// (decision-only | full). See internal/app for the entrypoint. The
// security guarantee comes from the DB connection ROLE, not the flag: a
// decision-only instance connects with a role that physically cannot write and
// asserts so at startup. This is the single binary — the former
// authzen-direct/authzen-opa commands are now just profiles of it.
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
	if err := app.Run("pgauthzd", version); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
