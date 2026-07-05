// authzen-direct — compat alias for `pgauthzd` pinned to the `decision-only`
// profile: direct pgx, READ-ONLY by DB role (eval + search + native read
// explain/watch), the historical behavior of this service. It asserts its
// connection role cannot write at startup. Prefer `pgauthzd` with
// PGAUTHORIZER_PROFILE; use the `full` profile (a writer-capable role) for the
// native write path.
package main

import (
	"flag"
	"fmt"
	"os"

	"thomasdarimont.de/authz/pgauthzd/internal/app"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("authzen-direct %s (pgauthzd compat)\n", version)
		return
	}
	if err := app.Run("authzen-direct", config.ProfileDecisionOnly); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
