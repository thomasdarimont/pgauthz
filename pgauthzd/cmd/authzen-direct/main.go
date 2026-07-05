// authzen-direct — compat alias for `pgauthzd` pinned to the `full` profile
// (direct pgx, read+write). Prefer `pgauthzd` with PGAUTHORIZER_PROFILE.
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
	if err := app.Run("authzen-direct", config.ProfileFull); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
