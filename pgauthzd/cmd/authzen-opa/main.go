// authzen-opa — compat alias for `pgauthzd` pinned to the `compat-opa` profile
// (AuthZEN → OPA → PostgREST). Prefer `pgauthzd` with PGAUTHORIZER_PROFILE.
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
		fmt.Printf("authzen-opa %s (pgauthzd compat)\n", version)
		return
	}
	if err := app.Run("authzen-opa", config.ProfileCompatOPA); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
