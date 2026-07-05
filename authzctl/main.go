// authzctl — model-as-code toolchain for pgauthz.
//
// A thin CLI over the engine's model registry and OpenFGA import: author
// models as .fga files in git, test them in CI, publish them as immutable
// registry versions, and roll them out per store. Connects directly to
// PostgreSQL (operator/CI tool — the same trust tier as psql; model and
// registry operations are admin-by-design and not exposed via OPA).
package main

import (
	"fmt"
	"os"
)

const usage = `authzctl — pgauthz operations toolchain

Usage:
  authzctl <command> [<verb>] [flags]

Commands:
  model     Model-as-code lifecycle (the verbs below)
  version   Print the authzctl version

Model verbs (authzctl model <verb>):
  import    Load a model (.fga DSL or OpenFGA JSON) into a store
  publish   Publish a model file as the next immutable registry version
  plan      Dry-run: what would applying a registry version change?
  diff      The plan's changes, rendered as +/- lines
  apply     Make store(s) match a registry version
  export    Export a store's live model (canonical JSON, or --dsl text)
  status    A store's managed-model state and drift
  versions  List registry versions (optionally for one model)
  rollout   Fleet view for one model name
  test      Run a tests.authz.yaml fixture file against an ephemeral store

Further command groups (tuple, store, watch, ...) are planned.

Connection:
  --dsn or PGAUTHZ_DSN (e.g. postgres://authz:authz@localhost:55433/authz)
  Most verbs need admin; plan/diff/export/status/versions/rollout work
  with a reader DSN.
`

func main() {
	if len(os.Args) >= 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		cmdVersion()
		return
	}
	if len(os.Args) < 3 || os.Args[1] != "model" {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	verb, args := os.Args[2], os.Args[3:]

	var err error
	switch verb {
	case "import":
		err = cmdImport(args)
	case "publish":
		err = cmdPublish(args)
	case "plan":
		err = cmdPlan(args)
	case "diff":
		err = cmdDiff(args)
	case "apply":
		err = cmdApply(args)
	case "export":
		err = cmdExport(args)
	case "status":
		err = cmdStatus(args)
	case "versions":
		err = cmdVersions(args)
	case "rollout":
		err = cmdRollout(args)
	case "test":
		err = cmdTest(args)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
