// pgauthzctl — model-as-code toolchain for pgauthz.
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

const usage = `pgauthzctl — pgauthz operations toolchain

Usage:
  pgauthzctl <command> [<verb>] [flags]

Commands:
  model     Model-as-code lifecycle (the verbs below)
  issuers   Issuer bindings as code (the verbs below)
  version   Print the pgauthzctl version

Model verbs (pgauthzctl model <verb>):
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

Issuer verbs (pgauthzctl issuers <verb>) — what each trusted identity
provider's tokens may do, kept in authz.issuer_bindings and applied by every
pgauthzd running ISSUERS_SOURCE=env+db (trust itself stays in JWT_ISSUERS):
  list      The bindings and the revision in force (--json for the export shape)
  export    The bindings as a JSON file to keep in git (--out <file>)
  import    Upsert the bindings of a file (--prune: delete the rest; --dry-run)
  delete    Drop one binding (the issuer falls back to its environment)

Further command groups (tuple, store, watch, ...) are planned.

Connection:
  --server or PGAUTHZ_SERVER: pgauthzd's admin API (the long-run transport,
    ADMIN_API_ENABLED on a full instance), with --token / PGAUTHZ_TOKEN (a
    bearer token of the admin identity provider) or --cert/--key /
    PGAUTHZ_CLIENT_CERT/_KEY (a client certificate the admin listener's mTLS
    maps) and --ca / PGAUTHZ_CA; the audit names the credential. Today the
    issuers verbs run over it; the model verbs follow as their endpoints land.
  --dsn or PGAUTHZ_DSN (e.g. postgres://authz:authz@localhost:55433/authz):
    the direct database connection — installation-time work, model test,
    break-glass, and the verbs without an admin endpoint yet. Most need
    admin; plan/diff/export/status/versions/rollout and issuers list/export
    work with a reader DSN.
`

func main() {
	if len(os.Args) >= 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		cmdVersion()
		return
	}
	if len(os.Args) < 3 || (os.Args[1] != "model" && os.Args[1] != "issuers") {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	group, verb, args := os.Args[1], os.Args[2], os.Args[3:]

	var err error
	if group == "issuers" {
		switch verb {
		case "list":
			err = cmdIssuersList(args)
		case "export":
			err = cmdIssuersExport(args)
		case "import":
			err = cmdIssuersImport(args)
		case "delete":
			err = cmdIssuersDelete(args)
		default:
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
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
