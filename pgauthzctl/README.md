# pgauthzctl — model-as-code toolchain

A thin CLI over the pgauthz model registry and OpenFGA import: author
authorization models as `.fga` files in git, test them in CI, publish them
as immutable registry versions, and roll them out per store.

`.fga` files are **verbatim OpenFGA DSL** (parsed with the official
[`openfga/language`](https://github.com/openfga/language) transformer — no
new DSL), and the test fixture format is a superset of OpenFGA's store-test
YAML, so existing OpenFGA models and tests port directly.

```
model.fga (git) ──pgauthzctl publish──▶ registry version N (immutable)
                        │
tests.authz.yaml ──pgauthzctl test──▶ ephemeral store → check/list/explain asserts
                        │
registry ──pgauthzctl plan / apply──▶ canary store → tenant fleet
```

`pgauthzctl version` prints the version plus the VCS revision it was built
from. Like the authzen binaries, the version is stamped at build time
(`go build -ldflags "-X main.version=0.7.0"`); a plain `go build` reports
`dev` with the revision.

## Connection

`--dsn` or `PGAUTHZ_DSN`, e.g. the dev stack:

```bash
export PGAUTHZ_DSN=postgres://authz:authz@localhost:55433/authz
```

pgauthzctl is an **operator/CI tool** in the same trust tier as psql — model
and registry operations are admin-by-design (deliberately not exposed via
the OPA front door). `plan`, `diff`, `export`, `status`, `versions` and
`rollout` work with a reader-grade DSN; `import`, `publish`, `apply` and
`test` need admin (store creation / model writes).

## Lifecycle

```bash
# Author → test → publish → canary → fleet
pgauthzctl model test  ./tests.authz.yaml --junit report.xml
pgauthzctl model publish ./model.fga --name saas_core --message "$(git rev-parse --short HEAD)"
pgauthzctl model plan  saas_core --store tenant_canary        # exit 1 on blockers → CI gate
pgauthzctl model apply saas_core --store tenant_canary --plan-first
pgauthzctl model apply saas_core --stores tenant_a,tenant_b   # small fleets: one atomic tx
pgauthzctl model rollout saas_core                             # fleet view: versions + drift

# Inspect
pgauthzctl model status --store tenant_a
pgauthzctl model diff saas_core@3 --store tenant_a
pgauthzctl model export --store tenant_a          # canonical JSON (round-trippable)
pgauthzctl model export --store tenant_a --dsl    # human-readable (display only)
pgauthzctl model versions saas_core
```

For large fleets, orchestrate `apply` per store (or in bounded batches with
a pinned `name@version`) and use `rollout` as the progress/retry view — see
[MODEL_DESIGN §16](../docs/MODEL_DESIGN.md#16-sharing-one-model-across-stores-model-registry).

## Test fixtures (`tests.authz.yaml`)

A superset of OpenFGA's store-test format; pgauthz extensions are additive
(`context`, `contextual_tuples`, golden `explain` reason paths):

```yaml
model_file: ./model.fga        # or: model: saas_core@3 (registry ref)

tuples:
  - user: user:alice
    relation: member
    object: group:eng
  - user: group:eng#member     # userset
    relation: viewer
    object: folder:specs

tests:
  - name: group members read via folder inheritance
    check:
      - user: user:alice
        object: doc:design
        assertions: { can_read: true, can_write: false }
      - user: user:alice
        object: doc:design
        context: { current_time: "2026-07-05T10:00:00Z" }   # condition input
        assertions: { can_download: true }
    list_objects:
      - user: user:bob
        type: doc
        assertions: { can_write: [doc:readme] }
    explain:                                # golden resolution paths
      - user: user:alice
        relation: can_write
        object: doc:design
        expect_reasons: [no_direct_tuple, computed]
```

The runner creates an ephemeral store per run (hermetic, repeatable),
imports the model, seeds the tuples, runs the assertions, and drops the
store. `--junit out.xml` emits JUnit XML for CI; `--keep-store` retains the
store for debugging. Fixtures using `contextual_tuples` need a DSN whose
role holds `authz_contextual_reader` (the injection API is deliberately
gated) — a superuser test database also works.

## Conditions in DSL files

OpenFGA `condition` blocks are **parsed but not imported**: the OpenFGA CEL
vocabulary (bare parameter names) differs from pgauthz CEL
(`request.*` / `stored.*` namespaces), so an automatic translation would be
wrong more often than right. pgauthzctl prints a warning with a
`create_condition_cel` scaffold per condition — create them natively and
reference them from tuples as usual. Models without DSL conditions
round-trip cleanly.

## Not in phase 1

`model lint` (static analysis: unreachable relations, expensive patterns),
`model fmt`, modular models/imports, and DSL export
(`export --dsl` is display-only until a faithful OpenFGA JSON exporter
lands). Tracked in the roadmap.
