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

The registry verbs (`export`, `status`, `versions`, `plan`, `diff`, `apply`,
`rollout`) are thin shells over [`pgauthzadm`](../pgauthzadm), the embeddable
library the [management console](../console/README.md) uses in-process — one
implementation for the CLI and the UI.

`pgauthzctl version` prints the version plus the VCS revision it was built
from. Like the authzen binaries, the version is stamped at build time
(`go build -ldflags "-X main.version=0.7.0"`); a plain `go build` reports
`dev` with the revision.

## Connection

Two transports. **The admin API** of a pgauthzd (`ADMIN_API_ENABLED`,
[ADR 0016](../docs/adr/0016-issuer-bindings-and-admin-api.md)) is the
long-run one — no database credentials on laptops or in pipelines, the gate
and the audit are pgauthzd's, and the actor recorded is whoever
authenticated:

```bash
# a person: a token of the admin identity provider
export PGAUTHZ_SERVER=https://pgauthz-admin.example:8082
export PGAUTHZ_TOKEN=$(…)                         # or --token
# a machine (CI, a Terraform runner): a client certificate the admin
# listener's mTLS verifies and ADMIN_CLIENT_CERTS maps to a scope
pgauthzctl issuers list --server https://pgauthz-admin.example:8082 \
    --cert ci.crt --key ci.key --ca admin-ca.crt
```

Every verb runs over it except `model import` (a direct import into a
store) and `model test` (ephemeral stores): `publish` sends the parsed
OpenFGA model and the daemon converts it (`publish_model_openfga`); `apply`
is plan-first on the daemon and a blocked plan is the error; `--stores`
applies one store at a time. **The direct database connection** (`--dsn`
or `PGAUTHZ_DSN`, e.g. `postgres://authz:authz@localhost:55433/authz`)
stays for those two verbs, installation and break-glass — the same trust
tier as psql. Routine verbs over it print a note: it is on its way out for
them. Over `--dsn`, `plan`, `diff`, `export`, `status`, `versions`,
`rollout`, `issuers list` and `issuers export` work with a reader-grade
DSN; the rest needs admin.

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
pgauthzctl model export --store tenant_a --sql    # the engine calls that rebuild it (runnable in psql)
pgauthzctl model versions saas_core
```

For large fleets, orchestrate `apply` per store (or in bounded batches with
a pinned `name@version`) and use `rollout` as the progress/retry view — see
[MODEL_DESIGN §16](../docs/MODEL_DESIGN.md#16-sharing-one-model-across-stores-model-registry).

## Stores, recorders and namespaces (admin API only)

The `store` group is the first born on the admin API — there is no `--dsn`
form. Stores as upserts, their recorder allowlists (ADR 0012) and their
namespace grants, within the credential's scope:

```bash
pgauthzctl store list                                   # name, live/retired, model@version, description
pgauthzctl store set tenant_a --description "tenant A" # create or update; --retired retires
pgauthzctl store recorder-set tenant_a svc_approvals approve_sale,pay
pgauthzctl store recorder-lift tenant_a svc_approvals
pgauthzctl store namespace-grant tenant_a hr app_hr --read --write
pgauthzctl store namespace-revoke tenant_a hr app_hr
pgauthzctl store delete tenant_a --purge-audit --purge-decisions  # the erasure path; audit history and decision log only when asked
pgauthzctl store deletions tenant_a                       # the engine's deletion receipts: incarnation, time, by whom
pgauthzctl store purge-decisions tenant_a --store-id 7    # retry a failed --purge-decisions for that deleted incarnation
```

Every verb takes `--json` for the API's answer verbatim.

## Data subject requests (admin API only)

The GDPR path for the application teams and the DPO's scripts (the console's
*Data subject* tab offers the same three; the engine functions are in
`docs/API.md`). The takeout names the *references* — the object ids under
each type and relation — the applications hold the records:

```bash
pgauthzctl subject objects tenant_a user:alice                       # a table: type, relation, id (+ direct / wildcard / truncated)
pgauthzctl subject objects tenant_a user:alice --csv --out alice.csv # the hand-over file (store + subject in every row)
pgauthzctl subject objects tenant_a user:alice --relations owner,editor --object-types doc,folder
pgauthzctl subject export  tenant_a user:alice --out alice.json      # tuples both sides, effective objects, events, audit rows
```

There is no `subject erase`, on purpose: erasure comes **last** in a data
subject request — after the applications deleted their records by the
takeout's references — and belongs to the console's *Data subject* tab (a
person, a confirmation, the audit record) or `authz.erase_subject` in SQL,
not to a script that may run it first. `--json` prints the API's answer
verbatim here too.

## Tests

`go test ./...` runs the unit tests: the admin-API mode against a fake
pgauthzd (`api_test.go` — credentials, the error mapping, every verb's
request shape and output, an mTLS handshake with a generated CA); no stack
needed. `../tests/test-pgauthzctl.sh` runs them, builds the binary and
exercises the real lifecycle against the dev stack over `--dsn` and, when
the admin listener is up, over `--server`.

## Issuer bindings as code

What each trusted identity provider's tokens may do — the stores they
reach, the DB roles they may claim, which clients may assert subjects,
whether they are accepted at all — lives in `authz.issuer_bindings` and is
applied by every pgauthzd running `ISSUERS_SOURCE=env+db` without a restart
([ADR 0016](../docs/adr/0016-issuer-bindings-and-admin-api.md)). Trust
itself (issuer, audience, keys) stays in the instances' `JWT_ISSUERS`; a
row may only narrow it. These verbs keep the rows in git:

```bash
pgauthzctl issuers list                      # the rows and the revision in force
pgauthzctl issuers export --out issuers.json # the file to commit (audit columns left out)
# edit issuers.json …
pgauthzctl issuers import issuers.json --dry-run   # + create / ~ update / - delete
pgauthzctl issuers import issuers.json --prune     # one transaction; --prune drops rows the file no longer names
pgauthzctl issuers delete https://old-idp.example   # the issuer is back to its environment bindings
```

The file is `{"bindings": [{issuer, stores, db_roles, client_db_roles,
pep_clients, enabled, description}, …]}` — the shape the admin API
(`PUT /pgauthz/v1/admin/issuer-bindings`) and the console's Platform →
Issuers use. Validation is the engine's (anchored patterns, PEP clients
within stores); a row for an issuer no instance trusts, or one that widens
the environment's `stores`, is stored but reported and ignored by the
instances (their logs, `pgauthzd_issuers_reloads_total{result="rejected"}`,
the console's *not applied* badge). Over the admin API (`--server`) a write is recorded
with the credential's identity (`internal_user:alice`, `cert:spiffe://…`)
and an import is one PUT per issuer, in order, stopping at the first
refusal; over `--dsn` it is one transaction recorded as `--performed-by`
(default `pgauthzctl`), `list` / `export` need a reader DSN and `import` /
`delete` the admin tier (`authz_admin`).

## Test fixtures (`tests.authz.yaml`)

A superset of OpenFGA's store-test format; pgauthz extensions are additive
(`context` and `contextual_tuples` on check and every list case, golden
`explain` reason paths):

```yaml
model_file: ./model.fga        # or: model: saas_core@3 (registry ref)
                               # or: store: gdrive (a live store's current model)

tuples:
  - user: user:alice
    relation: member
    object: group:eng
  - user: group:eng#member     # userset
    relation: viewer
    object: folder:specs
  - user: user:zed             # a tuple the model must REFUSE (a relation
    relation: parent           # constraint's max_direct): asserted as a
    object: doc:design         # result of the run, not a seed
    refused: true

tests:
  - name: group members read via folder inheritance
    description: "REQ-12 — folder viewers read every document below"   # free text, shown with a failure
    check:
      - user: user:alice
        object: doc:design
        assertions: { can_read: true, can_write: false }
        notes: { can_write: "JIRA-4711: viewers never write" }         # per assertion
      - user: user:alice
        object: doc:design
        context: { current_time: "2026-07-05T10:00:00Z" }   # condition input
        assertions: { can_download: true }
    list_objects:
      - user: user:bob
        type: doc
        assertions: { can_write: [doc:readme] }
    list_subjects:                          # the reverse search; a wildcard grant lists as user:*
      - object: doc:design
        type: user
        assertions: { can_read: [user:alice, user:bob] }
    list_actions:                           # exactly what the subject holds and may do on the object
      - user: user:bob
        object: doc:readme
        expect: [owner, can_read, can_write] # reported as "may [can_read, can_write] · is [owner]"
                                            # when the model declares relation kinds
    explain:                                # golden resolution paths
      - user: user:alice
        relation: can_write
        object: doc:design
        expect_reasons: [no_direct_tuple, computed]
```

The runner (`pgauthzadm.RunFixture`, shared with the console's Scenarios)
creates an ephemeral store per run (hermetic, repeatable), imports the
model, seeds the tuples (a seed refused by a relation constraint's
`max_direct` becomes a failed result rather than a run error; `refused: true`
asserts the refusal), runs the assertions, and drops the store — all in
one transaction, with the engine's `authz.ephemeral_store` setting on, so
the store's types get no tuples partitions (no DDL, no lock on the engine's
tuples table while the run lasts) and the store never appears in the
committed state unless `--keep-store`. The
model comes from `model_file` (DSL or OpenFGA JSON), `model` (the registry)
or `store` — a live store's current model, copied loss-free (conditions,
gates and grant rules included, which the DSL cannot carry); a fixture
without a model line takes the store from `--store`, which is how the
console's saved scenarios and the examples' `scenarios.authz.yaml` run:
`pgauthzctl model test examples/models/gdrive/scenarios.authz.yaml --store gdrive`. `--junit out.xml` emits JUnit XML for CI; `--keep-store` retains the
store for debugging. Fixtures using `contextual_tuples` need a DSN whose
role holds `authz_contextual_reader` (the injection API is deliberately
gated) — a superuser test database also works.

## Conditions in DSL files

OpenFGA `condition` **bodies** are parsed but not imported: the OpenFGA CEL
vocabulary (bare parameter names) differs from pgauthz CEL
(`request.*` / `stored.*` namespaces), so an automatic translation would be
wrong more often than right. pgauthzctl prints a warning with a
`create_condition_cel` scaffold per condition — create them natively and
reference them from tuples as usual. Facet bindings (`[user:* with cond]`)
**are** imported: the engine binds the facet and, if the store has no
condition of that name yet, creates a deny-all placeholder so the binding is
enforced from the first write (tuples carrying it deny until you define the
real expression; the summary lists them under `placeholder_conditions`).
Models without DSL conditions round-trip cleanly.

## Not in phase 1

`model lint` (static analysis: unreachable relations, expensive patterns),
`model fmt`, modular models/imports, and DSL export
(`export --dsl` is display-only until a faithful OpenFGA JSON exporter
lands). Tracked in the roadmap.
