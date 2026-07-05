# Contributing

Thanks for your interest in pgauthz. It's an authorization engine, so changes
are held to a high bar for correctness and security — please read this first.

## Getting set up

```bash
./start.sh          # start the stack (PostgreSQL, pgauthzd, OPA) via docker compose
./bootstrap.sh      # install the engine + demo model and run all tests
```

Day to day:

```bash
./init.sh           # (re)install the full engine: reset → sqlx migrate run → load all profiles' code
./init-readonly.sh  # install only the read-only excerpt (substrate + read profiles)
./tests/test.sh     # SQL unit tests
./tests/test-all.sh # init + all suites (SQL, OPA, AuthZEN)
```

`init.sh` resets the dev schema, then applies the structural migrations in
`db/migrations/` with `sqlx` before loading the idempotent engine code — so it
needs `sqlx-cli` on PATH (`env.sh` also looks in `~/.cargo/bin`):

```bash
cargo install sqlx-cli --version 0.9.0 --no-default-features --features rustls,postgres
```

CEL work: `PGAUTHZ_CEL=1 ./bootstrap.sh` (builds and enables the `pg_cel`
extension; see [`extensions/pg-cel`](extensions/pg-cel/)).

## Engine layout

The SQL engine lives in `db/engine/`, grouped into **deployment profiles**
declared in [`db/engine/manifest.sh`](db/engine/manifest.sh) — `substrate`,
`read`, `write`, `audit`. The manifest is the single source of truth for load
order, consumed by `init.sh`, `init-readonly.sh`, `deploy/migrations/`, and the
replication scripts. **When you add an engine SQL file, register it in the
manifest with its profile** (and keep read-only deployments able to load
`substrate + read` alone). See `CLAUDE.md` → *SQL Engine Conventions*.

## Schema changes (migrations)

Structure (tables, indexes, types, partitioned parents) and code (functions,
views, triggers) are tracked **separately** — see
[`docs/adr/0001-schema-migrations.md`](docs/adr/0001-schema-migrations.md):

- **Code** in `db/engine/` is idempotent (`CREATE OR REPLACE …`, and
  `CREATE OR REPLACE TRIGGER` for triggers). Just edit the file and re-run
  `init.sh` — no migration needed for a function/view/trigger change.
- **Structure** changes are **forward-only migrations** in `db/migrations/`,
  applied by `sqlx` and tracked in `public._sqlx_migrations`. Add one with:

  ```bash
  sqlx migrate add --source db/migrations <short_change_name>   # sequential NNNN_ file
  ```

  Write the `ALTER`/`CREATE` delta (no `DROP SCHEMA`, no `down` file).
  `0001_baseline.sql` is **frozen** once a release is tagged — never edit it;
  every later structural change is a new file. A migration needing
  non-transactional DDL (e.g. `CREATE INDEX CONCURRENTLY`) gets `-- no-transaction`
  at the top. Run `./init.sh` to apply and keep `./tests/test.sh` green.

To eyeball the full assembled schema (structure + code), regenerate the
gitignored reference on demand:

```bash
./scripts/gen-schema.sh     # writes db/schema.generated.sql (throwaway container)
```

## Conventions

- **Public functions are `SECURITY DEFINER`** (set in `db/security/roles.sql`)
  so app roles never need direct table access. Don't grant table privileges.
- **Fail closed.** Errors on the decision path resolve to *deny*, never *allow*;
  conditions evaluate in the zero-privilege `authz_eval` sandbox.
- Everything is scoped to a `store_id`; respect namespace and type-restriction
  boundaries.
- Match the surrounding SQL style (comment density, naming, idioms).

## Tests are required

Add coverage for any behavior change under `tests/sql/` (helpers in
`tests/sql/tests_helpers.sql`); wire new files into `tests/test.sh`. For changes
that affect authorization *semantics* (resolution, conditions, exclusion/
intersection, wildcards, time-travel), add cases that assert both the allow and
the deny paths. `./tests/test.sh` must be green.

## Pull requests

- Keep PRs focused; describe the behavior change and the security implications.
- **Security-sensitive changes** — anything touching `SECURITY DEFINER`
  functions, role grants, the condition sandbox, namespace isolation, or
  resolution semantics — should get an extra, careful review and a clear note in
  the PR description of why the access boundary is preserved.
- Reference design rationale in `docs/DESIGN.md` / `docs/ARCHITECTURE.md`; for
  changes to authorization semantics, capture the reasoning there.
- Report security vulnerabilities privately — see [`SECURITY.md`](SECURITY.md),
  not a public issue or PR.

## Releasing

Cutting a tagged release follows a fixed flow (bump → write CHANGELOG notes →
push → CI green → tag) with a pre-release checklist. See
[`docs/RELEASING.md`](docs/RELEASING.md).
