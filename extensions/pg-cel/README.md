# pg_cel — CEL conditions for pgauthz

A small [pgrx](https://github.com/pgcentralfoundation/pgrx) PostgreSQL extension
that evaluates [CEL](https://cel.dev/) (Common Expression Language) expressions,
so pgauthz conditions can be written in CEL instead of raw SQL.

```
sql : ($1->>'current_time')::timestamptz < ($2->>'expires')::timestamptz
cel : timestamp(request.current_time) < timestamp(stored.expires)
```

CEL is non-Turing-complete (guaranteed to terminate), side-effect free, and has
real operators for numbers/strings/lists/timestamps — so ABAC conditions read
far more naturally than the `->>`/`::cast` SQL form. `lang='sql'` remains the
built-in default; CEL is purely additive.

## Why Rust/pgrx (and not cgo + cel-go)

pgauthz's whole premise is running safely *inside* Postgres, so the failure mode
matters more than spec completeness. A Rust/pgrx extension catches a panic at the
FFI boundary and turns it into a clean PostgreSQL error that **aborts the
transaction, not the server**. A cgo extension that embeds the Go runtime in the
backend process (e.g. [SPANDigital/pg-cel](https://github.com/SPANDigital/pg-cel),
which wraps cel-go) doesn't offer that guarantee. We deliberately expose the
**same function contract** as that project, so the two are interchangeable from
pgauthz's side — this crate is just the safer implementation we ship.

## The contract pgauthz depends on

```sql
cel_eval_bool(expression text, json_data text) -> boolean
cel_compile_check(expression text)             -> boolean
```

pgauthz's dispatcher (`authz._eval_condition_expr`) calls:

```sql
cel_eval_bool(<expr>, jsonb_build_object('request', <request_ctx>,
                                         'stored',  <stored_ctx>)::text)
```

so expressions reference the two context bags as **`request.*`** (the per-request
context) and **`stored.*`** (the tuple's stored condition context). A non-boolean
result returns `NULL` → pgauthz denies (fail closed); a compile/eval error is
raised and likewise caught as a deny. `cel_compile_check` is used at condition
**write time** to reject malformed expressions up front.

> Install into the engine's `authz` schema — the CEL evaluator is an engine
> dependency, and pgauthz references `authz.cel_eval_bool` /
> `authz.cel_compile_check`. `init.sh` does this with
> `CREATE EXTENSION pg_cel SCHEMA authz`.

## Build & enable

The usual path is the compose overlay, which builds this image and enables the
extension automatically:

```bash
docker compose -f compose.yml -f compose-cel.yml up -d --build
./init.sh        # runs CREATE EXTENSION IF NOT EXISTS pg_cel SCHEMA authz
```

Then CEL conditions just work:

```sql
INSERT INTO authz.conditions (store_id, name, expression, lang, required_context)
VALUES (authz._s('demo'), 'cel_not_expired',
        'timestamp(request.current_time) < timestamp(stored.expires)',
        'cel',
        '{"request": ["current_time"], "stored": ["expires"]}');
```

For a runnable end-to-end example against the demo store (load model.sql +
seed.sql first), see
[`examples/models/demo/demo_cel.sql`](../../examples/models/demo/demo_cel.sql).

### Build the image directly

```bash
# from the repository root (build context must include extensions/pg-cel)
docker build -f extensions/pg-cel/Dockerfile -t pgauthz-postgres-cel:18.4 .
```

### Local extension development (cargo-pgrx)

```bash
cargo install cargo-pgrx --version 0.19.1 --locked
cd extensions/pg-cel
cargo pgrx init --pg18 $(which pg_config)   # or: --pg18 download
cargo pgrx run                              # interactive psql with the ext loaded
cargo pgrx test                             # runs #[test] + #[pg_test]
cargo check                                 # fast compile check (no Postgres)
```

Per the cargo-pgrx conventions, pure CEL logic is covered by plain `#[test]`
and the SQL-surface checks by `#[pg_test]` (which boots a real backend).

## Caveats / scope

- **Types still need converting.** JSON delivers strings/numbers; use CEL's
  `timestamp(...)` / `duration(...)` for temporal comparisons. Cleaner than SQL
  casts, but not zero.
- **No IP/CIDR.** cel-rust has no native IP type, so IP-range conditions stay
  `lang='sql'`. Mixed stores are fine — `lang` is per condition.
- **Version pinning.** Keep `pgrx` in `Cargo.toml`, `PGRX_VERSION` in the
  Dockerfile, and `PG_MAJOR`/`POSTGRES_TAG` (compose) consistent with the server
  version. The CEL crate API (`cel-interpreter`, `json` feature) should be
  verified against the pinned version when bumping.
- **Throughput.** cel-rust evaluates the AST directly; ample for pgauthz (a
  handful of conditions per check), not tuned for hundreds of expressions per
  request.
