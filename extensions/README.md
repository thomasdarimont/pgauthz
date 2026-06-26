# extensions/

Optional native PostgreSQL extensions for pgauthz. The core engine is pure
PL/pgSQL and needs nothing here — these are **opt-in** add-ons that unlock extra
capabilities when baked into the Postgres image.

| Extension | Purpose | Enables |
|---|---|---|
| [`pg-cel`](pg-cel/) | CEL (Common Expression Language) evaluator (Rust/pgrx) | `lang='cel'` conditions — friendlier ABAC expressions than raw SQL |

Each extension is self-contained (its own `Cargo.toml` / build) and ships a
Dockerfile that bakes it into the stock `postgres` image. Nothing here is loaded
by `init.sh` on the default stack; an extension only takes effect when its image
is built (see each subdirectory's README) and the corresponding compose overlay
is used.

Future condition languages (cedar, rego, …) would land here as sibling
directories exposing their own evaluator, wired into the engine the same way —
see [`db/engine/core_internal.sql`](../db/engine/core_internal.sql)
(`authz._eval_condition_expr`).
