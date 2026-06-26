# Authorization as a JOIN (data filtering)

Demonstrates filtering an application table by ReBAC authorization in a single
SQL statement — the in-database alternative to the external "partial evaluation
→ SQL filter" pattern (Axiomatics, Cerbos query plans, OPA partial eval, Oso
data filtering).

Because pgauthz is SQL in the same Postgres as your data, you don't translate a
residual policy expression into a `WHERE` clause via an ORM adapter — you JOIN
[`authz.list_objects(...)`](../../db/engine/access.sql) (called without a limit,
so it returns the full authorized set) against your own table.

> **Topology note.** This works only when your app data shares a database with
> the engine — pgauthz **co-located** in the app DB, or a derived permissions
> slice **replicated** into it (see [`db/replication/`](../../db/replication/)).
> That is the *minority* setup. The common deployment is a **central authz
> service** reached over REST (OPA → PostgREST) or AuthZEN, where the data is in
> separate databases — there you call `list_objects` and filter your own query by
> the returned ids (`WHERE id = ANY(:ids)`, plus the wildcard flag) rather than
> JOINing. This example uses one database to show the co-located form.

## Run

```bash
# 1. load the demo model + seed (creates the 'demo' store)
cat examples/models/demo/model.sql examples/models/demo/seed.sql \
  | docker exec -i $(docker compose ps -q authz-db) psql -U authz -d authz

# 2. run the showcase
cat examples/filtering/filtering.sql \
  | docker exec -i $(docker compose ps -q authz-db) psql -U authz -d authz
```

## What it shows

- **Explicit grants** — `bob` `can_read` returns only his three documents.
- **Wildcards** — `nadia_auditor` has an object-wildcard grant (`document:*`), so
  the `is_wildcard` branch returns **all** rows. A naive `JOIN … ON
  a.object_id = d.id` would match nothing here and wrongly deny — always branch
  on `is_wildcard`.
- **No access** — an ungranted user returns zero rows.

The query cost tracks what the subject can reach (reverse expansion), not the
size of the table.

## Scope

This is the ReBAC-native answer to data filtering. It does **not** compile
conditions into predicates over your application's columns — if a decision
depends on an attribute that lives only in your tables, that is where an
ABAC/policy engine's partial evaluation fits. See the README's
[Authorization as a JOIN](../../README.md#authorization-as-a-join-data-filtering)
section.
