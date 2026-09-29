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
> service** — pgauthzd, reached over its native `/pgauthz/v1` REST API or
> AuthZEN 1.0 — where the data is in separate databases; there you call
> `list_objects` and filter your own query by
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
ABAC/policy engine's partial evaluation fits. The pattern is explained in full below.

## The pattern

The "which rows can this user see?" problem — *list filtering* — is usually
solved by external engines with **partial evaluation**: evaluate the policy
against the known inputs, emit a residual filter, then translate that filter
(an AST) into a `WHERE` clause via a per-ORM adapter so the database returns
only authorized rows.

**When does this apply?** Only in the **co-located** (or replicated-permissions)
[deployment topology](../../docs/ARCHITECTURE.md#deployment-topologies) — when your application data shares
a database with the engine. This is the *minority* setup. Most applications use
pgauthz as a **central authorization service** over HTTP (OPA → pgauthzd native
callback) or AuthZEN, where the authz data and your business tables live in **different
databases** — there you do **not** JOIN. Instead `list_objects` returns the
authorized id set over the wire and your app filters by it (`WHERE id =
ANY(:ids)`, honoring the wildcard flag), exactly as an OpenFGA-style engine hands
back ids for the app to query. The JOIN below is the *bonus* you get when the
data happens to be co-located — not a reason to move your schema into the authz
database.

In that co-located case, because pgauthz **is** SQL in the same Postgres as your
data, you skip the residual-expression compiler and the ORM adapter entirely —
you just **JOIN** `authz.list_objects(...)` (called without a limit it returns
the full reachable set) into a query over your own table:

```sql
-- Return only the documents Bob can read, with your own ordering/paging,
-- in one round-trip. The authorization set is computed once (MATERIALIZED).
WITH authorized AS MATERIALIZED (
    SELECT object_id, is_wildcard
      FROM authz.list_objects('demo','internal_user','bob','can_read','document')
)
SELECT d.*
  FROM documents d                                   -- your application table
 WHERE EXISTS (SELECT 1 FROM authorized WHERE is_wildcard)   -- public/wildcard → all rows
    OR d.id IN (SELECT object_id FROM authorized)            -- else: explicit grants
 ORDER BY d.created_at DESC
 LIMIT 20;
```

The cost tracks what Bob can reach (reverse expansion), not how many rows
`documents` has — and, co-located, there is no second service, no network hop,
and no dialect translation.

> **Wildcard rows are not ids.** A row with `is_wildcard = true` (e.g. an
> object-wildcard grant, `object_id = '*'`) means *every* object of the type is
> authorized. It must **widen** the filter, as above — a naive
> `JOIN … ON a.object_id = d.id` would match nothing for it and silently deny a
> user who actually has access to everything. Always branch on `is_wildcard`.

### Bounding the cost

Counter-intuitively, **a wildcard grant is the cheap case**: `list_objects`
returns a single `is_wildcard` row, not an enumeration, and the `is_wildcard`
branch hands filtering back to your own `WHERE`/`LIMIT`. The unbounded case is a
subject with a very large *reachable* set (e.g. via huge groups), where
`list_objects` returns many concrete ids and the `IN (…)` materialises all of
them — your `LIMIT` bounds the output, not that set. (Don't cap it by passing a
limit to `list_objects` — that silently under-authorises.) When the reachable set
can be large but your query is already selective, invert to
**filter-then-authorise** — let the indexed business filter pick candidates and
check each:

```sql
SELECT d.* FROM documents d
 WHERE d.team_id = 42                                    -- selective, indexed
   AND authz.check_access('demo','internal_user','bob','can_read','document', d.id)
 ORDER BY d.created_at DESC LIMIT 20;                    -- work ∝ rows scanned
```

Rule of thumb: **authorize-then-filter** (the JOIN) when the reachable set is
modest or authz drives the result; **filter-then-authorize** when your business
query is selective and the reachable set could be huge.

This is ReBAC's native answer to data filtering. What it deliberately does *not*
do is compile conditions into predicates over your application's columns — if a
decision depends on an attribute that lives only in your tables, an ABAC/policy
engine's partial evaluation is the better fit (see
[Comparison with OpenFGA](../../docs/COMPARISON.md#comparison-with-openfga) and `examples/filtering/`).
