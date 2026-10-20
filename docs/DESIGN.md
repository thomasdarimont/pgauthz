# Design Decisions

## Why PostgreSQL?

Zanzibar-style authorization is fundamentally a **graph-resolution problem over
relationship data** — exactly the kind of work a relational database with
recursive queries is built for. Implementing it *inside* PostgreSQL, rather than
as a separate service in front of it, has concrete advantages:

- **No separate service to operate** — the engine is SQL functions, not another
  process with its own deployment, scaling, monitoring, and failure modes. If
  you already run PostgreSQL, you already run the authorization engine. One
  thing to back up, patch, and secure.

- **No network hop on the hot path** — `check_access` is a function call, not a
  round-trip to an external PDP. Authorization decisions resolve at memory and
  index speed, in the same process that already holds your data.

- **Deploy it where it fits your topology** — because it's just SQL, you choose
  where it lives. Run it *inside* your application database and authorization
  checks and writes participate in the **same transaction** as your business
  logic — grant a relationship and update the resource atomically, with no
  dual-write problem and no drift between an external authz store and your data.
  Or run it as a **dedicated authorization database** and materialize a scoped
  extract of the effective permissions into an application-specific table that is
  periodically refreshed and replicated to where it's consumed (see
  [`db/replication/`](../db/replication)). The dedicated, central database is the
  common deployment — see [Deployment topologies](ARCHITECTURE.md#deployment-topologies).

- **Strong consistency by default** — PostgreSQL MVCC gives read-after-write
  consistency on a single instance with no consistency tokens to manage. Writes
  are immediately visible to subsequent checks in the same connection and, once
  committed, to everyone else.

- **Mature platform features come for free** — point-in-time recovery, logical
  and streaming replication, partitioning, fine-grained roles and `SECURITY
  DEFINER` privilege boundaries, and a decades-hardened query planner. The audit
  trail, time-travel queries, monthly partitioning, and read-replica scaling in
  this project are all built on stock PostgreSQL, not bespoke infrastructure.

- **Expressive enough for the whole model** — recursive CTEs and PL/pgSQL handle
  userset expansion, computed relations, and tuple-to-userset traversal directly,
  while conditions/ABAC reuse PostgreSQL's own expression evaluation. Condition
  expressions are evaluated in a **sandbox**: they run as a dedicated `authz_eval`
  role that has zero table and function access, so a malicious or buggy condition
  can compute over the supplied context but cannot read or modify any data. The
  full Zanzibar/OpenFGA model fits in ~4200 lines of SQL with no external
  dependencies.

- **Scales horizontally with stock replication** — authorization is read-heavy
  (`check_access` vastly outnumbers tuple writes), which is exactly the workload
  read replicas serve well. Send writes to the primary and fan checks out across
  streaming read replicas ([`compose-scaling.yml`](../compose-scaling.yml)), or use
  logical replication to push a derived/materialized permissions table out to
  consumers ([`db/replication/`](../db/replication)) — all built on PostgreSQL's
  native replication, no custom sharding layer.

- **SQL-native integration** — query and join authorization data with the rest
  of your schema, expose it over HTTP with pgauthzd's HTTP API (native
  `/pgauthz/v1` + AuthZEN), or front it with OPA — all without inventing a new
  transport or data format.

This is not the right tradeoff for everyone — if you need official polyglot SDKs,
native gRPC streaming, or a fully managed hosted service, see
[When to choose OpenFGA](COMPARISON.md#when-to-choose-openfga) below for an honest comparison.

## Security architecture

### SECURITY DEFINER as the access control boundary

All public API functions (`check_access`, `write_tuple`, `list_objects`, etc.)
are marked `SECURITY DEFINER` and owned by the dedicated **non-superuser**
`authz_owner` role (NOLOGIN), limiting the blast radius of any function flaw.
Application roles never receive direct `SELECT`, `INSERT`, or `DELETE`
grants on any authz table — they can only interact through the function API.

This means:

- The table schema is an implementation detail that can change freely
- Row-level security (RLS) is unnecessary — the function layer enforces
  access control, and the function body runs as `authz`, bypassing any
  RLS policies anyway
- All writes go through `write_tuple` / `delete_tuple`, which validate
  input, enforce namespace access, and fire audit triggers

### Role hierarchy

Five application roles — both `authz_auditor` and `authz_writer` inherit
from `authz_reader`, `authz_writer` also inherits `authz_recorder`, and
`authz_admin` inherits both branches:

```
                ┌── authz_auditor ──┐
     authz_reader                   ├── authz_admin
                └── authz_writer ───┘
   authz_recorder ───────┘
```

| Role | Capabilities |
|---|---|
| `authz_auditor` | Reader + audit trail queries, time-travel access checks (`audit_list_user`, `audit_list_object`, `audit_check_access`, `audit_list_actions`), the changefeed (`watch_changes`) and the action log (`list_events`) |
| `authz_reader` | Live access checks, search queries, explain |
| `authz_recorder` | Feed the action log only (`record_event`, `record_events_jsonb`, `reserve_event`) — a **PEP-only** credential: recorded events drive temporal gates, so a recorder can move a gate; never grant it to end-user-facing clients ([ADR 0012](adr/0012-action-log.md)) |
| `authz_writer` | Tuple management (write, delete, batch operations); inherits `authz_recorder` |
| `authz_admin` | Store lifecycle, model evolution (`model_register_type`, `model_register_relation`, `model_add_rule`, `model_remove_rule`), type restrictions, temporal gates (`add_gate`, `drop_gate`), namespace management, recorder allowlists (`grant_recorder_actions`), model import, maintenance (`cleanup_redundant_tuples`, event partitions and retention) |

This separation ensures compliance teams can review both current
permissions and historical access states, without being able to
modify any authorization data.

Default `PUBLIC` execute is revoked on all authz functions — only
explicitly granted roles can call anything.

### Namespace-based access control

Object types can be assigned to a namespace (e.g., `hr`, `accounting`).
When a type has a non-NULL namespace, the `_check_namespace_access()`
function verifies that `session_user` is a member of a PostgreSQL role
granted read or write access to that namespace.

This provides data-plane isolation between tenants or departments without
needing separate databases or schemas:

```sql
-- Only the app_hr role can read/write tuples for types in the 'hr' namespace
SELECT authz.grant_namespace_access('demo', 'hr', 'app_hr', true, true);

-- The portal role can read but not write
SELECT authz.grant_namespace_access('demo', 'hr', 'app_portal', can_read := true);
```

Types with `namespace = NULL` remain unrestricted (backward compatible).

### Condition expression sandboxing

Conditions are user-defined SQL boolean expressions evaluated at check
time. To prevent malicious expressions from reading or modifying data,
evaluation is sandboxed:

1. `_exec_condition()` is `SECURITY DEFINER` and owned by `authz_eval`
2. `authz_eval` is a role with zero table grants and zero function grants
3. Only pure SQL operators and casts work inside expressions — any
   attempt to `SELECT` from a table or call a privileged function (file
   access, `dblink`, …) fails with a permission error
4. Evaluation errors are caught and treated as deny (fail-closed)

This is a **capability** sandbox: it removes the ability to read data or
reach the host. The remaining risk is **resource exhaustion** — an
expression that burns CPU/time (`pg_sleep`, a catastrophic regex, a huge
`generate_series`/string), which needs no privileged function. Two further
bounds address that, applied in `db/security/roles.sql`:

5. **Time bound.** The service login roles carry a `statement_timeout`, so
   every authorization query — condition evaluation included — is bounded.
   A timed-out condition fails closed: the cancel propagates and aborts the
   check (`_eval_condition` re-raises `query_canceled` rather than swallowing
   it into a silent deny). Authorization checks are sub-millisecond, so the
   timeout only catches pathological expressions.
6. **Targeted capability removal.** `pg_sleep` (and `pg_sleep_for` /
   `pg_sleep_until`) — the obvious hang primitive, a PUBLIC builtin — is
   revoked from `PUBLIC`, so the sandbox cannot call it at all. This is
   defense-in-depth, not a substitute for the time bound: arbitrary
   expensive pure-SQL needs no builtin and is bounded only by the timeout.

Expressions are also **syntax-checked at write time** (a `BEFORE
INSERT/UPDATE` trigger test-compiles them in the sandbox and rejects
malformed ones), so a broken expression is rejected rather than stored and
silently denying.

### Audit trail

Every tuple INSERT and DELETE fires a trigger that records the change
in `tuples_audit`, including:

- The operation (`INSERT` / `DELETE`)
- A `performed_by` field that reads the session variable
  `authz.performed_by` (set by `write_tuple`/`delete_tuple` when
  `p_performed_by` is provided), falling back to `session_user`
- The full tuple data including condition context

The `performed_by` variable is set via `set_config(..., true)`, making
it transaction-local — it auto-resets after each call with no risk of
leaking between requests.

The audit trail is one of **two** append-only logs. It records how the
*graph* changed. The **action log** (`authz.events`, [ADR 0012](adr/0012-action-log.md))
records what principals *did*, as asserted by a trusted recorder, and is what
temporal gates evaluate; the check path never writes to it — a decision is
not an action. Both are monthly-partitioned with partition-drop retention.

## Performance

### Integer ID encoding

All type and relation names are stored as `smallint` IDs (2 bytes)
rather than text. The public API accepts text names and resolves them
internally via `_s()`, `_t()`, `_r()` helpers.

Benefits:
- Smaller row size in the tuples table (critical for cache hit ratio)
- Faster comparisons (integer vs text) on every index lookup
- Smaller indexes

Trade-off: one extra lookup per API call to resolve names → IDs.
These are cached by PostgreSQL's buffer cache after the first call.

### Tuple partitioning

The `tuples` table is LIST-partitioned by `object_type`. Every object
type gets a dedicated partition so that `check_access` queries benefit
from partition pruning — only the partition for the target object type
is scanned.

For high-volume object types, a second level of HASH sub-partitioning
on `object_id` can be added:

```sql
SELECT authz._ensure_tuple_partition(authz._s('demo'), 'document', 8);
-- Creates: tuples_demo_document (LIST)
--            tuples_demo_document_0 .. _7 (HASH by object_id)
```

This spreads tuples across multiple physical tables, reducing index
size and lock contention during concurrent writes.

### Covering partial indexes

Three indexes are tuned to the three query patterns of `_check_access`:

| Pattern | Index | Strategy |
|---|---|---|
| Direct tuple lookup | `idx_tuples_direct` | Partial (`WHERE user_relation IS NULL`) — skips userset tuples entirely |
| Userset expansion | `idx_tuples_userset` | Partial (`WHERE user_relation IS NOT NULL`) with `INCLUDE` columns for index-only scan |
| Reverse lookup | `idx_tuples_user` | For `list_objects` and write validation, `INCLUDE` avoids heap access |

The partial indexes split direct and userset tuples into separate
B-trees, which keeps each smaller and makes the planner's cost
estimates more accurate.

### Reverse expansion for search queries

`check_access` answers a single yes/no question. The search functions
answer set questions — and the naive way to answer them, "enumerate all
candidates and call `check_access` on each", scales with the store, not
with the answer. Both avoid that with **reverse expansion**: a recursive
CTE that walks the grant graph outward from the known end and collects
candidates, bounding the work by the *reachable set* rather than the
store size.

- **`list_objects`** ("which objects can subject S reach via relation R?")
  seeds from the tuples where S is the subject and walks **downward** —
  computed (`r` on A ⇒ `R` on A), userset (a tuple `A#r` grants something
  on B), and TTU (a link `A→B` plus a rule on B). Cost is O(S's reachable
  objects). Seeds use the user-keyed `idx_tuples_user`.
- **`list_subjects`** ("which subjects of type T hold relation R on object
  Z?") is the exact dual: it seeds from `(Z, R)` and walks **upward** to
  the subjects that imply it — computed (rule `R = computed(C)` ⇒ resolve
  `(B, C)`), userset (a tuple `(B, R, A#ur)` ⇒ resolve `(A, ur)`), and TTU
  (rule `R = ts→C` plus link `(B, ts, A)` ⇒ resolve `(A, C)`), collecting
  concrete subjects of type T at every reached node. Cost is O(Z's
  reachable subjects). It uses the object-keyed `idx_tuples_direct` /
  `idx_tuples_userset` — the same indexes as the `check_access` hot path.

**Over-approximate, then verify.** The recursive walk follows the
OR-union of every grant path and deliberately ignores `group_op`
(intersection / exclusion) and conditions. Because those mechanisms only
ever *remove* access, the walk is a guaranteed **superset** of the true
answer; a final `check_access` over each candidate makes the result
exact. This keeps the recursive query simple (one self-reference, a
single `LATERAL` with one branch per mechanism) while the authoritative
engine still decides every row. `UNION` (not `UNION ALL`) deduplicates,
which also terminates cycles.

**Scaling and the wildcard escape hatch.** For an object (or subject)
reachable through many individual grants, the candidate set approaches
that population and the call degrades to O(those rows) — which is just
the answer size. The escape hatch is a wildcard: a user wildcard
(`user_id = '*'`) collapses `list_subjects` to a single `('*', true)`
row, and an object wildcard (`object_id = '*'`) does the same for
`list_objects` — both O(1). Measured: a 3-grantee object in a 100k-user
store returns in ~7 ms (the prior all-users scan took ~11 s).

**The other list operations don't traverse the graph.** Only the *set*
searches over objects or subjects need reverse expansion — the rest are
already bounded:

- **`list_actions`** ("what can X do on Z?") iterates the relations the
  *model* defines for the object's type — a handful, fixed by the schema,
  not a function of the data — and checks each. Cost is O(model size).
- **`audit_list_actions`** is the point-in-time form of `list_actions`
  (it resolves against the reconstructed snapshot) and is likewise
  bounded by the model.
- **`audit_list_user`** and **`audit_list_object`** are not graph
  traversals at all — they are indexed scans of the `tuples_audit` log
  by subject or by object, returning O(matching events).

### Audit log partitioning

The `tuples_audit` table is RANGE-partitioned by `performed_at` with
monthly partitions. This provides:

- Efficient time-range queries (partition pruning on `performed_at`)
- Easy retention management: `DROP` an entire monthly partition instead
  of `DELETE` + `VACUUM`
- Partitions are created on-demand via `_ensure_audit_partition(year, month)`

A default partition catches rows that fall outside explicit partitions.

### Recursion limit

Access checks have a maximum resolution depth of 32 by default
(`_max_depth()`), overridable at any level via the `authz.max_depth`
GUC (the most specific setting wins: session > database > instance):

```sql
-- This session only (reverts when the connection closes):
SET authz.max_depth = '64';

-- All new sessions on one database:
ALTER DATABASE authz SET authz.max_depth = '64';

-- Whole PostgreSQL instance (superuser; persists in
-- postgresql.auto.conf; applies to new sessions after reload):
ALTER SYSTEM SET authz.max_depth = '64';
SELECT pg_reload_conf();

-- Revert the instance-wide setting:
ALTER SYSTEM RESET authz.max_depth;
SELECT pg_reload_conf();
```

Alternatively, set it in `postgresql.conf` (`authz.max_depth = '64'`),
or — for this project's docker compose stack — as a server flag on the
`authz-db` service in `compose.yml`:

```yaml
  authz-db:
    command:
      - postgres
      - -c
      - authz.max_depth=64
      # ... existing -c flags ...
```

Every recursion step — computed-relation hop, tuple-to-userset
traversal, userset expansion — consumes one level, so a typical schema
layer costs 2–3 levels; the default accommodates roughly 10 layers or
~28 levels of folder-style nesting. Exceeding the limit raises an
exception (like OpenFGA's "resolution too complex") rather than
silently denying. Cycles in the relationship graph are detected and
pruned independently of this limit, so the limit only bounds genuinely
deep chains.

## Scalability

### Streaming replication (read scaling)

For read-heavy workloads, the primary can stream WAL to one or more
read-only replicas. pgauthzd (the front door) connects to the replica for
access checks while writes go directly to the primary:

```
authz-primary (wal_level=replica)
  └── WAL stream
        └──▶ authz-replica (hot_standby=on, read-only)
               ├── pgauthzd (decision-only — check_access via pgx)
               └── pgauthzd (+ OPA_URL) + OPA sidecar
                     └── OPA calls back into pgauthzd's native /pgauthz/v1
```

The replica receives the full schema, functions, and data — no setup
beyond the initial `pg_basebackup`. Replication lag is typically
sub-second.

Replication is asynchronous, so replica reads are eventually consistent:
the case to guard is a **stale allow after a revoke**. Route
security-critical checks (especially confirming checks after a revoke) to
the primary, which is always read-your-writes — or opt into **freshness
tokens** ([ADR 0009](adr/0009-freshness-tokens.md)) to keep those reads on a
replica that has provably caught up. See the README "Consistency model"
section for the full contract.

See `compose-scaling.yml` for a working example.

### Logical replication (selective data distribution)

For application databases that need local authorization checks without
calling a central service, PostgreSQL logical replication can publish
selective subsets of authorization data:

```
authz-primary (wal_level=logical)
  ├── Publication: authz_metadata (stores, types, relations, models)
  ├── Publication: authz_accounting (selective tuple partitions)
  └── Publication: authz_derived (materialized_relations)
```

Key configuration parameters:

| Parameter | Recommended | Why |
|---|---|---|
| `wal_level` | `logical` | Required for logical replication |
| `max_wal_senders` | 25 | One per active subscription + initial sync workers |
| `max_replication_slots` | 10+ | One permanent slot per subscription, plus temporary slots during initial table sync. Increase when adding more subscribers |
| `max_sync_workers_per_subscription` | 10 | Sync multiple tables in parallel during initial subscription copy |

Tables without a primary key (tuples and tuple partitions) require
`REPLICA IDENTITY FULL` for UPDATE/DELETE replication.

Partitioned tables use `publish_via_partition_root = true` so changes
are published using the root table's identity, allowing the subscriber
to route them into its own local partition structure.

See `compose-replication.yml` and `db/replication/` for working examples.

## Where to put permissions: authz model vs. application

When integrating with the authorization engine, each permission must live
in one of two places:

1. **In the authz model** — defined as relations and resolution rules,
   evaluated by `check_access()`
2. **In the application** — defined in application code, evaluated locally

The right choice depends on whether the permission is a *structural
relationship* (who has what role on what resource) or a *business rule*
(under what circumstances does that role apply).

### Put it in the authz model when

- The permission depends on relationships already in the authorization
  graph (team membership, engagement hierarchy, data space assignments)
- Multiple applications need to agree on who has the permission (shared truth)
- You need `explain_access`, `list_objects`, `list_subjects`, or
  time-travel queries for that permission
- The permission flows through the same TTU chains as existing permissions
  (e.g., `can_approve` follows the same path as `can_edit` through
  assignments and engagements)

**Example:** `can_approve` on an assignment is a good fit for the authz
model — it's granted through team membership and engagement hierarchy,
the same graph that resolves `can_edit` and `can_view`.

### Keep it in the application when

- The permission depends on business logic that changes with application
  releases (e.g., approval thresholds, workflow state)
- It doesn't depend on the authorization graph at all
- Only one application cares about it
- It requires data that the authz engine doesn't have (invoice amounts,
  document status, user preferences)

**Example:** "can approve invoices over 10,000 EUR" combines a structural
permission (`can_approve`) with a business rule (amount threshold). The
structural part belongs in the authz model; the threshold belongs in the
application.

### Recommended pattern: combine both layers

Use the authz model for *who has what role on what resource* (structural
permissions) and let each application layer its own business rules on top:

```
Authz model (shared, graph-based):
  can_approve := accountant OR payroll_clerk     → who

Application layer (local, business logic):
  if check_access('can_approve', ...)            → structural check
     AND invoice.amount < approval_limit         → business rule
     AND invoice.status = 'pending'              → workflow state
  then allow
```

This separation keeps the authz model stable and reusable across
applications while allowing each application to evolve its business rules
independently.

### Avoid putting app-specific object types in the central model

Each application-specific type added to the authz model:

- **Increases coordination cost** — model changes require agreement across
  teams, and schema migrations must be rolled out to all subscribers
- **Adds tuples that other apps don't care about** — more partitions, more
  data, longer `list_objects` scans
- **Makes the model harder to understand** — the authorization graph
  becomes a mix of shared domain concepts and app-specific details

Instead, keep the authz model focused on shared domain entities
(engagements, assignments, data spaces, documents) and let each app
define its own fine-grained types locally.

### The conditions system as a middle ground

The conditions system (`non_expired_grant`, IP allowlists, usage quotas)
is the right place for constraints that are *inherently part of the access
grant itself* — they modify when or how a structural permission applies,
rather than adding business logic on top.

Use conditions when:
- The constraint is part of the grant (time window, IP range, quota)
- It should be evaluated consistently everywhere the permission is checked
- It needs to be visible in `explain_access` traces

Use application-side logic when:
- The constraint is about the *object being acted on* (invoice amount,
  document status) rather than the *grant itself*
- Different applications apply different thresholds to the same permission

### Temporal gates: history as a third layer

Conditions look at the request; **temporal gates** look at the *past* — what
the principal already did, as recorded in the action log by the PEP after
the action ran ([ADR 0012](adr/0012-action-log.md),
[MODEL_DESIGN §17](MODEL_DESIGN.md#17-temporal-gates-history-dependent-rules)).
They are centrally managed, history-dependent **veto** rules attached to an
`(object_type, relation)`, evaluated after the graph allows, over four fixed
primitives (`count_within`, `count_distinct_within`, `sum_within`,
`formerly_within`). The decision composes as

```
graph allows  AND  conditions allow  AND  temporal gates over recorded actions allow
```

Use a gate when the rule is a *permission* question a security or compliance
owner wants defined and enforced centrally — quotas and velocity caps, prior
approval, step-up freshness, lockout after repeated denials, separation of
duties, agent guardrails — and the same rule as for conditions applies: keep
*outcome* decisions (which account to debit, whether to retry, the next
workflow state) in the application. Gates are not a workflow engine, and they
bound *recorded* actions: the recorder (`authz_recorder`) is a trusted PEP
credential, and where a cap must hold exactly under concurrency the PEP uses
`reserve_event` rather than check-then-record.

## Model updates

### Models stored as data, not schema

Authorization models are stored as rows in `authz.models` — not as
DDL or code. This means model changes are data operations (INSERT/DELETE)
that can be performed at runtime without schema migrations or function
reloads.

The models table has a primary key (`id`) and a unique index preventing
duplicate rules. Two update strategies are available:

- **Full replacement** via `import_openfga_model` — atomic DELETE + INSERT
  within a single transaction (MVCC ensures no denial window)
- **Incremental** via `model_add_rule` / `model_remove_rule` /
  `model_remove_rules` — add or remove individual rules without
  touching the rest of the model

### Versioning via multi-store isolation

There is no built-in model versioning or migration system. Instead,
the multi-store architecture provides isolation for model evolution:

- Create a new store with the updated model
- Migrate tuples from the old store to the new one
- Switch applications to the new store
- Delete the old store when no longer needed

This is analogous to blue-green deployment for authorization models.
Each store is a fully independent namespace with its own types,
relations, conditions, and tuples.

### Model cloning for test and analysis environments

Because a model is pure data (rows in `types`, `relations`, `conditions`,
`models`), it can be exported from production and imported into a
separate test environment without copying any production tuples. The
test environment then operates on its own synthetic or anonymized data
while using the exact same authorization rules as production.

This enables:

- **Model validation** — test model changes against synthetic data
  before deploying to production
- **Permission analysis** — run `list_objects`, `list_subjects`, and
  `explain_access` against crafted scenarios without access to real
  user data
- **Regression testing** — verify that a model change doesn't
  accidentally grant or revoke access by comparing results across
  stores
- **Training and demos** — give new team members a fully functional
  authz environment with representative structure but no sensitive data

The workflow is straightforward:

1. Export the model SQL from production (or use the same model.sql file
   that was used to load production)
2. Create a new store in the test environment and load the model
3. Populate with synthetic tuples for the scenarios under test
4. Run access checks, explain traces, and search queries

Since stores are fully isolated, the test store can coexist on the
same database instance as production (using a different store name)
or on a completely separate instance.

### OpenFGA model import

The `import_openfga_model()` function accepts an OpenFGA model as JSON
and translates it into authz model rules. This provides a familiar
authoring format while using the PostgreSQL engine for evaluation.

Import is a model-level replacement: the function deletes all existing
model rules and type restrictions for the store, then inserts the new
model. Types, relations, and conditions are preserved (types and
relations are registered idempotently via `ON CONFLICT DO NOTHING`).
This ensures the model is always consistent with the import source
while avoiding the need to recreate tuple partitions.

### Atomic model replacement

Model changes take effect immediately for new `check_access` calls
(no cache invalidation needed — models are read from the table on each
call). Full model replacement via `import_openfga_model` runs as a
single PL/pgSQL function call — the DELETE and INSERT happen within
one transaction. PostgreSQL MVCC ensures concurrent readers see either
the complete old model or the complete new model, never an empty one.

### Evolving the model: adding and removing types and relations

The model can be evolved incrementally without a full replacement.
Each operation has different implications for existing tuples,
partitions, and downstream subscribers.

#### Adding a new object type

1. **Register the type and create its partition** — call
   `model_register_type()`, which inserts the type and creates its
   tuples partition (with optional hash sub-partitioning and namespace)
2. **Add model rules** via `model_add_rule()` — idempotent, returns
   the rule ID whether newly created or already existing

```sql
-- 1. Register type + create partition (hash sub-partitioned for high volume)
SELECT authz.model_register_type('demo', 'invoice', 8);

-- 2. Add model rules
SELECT authz.model_add_rule('demo', 'invoice', 'can_read', 'ttu',
    p_tupleset_relation := 'parent_assignment', p_tupleset_computed := 'can_view');
SELECT authz.model_add_rule('demo', 'invoice', 'can_approve', 'ttu',
    p_tupleset_relation := 'parent_assignment', p_tupleset_computed := 'can_approve');
```

**Impact on existing data:** none — new types start with zero tuples.

**Impact on replication subscribers:** if using logical replication
(approach 1: full replica), the new partition must be added to the
publication on the primary and the partition structure must be created
on each subscriber before it can receive tuples. For derived
permissions (approach 2), no subscriber changes are needed — new
permissions flow through `materialized_relations` automatically.

#### Adding a new relation to an existing object type

1. **Register the relation** — call `model_register_relation()`
   (idempotent — returns the existing ID if already registered)
2. **Add model rules** via `model_add_rule()` (idempotent)

```sql
-- 1. Register the new relation
SELECT authz.model_register_relation('demo', 'can_archive');

-- 2. Add model rule: can_archive on document := can_edit from in_internal_space (TTU)
SELECT authz.model_add_rule('demo', 'document', 'can_archive', 'ttu',
    p_tupleset_relation := 'in_internal_space', p_tupleset_computed := 'can_edit');
```

**Impact on existing data:** none — the new relation simply becomes
available for `check_access`. Existing tuples are not affected.
If the new relation is computed from existing relations (like the
example above), it works immediately without writing any new tuples.

**Impact on derived permissions:** if using materialized permissions,
run `refresh_all_materialized_relations()` to compute the new
relation for all existing objects. Incremental changes after that
are handled by the trigger/queue mechanism automatically.

#### Removing a relation from an object type

1. **Delete the model rules** via `model_remove_rules()` — removes all
   rules for the given relation on the target type (also cleans up
   associated type restrictions)
2. **Clean up orphaned tuples** — use `cleanup_redundant_tuples` to
   find and remove tuples that no longer match any model rule

```sql
-- 1. Remove all model rules for can_archive on document
SELECT authz.model_remove_rules('demo', 'document', 'can_archive');

-- 2. Find orphaned tuples (dry run first)
SELECT * FROM authz.cleanup_redundant_tuples('demo', 'document', 'can_archive');

-- 3. Delete them (audit trail records the cleanup)
SELECT * FROM authz.cleanup_redundant_tuples('demo', 'document', 'can_archive',
    p_dry_run := false);
```

**Impact on access checks:** immediate — `check_access` will no longer
find model rules for the removed relation and will return false.

**Impact on derived permissions:** if using materialized permissions,
run `refresh_all_materialized_relations()` to remove the now-denied
permissions from the lookup table. Or wait for the trigger/queue
mechanism to process affected objects as the tuples are deleted.

**Impact on audit trail:** audit records for the deleted tuples are
preserved — they record the DELETE action with the full tuple data.

#### Removing an object type

This is the most involved operation. The recommended order:

1. **Delete all tuples** for the type (fires audit triggers)
2. **Delete model rules and type restrictions** referencing the type
3. **Delete the partition** — detach and drop the partition table(s)
4. **Delete the type** from `authz.types`

```sql
DO $$
DECLARE
    s smallint := authz._s('demo');
    t_id smallint := authz._t(s, 'invoice');
BEGIN
    -- 1. Delete all tuples (audit trail preserved)
    DELETE FROM authz.tuples WHERE store_id = s AND object_type = t_id;

    -- Also delete tuples where this type appears as user_type in usersets
    DELETE FROM authz.tuples WHERE store_id = s AND user_type = t_id;

    -- 2. Delete type restrictions and model rules
    DELETE FROM authz.type_restrictions WHERE store_id = s AND object_type = t_id;
    DELETE FROM authz.models WHERE store_id = s AND object_type = t_id;

    -- 3. Detach and drop partition(s)
    -- For a simple partition:
    --   ALTER TABLE authz.tuples DETACH PARTITION authz.tuples_demo_invoice;
    --   DROP TABLE authz.tuples_demo_invoice;
    -- For hash sub-partitioned: drop each sub-partition, then the parent.

    -- 4. Delete the type
    DELETE FROM authz.types WHERE store_id = s AND id = t_id;
END;
$$;
```

**Caution:** also check for model rules on *other* types that reference
the removed type via TTU chains (e.g., `tupleset_relation` pointing to
a relation where the removed type was the linked object). These rules
won't cause errors — they'll simply never match — but they should be
cleaned up to keep the model understandable.

**Impact on replication subscribers:** for full replicas, the partition
must be dropped on each subscriber as well. For derived permissions,
run `refresh_all_materialized_relations()` after deletion to clean
up any stale entries.

## Integration patterns for application databases

When applications need to perform authorization checks locally (without
calling the central authz database), two approaches are available:

### Approach 1: Full authz replica

The application database receives the full authz schema, functions, and a
selective subset of tuples via PostgreSQL logical replication. The
application runs `check_access()` locally against replicated tuples.

```
authz-primary (wal_level=logical)
  └── Publication: selective tuple partitions
        │
        └──▶ app-db (subscriber)
               ├── authz schema + functions (deployed)
               ├── model rules (deployed)
               └── tuples (replicated)
               └── check_access() runs locally
```

**Trade-offs:**
- Schema and function changes must be coordinated across all subscriber databases
- Full graph resolution capability (TTU chains, computed relations, conditions)
- Immediate consistency once replication catches up (typically < 1s)

### Approach 2: Derived permissions (recommended for most apps)

The central authz database maintains a `materialized_relations` table —
a flat, denormalized lookup table of every (subject, relation, object) the
engine answers yes to, permissions and structural relations alike — plus
two small side tables,
`materialized_subjects` and `materialized_objects`, that list the subjects
and objects the engine knows (= have at least one tuple), and one
freshness row per store, `materialized_refresh_state`. Applications
subscribe to these tables only, and call two helpers:
`authz.check_permission()`, a single inlinable SQL expression, and
`authz.permissions_as_of(store)` / `authz.permissions_fresh(store,
max_staleness)`. No authz schema, functions, or model knowledge needed.

```
authz-primary
  ├── tuples (source of truth) ── audit log ── watch_changes (changefeed)
  ├── refresh_materialized_relations(): worker, resumes from a stored cursor,
  │     re-derives only the affected subject × object pairs via _decide
  └── Publication: materialized_relations + subjects/objects + refresh_state
        │
        └──▶ app-db (subscriber)
               ├── the tables (replicated)
               ├── authz.check_permission(...) in WHERE clauses / joins
               └── authz.permissions_as_of('demo') — how stale may this be?
```

**Trade-offs:**
- No schema coupling — the app only needs the flat permissions table
- Permissions are pre-computed, so there is a lag between a tuple change
  on the primary and the updated permission appearing on the subscriber
  (the changefeed's stability lag, 1 s by default + the worker's cadence +
  replication lag); `permissions_as_of()` states it
- The app cannot run `explain_access` or `list_objects` — only simple
  permission lookups
- Requires the audit profile on the primary (the changefeed is the source)
- One application's share: a row-filtered publication per namespace (below)

**Wildcards: the contract.** The engine cannot expand an object wildcard
(`document:*`) — it does not know the application's object universe — and
will not enumerate every user for a subject wildcard (`employee:*`). Such
grants are stored as literal `*` rows, and a `*` row is correct **only for a
subject or object the engine does not know**: a known one has authoritative
concrete rows (exclusions, markers and intersections already applied),
while an unknown one has no tuples and therefore nothing that could narrow
the wildcard. That is what the two side tables are for, and what
`check_permission()` applies:

```
subject keys = {user_id}   ∪ {'*' if (store, user_type, user_id) ∉ materialized_subjects}
object keys  = {object_id} ∪ {'*' if (store, object_type, object_id) ∉ materialized_objects}
allowed      = a row exists with user_id IN subject keys AND object_id IN object keys
```

A consumer that joins on the table directly must apply the same rule — a
plain `user_id = :me AND object_id = d.id` silently under-authorizes on
wildcards. `tests/test-replication.sh` proves the contract differentially:
every subject × relation × object of the demo and aia-acme stores, plus
unknown probes, must agree between the subscriber's `check_permission()`
and the primary's live `check_access()`.

**What a precomputed row cannot hold.** Conditions and contextual tuples
depend on the request, so the table stores the context-free, fail-closed
answer: a conditional grant is absent until its condition is dropped.
Temporal gates are per-principal history and are not evaluated at all (the
refresh calls `_decide` with an empty gate list). Decisions that must be
exact at the moment of the request stay on the live `check_access`. This
is the same shape as Auth0 FGA's hosted *Permissions Index*, which excludes
conditions and contextual tuples for the same reason.

**Install and ownership.** Load `materialized_relations.sql` after the
engine (full profile: it reads the audit changefeed); the functions are
`SECURITY DEFINER` (the engine's per-session memo table must be created
under one role), and the script transfers them to `authz_owner` when
`roles.sql` has run. The worker role needs only `EXECUTE` on
`refresh_materialized_relations()`.

### One application, one namespace

An application rarely wants the whole store's permissions, only those of
the object types it manages — its namespace. The derivation stays
store-wide (a team in a shared namespace grants access to documents in the
application's), but the *subscription* narrows: rows of
`materialized_relations` and `materialized_objects` carry the object
type's namespace, as part of their primary key so a publication row filter
may name it, and each application gets its own publication:

```sql
CREATE PUBLICATION authz_derived_dms FOR TABLE
    authz.materialized_relations WHERE (store = 'demo' AND namespace = 'dms'),
    authz.materialized_objects     WHERE (store = 'demo' AND namespace = 'dms'),
    authz.materialized_subjects,          -- store-wide: "known subject" is a store-wide notion
    authz.materialized_refresh_state      -- per store: as_of / permissions_fresh()
    WITH (publish_via_partition_root = true);
```

The subscriber uses the same minimal schema and helpers; it simply has no
rows for the other object types. Adding a type to the namespace needs no
change to the publication; moving a type between namespaces needs
`refresh_all_materialized_relations(store)`. Rows also carry
`is_permission`, the relation's declared kind ([MODEL_DESIGN.md → Relation
kinds](MODEL_DESIGN.md#relation-kinds-what-a-subject-is-versus-what-it-can-do)),
because the table holds both: what a subject may *do* (`can_read`) and what
it *is* (`member`, `parent`, `owner`, a third to a half of the rows in the
fixtures). An application that only asks "may X do Y?" reads
`WHERE is_permission`; one that wants those rows kept off the wire adds
`AND is_permission` to its publication filter, which is why the flag is in
the key — and a boolean, not an enum, because a row filter may not
reference a user-defined type. Re-declaring a kind needs `refresh_all` like
a namespace move. The worker's login role is
what the engine's namespace check sees inside `list_subjects`: grant it
`authz_namespace_bypass` or read access to every namespace, or the
expansion falls back to every known subject (correct, slow). Two things it
is not: a security boundary — any replication role that may read the
tables may subscribe to any publication; isolate tenants with stores — and
a saving on the primary, which still derives every namespace once. The
replication demo runs this as a third subscriber (`accounting-app-dms-db`,
publication `authz_derived_dms`, namespace `dms` = document + folder), and
`tests/test-replication.sh` asserts it holds exactly the primary's `dms`
rows after the snapshot and after every random batch.

`check_permission()` answers for **any** relation, exactly like the live
`check_access()`: asked about `viewer` it says whether the subject *is* a
viewer, asked about `can_read` whether it *may* read. The `is_permission`
flag classifies rows for consumers that list or filter; it never changes an
answer.

**Upgrading an existing deployment.** Logical replication matches tables and
columns by name and carries no DDL, so a subscriber created for the first
shape (`materialized_permissions`, column `permission`) must be changed by
hand, in this order: disable the subscription; load
`db/replication/materialized_relations.sql` on the publisher (it renames its
tables in place and repoints the `authz_derived` publication) and run
`refresh_all_materialized_relations(store)` for every registered store; on
the subscriber run `db/replication/upgrade-derived-tables.sql` and then
`schema-derived.sql`, and truncate the four derived tables; enable the
subscription, then `ALTER SUBSCRIPTION … REFRESH PUBLICATION` (refused while
disabled). The refresh re-copies everything: the first publication listed
leaf partitions, the current one publishes the partitioned root, which the
subscription meets as a new table — a copy into a subscriber still holding
the old rows collides on the key and never finishes, hence the truncate.
Changes after the copy's snapshot stream in as usual, so nothing is lost,
only re-copied. Verify with `pg_subscription_rel` and a content digest
against the publisher. `tests/test-replication.sh` runs this procedure
against a live subscription from the first shape, then checks row-for-row
parity and a write after resumption — the first version of the procedure,
without the truncate, failed exactly there.

### Change propagation for derived permissions

The source of change is the audit changefeed
([AUDIT.md → Watching for changes](AUDIT.md#watching-for-changes-changefeed)).
`refresh_all_materialized_relations(store)` takes the initial snapshot —
the blast radius of every tuple of the store, so its cost is linear in the
grants, not objects × subjects — and registers the store with a
`(performed_at, seq)` cursor from just before it; nothing on the write path
changes (no trigger on `authz.tuples`). On each run,
`refresh_materialized_relations()`:

1. captures one absolute, exclusive cutoff for the run —
   `watch_safe_until(lag)`: now minus the stability lag (1 s by default),
   capped at the start of the oldest transaction still open on the
   database, the worker's own included — and pulls one page of
   `watch_changes` per registered store after its cursor and before that
   cutoff. The feed is ordered by the writing transaction's start time, and
   a transaction may commit long after it started, so a fixed cutoff that
   never passes an open transaction is what makes "no row is skipped" hold;
   re-evaluating "now minus lag" per query would let the cutoff drift while
   the run works. **Operational limit:** any long-open transaction on the
   database, read-only ones included, holds the cutoff back and with it
   every revocation. The status shows `last_run_gate` and
   `oldest_open_txn_age`; the subscriber's `permissions_fresh(store,
   max_staleness)` lets a consumer refuse a stale copy and fall back to the
   live check. Set `idle_in_transaction_session_timeout` on application
   roles; bounded revocation latency independent of unrelated workloads
   needs a commit-ordered source (logical decoding), which this does not
   provide. The run also claims the deferred deltas that fell due (see 4)
2. computes each delta's blast radius — the subject × object pairs whose
   answer can have changed:
   - *objects*: the delta's object plus every object that reaches it
     through tuples (reverse closure over tuple edges, full depth, cycle
     safe); an object-wildcard delta seeds every object of the type,
     because their concrete rows are authoritative over the `*` row
   - *subjects*: the delta's own subject, always; for a userset
     (`team#member`) the userset's members and for an object reference (a
     parent folder, a manager, a classification — any type the model
     defines relations on) everyone holding any relation on that object,
     both from the engine's reverse expansion (`list_subjects`, gates off,
     expanded once per distinct reference); every known subject of the type
     only for a subject-wildcard delta, when `list_subjects` reports a
     wildcard, or for a manual whole-object entry. The closure walks the
     current tuples **and the batch's own deltas**: a deleted edge is the
     path a withdrawn permission came through, and a member whose
     membership and whose team's reference vanished in one batch is reached
     only that way
   - *relations*: every relation of the object's type
3. decides each pair through `_decide` (graph only) and **diffs** against
   the stored rows, so the table receives real inserts and deletes only (a
   CDC consumer downstream sees deltas); objects and subjects that lost
   their last tuple are delisted and lose their rows (wildcard-covered from
   then on), and — the other direction of the contract — a subject or
   object that *becomes* known stops being wildcard-covered, so it is
   derived against every object (subject) that carries a `*` row of its
   type, materializing what it inherited until then
4. files a deferred delta, due at `expires_at`, for every inserted tuple
   that expires — the feed reports writes, not the passing of time — so the
   rows an expiring grant produced are withdrawn when it expires
5. advances the cursor and `as_of` in `materialized_refresh_state`; logical
   replication delivers rows and freshness together

A write costs nothing extra; a typical grant or revoke re-derives one pair
(tens of milliseconds); a share with a team or a folder move re-derives the
affected objects for the subjects the engine's reverse expansion
(`list_subjects`, gates off) names — the members of the team, the holders
of a relation on the folder — so on the 50 k-user `drive` benchmark store a
userset share is 50 pairs in ~200 ms and the snapshot of the whole store
(the blast radius of every tuple, linear in the grants) 110 k pairs in
~200 s ([BENCHMARKS.md, 2026-10-20 addendum](BENCHMARKS.md#addendum-2026-10-20-derived-permissions-the-incremental-worker-on-drive)).
Every known subject is re-derived only where the contract demands it: a
subject-wildcard grant (`user:*` on an object) makes every known user's rows
on that object authoritative — 50 k pairs, ~100 s per public document at
that scale — so a store that makes documents public one by one is not a
good fit. `materialized_relations_status()`
shows the backlog, `as_of` and the last run per store. Run the worker:
- **Explicitly:** `SELECT authz.refresh_materialized_relations()` (again
  while any store's `feed_drained` is false)
- **Periodically:** via pg_cron (`SELECT cron.schedule(...)`)
- **Event-driven:** on `LISTEN authz_changes`, the audit log's doorbell

A physically deleted store (`delete_store`) is invalidated **synchronously**:
a trigger on `authz.stores`, installed by the replication script, drops the
store's rows and registration in the deleting transaction, so they replicate
atomically with it and a store recreated under the same name never inherits
its predecessor's permissions. The registration records the store's id —
its incarnation — and the subscriber's `check_permission()` requires a
registration row for the store, so even a stale row of an unregistered
incarnation answers false; a recreated store starts empty until
`refresh_all_materialized_relations` registers it. Registration, the
worker's cleanup (for registrations whose id no longer exists, leftovers
from before the trigger) and the trigger serialize per store name on an
advisory transaction lock, and cleanup only removes the incarnation it
identified, so it can never undo a concurrent re-registration. (A retired
store announces itself through `STORE_RETIRED` and is handled the same way.)

Deletion and snapshot never wait on each other in opposite order. Both
start with the engine's **store-wide lock** (the one checked writes hold
shared): `delete_store`/`retire_store` take it exclusively as their first
statement, before resolving the name and long before the partition DDL that
needs every reader of the store gone; `refresh_all_materialized_relations`
takes it shared, then the derived-rows lock, and only then resolves the
name. So a snapshot that meets a deletion in flight waits and then finds
the name gone (`Unknown store`) instead of registering the id being
deleted, and a deletion that meets a running snapshot waits and then
invalidates it. The worker holds `ACCESS SHARE` on the partitions it read
earlier in its transaction, exactly what a deletion's DDL waits for, so it
never blocks on a lock: it try-locks both per store, re-reads the
registration under the locks (its list of stores predates them), and leaves
a store someone else owns, or whose registration went meanwhile, for the
next run (its cursor does not move). The suite
runs each pairing with a held-open transaction and twelve seconds of all
three actors churning one store, and asserts no deadlock, no orphan row and
agreement with the engine.

A crashed worker resumes from the stored cursor; a page is replayed if its
run rolled back. One worker is the intended deployment, in its own `READ
COMMITTED` transaction: both entry points refuse any other isolation level,
because the cutoff is read from `pg_stat_activity` (not MVCC) while the
feed is read through the transaction's snapshot — under `REPEATABLE READ`
a change committed between snapshot and cutoff would be invisible yet past
the cutoff, skipped for good. Structural changes
are not pair-shaped: a page carrying `TYPE_REMOVED`, or tuple deltas whose
type no longer resolves, makes the worker rebuild that store in the same
run; `STORE_RETIRED` drops the store from the derived tables. Model changes
(rules, type restrictions) are not in the tuple feed at all — run
`refresh_all_materialized_relations(store)` after applying one. Every
function is `SECURITY DEFINER` with `search_path` pinned; `EXECUTE` is
revoked from `PUBLIC` and granted to `authz_admin`, and the worker role
needs it on `refresh_materialized_relations` only.

### Choosing between the approaches

| Consideration | Full replica | Derived permissions |
|---|---|---|
| Schema coupling | High — must deploy authz schema to every app DB | None — just one flat table |
| Query capability | Full (`check_access`, `list_objects`, `explain_access`) | Simple lookup only |
| Latency | Replication lag only (< 1s) | Changefeed stability lag (1 s) + worker cadence + replication lag; `permissions_as_of()` states it |
| App-side complexity | Low (call `check_access()`) | Low (call `SELECT EXISTS(...)`) |
| Combining with business rules | Call `check_access()` then apply rules | Call `check_permission()` then apply rules |
| Recommended for | Apps that need full graph queries or `explain_access` | Most apps that just need yes/no permission checks |

### Example: combining derived permissions with business rules

```sql
-- On the app database (subscriber):
-- Structural check from replicated permissions
SELECT authz.check_permission('demo',
    'internal_user', 'eva', 'can_approve', 'assignment', 'eng_42_accounting');
-- => true (eva is in accounting_team)

-- Application then applies its own business rules:
--   if check_permission('can_approve', ...) = true
--      AND invoice.amount < user.approval_limit
--      AND invoice.status = 'pending'
--   then allow_approval()
```

### Example: wildcards on the subscriber

`nadia_auditor` holds `viewer` on `document:*`. The derived table carries one
concrete row per document the engine knows and one literal `*` row:

```sql
-- On the app database (subscriber):
SELECT relation, object_id FROM authz.materialized_relations
 WHERE store = 'demo' AND user_id = 'nadia_auditor' AND object_type = 'document';
--  can_read | *             ← stands in for every document the engine never saw
--  can_read | doc_acc_001
--  can_read | doc_acc_002   …

-- A document created a second ago has no tuples. A naive lookup is wrong:
SELECT EXISTS (SELECT 1 FROM authz.materialized_relations
                WHERE store = 'demo' AND user_id = 'nadia_auditor'
                  AND permission = 'can_read' AND object_id = 'doc_brand_new');
-- => false   (the primary's check_access says true)

-- The helper applies the contract: '*' counts because doc_brand_new is not
-- in materialized_objects. For doc_acc_001 (known) only its concrete rows
-- count — so an exclusion on a known document is honoured.
SELECT authz.check_permission('demo','internal_user','nadia_auditor','can_read','document','doc_brand_new');
-- => true
SELECT authz.check_permission('demo','internal_user','alice','can_read','document','doc_brand_new');
-- => false  (alice is known and has no '*' grant)
```

The mirror case is a subject wildcard such as `employee:*`: a row with
`user_id = '*'` that `check_permission()` applies only to users absent from
`materialized_subjects`. A listing therefore filters with the helper, never
with a plain join on `user_id` and `object_id`:

```sql
SELECT d.* FROM documents d
 WHERE authz.check_permission('demo', 'internal_user', :me, 'can_read', 'document', d.id);
```

Writing a new object-wildcard tuple re-derives the subject against every
object of the type (their concrete rows must now say "allowed"); revoking
it removes the rows and, if that was the subject's last tuple, delists the
subject.

See `db/replication/` for a working demo of both approaches, including
a narrated demo script (`db/replication/demo-replication.sh`, section 7
walks through the wildcard contract). `./start-replication.sh` brings it
up next to the main stack (moved host ports, its own compose project),
initialises it and prints the connection strings; `./stop-replication.sh
[--clean]` takes it down.
