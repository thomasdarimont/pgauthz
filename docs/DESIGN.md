# Design Decisions

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

Four application roles — both `authz_auditor` and `authz_writer`
inherit from `authz_reader`, and `authz_admin` inherits both:

```
                ┌── authz_auditor ──┐
     authz_reader                   ├── authz_admin
                └── authz_writer ───┘
```

| Role | Capabilities |
|---|---|
| `authz_auditor` | Reader + audit trail queries, time-travel access checks (`audit_list_user`, `audit_list_object`, `audit_check_access`, `audit_list_actions`) |
| `authz_reader` | Live access checks, search queries, explain |
| `authz_writer` | Tuple management (write, delete, batch operations) |
| `authz_admin` | Store lifecycle, model evolution (`model_register_type`, `model_register_relation`, `model_add_rule`, `model_remove_rule`), type restrictions, namespace management, model import, maintenance (`cleanup_redundant_tuples`) |

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
the primary, which is always read-your-writes; there is no revision-token
(zookie) API yet. See the README "Consistency model" section for the full
contract.

See `compose-scaling.yml` for a working example.

### Logical replication (selective data distribution)

For application databases that need local authorization checks without
calling a central service, PostgreSQL logical replication can publish
selective subsets of authorization data:

```
authz-primary (wal_level=logical)
  ├── Publication: authz_metadata (stores, types, relations, models)
  ├── Publication: authz_accounting (selective tuple partitions)
  └── Publication: authz_derived (materialized_permissions)
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
permissions flow through `materialized_permissions` automatically.

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
run `refresh_all_materialized_permissions()` to compute the new
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
run `refresh_all_materialized_permissions()` to remove the now-denied
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
run `refresh_all_materialized_permissions()` after deletion to clean
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

The central authz database maintains a `materialized_permissions` table —
a flat, denormalized lookup table. Applications subscribe to this table
only. No authz schema, functions, or model knowledge needed.

```
authz-primary
  ├── tuples (source of truth)
  ├── trigger: tuple change → queue affected objects
  ├── process_permissions_refresh_queue() → re-evaluates permissions
  └── Publication: materialized_permissions
        │
        └──▶ app-db (subscriber)
               ├── materialized_permissions (replicated)
               └── SELECT EXISTS(...) for access checks
```

**Trade-offs:**
- No schema coupling — the app only needs the flat permissions table
- Permissions are pre-computed, so there is a lag between a tuple change
  on the primary and the updated permission appearing on the subscriber
  (queue processing time + replication lag)
- The app cannot run `explain_access` or `list_objects` — only simple
  permission lookups

### Change propagation for derived permissions

When a tuple changes on the primary:

1. A row-level trigger fires and queues the directly affected object plus
   objects reachable via reverse TTU traversal (2 levels deep)
2. The trigger sends `pg_notify('authz_permissions_changed')` to notify
   external listeners
3. A worker (pg_cron, external service, or explicit call) processes the
   queue by re-evaluating permissions for each queued object
4. Updated permissions are written to `materialized_permissions`
5. PostgreSQL logical replication delivers the changes to subscribers

The queue can be processed:
- **Explicitly:** `SELECT authz.process_permissions_refresh_queue()`
- **Periodically:** via pg_cron (`SELECT cron.schedule(...)`)
- **Event-driven:** via an external worker listening on the NOTIFY channel

### Choosing between the approaches

| Consideration | Full replica | Derived permissions |
|---|---|---|
| Schema coupling | High — must deploy authz schema to every app DB | None — just one flat table |
| Query capability | Full (`check_access`, `list_objects`, `explain_access`) | Simple lookup only |
| Latency | Replication lag only (< 1s) | Queue processing + replication lag |
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

See `db/replication/` for a working demo of both approaches, including
a narrated demo script (`db/replication/demo-replication.sh`).
