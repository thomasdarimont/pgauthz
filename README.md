# PostgreSQL Authorization Engine

[![CI](https://github.com/thomasdarimont/pgauthz/actions/workflows/ci.yml/badge.svg)](https://github.com/thomasdarimont/pgauthz/actions/workflows/ci.yml)

A pure PostgreSQL implementation of the [Google Zanzibar](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/) /
[OpenFGA](https://openfga.dev/) authorization model.
No external authorization service needed — just SQL functions
that resolve relationship tuples recursively.

## Features

- **Relationship-based access control (ReBAC)** — Zanzibar/OpenFGA model with direct, computed, and tuple-to-userset rules
- **Wildcard tuples** — `user:*` grants a relation to all users of a type without individual tuples (public/anonymous access)
- **Intersection and exclusion** — rule groups support AND (all rules must match) and BUT NOT (base must match, negated must not) semantics
- **Attribute-based access control (ABAC)** — conditions on tuples (time windows, IP ranges, quotas) evaluated at check time, written in SQL or, optionally, [CEL](#condition-languages-lang)
- **Contextual tuples** — ephemeral per-request relationships that are not persisted (VPN context, org selection)
- **Multi-store** — independent authorization namespaces with isolated types, relations, models, and tuples
- **Batch operations** — `write_tuples` / `delete_tuples` for efficient bulk insert and delete
- **Conditional / atomic writes** — `write_tuples_checked` applies preconditions (exists/absent) plus deletes and writes in one transaction (optimistic concurrency: race-free ownership transfer, "at most one owner")
- **Full audit trail** — immutable, monthly-partitioned audit log with application user tracking (`performed_by`)
- **Time-travel queries** — `audit_check_access` reconstructs permissions at any past point in time from the audit log
- **Watch / changefeed** — `watch_changes` streams tuple changes (cursored, filterable by object type / namespace / relation) plus a `NOTIFY authz_changes` doorbell, for cache invalidation / materialization / sync
- **AuthZen Search API** — `list_objects`, `list_subjects`, `list_actions` for discovery queries
- **OpenFGA import** — import existing OpenFGA JSON models and tuples directly
- **Namespace-based write access control** — restrict which applications can manage tuples for which object types within a shared store
- **PostgREST + OPA integration** — OPA is the single front door for reads *and* writes (JWT verification, policy-as-code, response caching); PostgREST bridges SQL functions to HTTP
- **AuthZEN 1.0 API** — standard [AuthZEN](https://openid.net/specs/authorization-api-1_0.html) Go API layer with two backends: direct PostgreSQL (`authzen-direct`) and OPA (`authzen-opa`)
- **Performance** — integer IDs, LIST partitioning by object type, covering partial indexes, store-scoped index pruning

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
  [`db/replication/`](db/replication/)). The dedicated, central database is the
  common deployment — see [Deployment topologies](#deployment-topologies).

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
  streaming read replicas ([`compose-scaling.yml`](compose-scaling.yml)), or use
  logical replication to push a derived/materialized permissions table out to
  consumers ([`db/replication/`](db/replication/)) — all built on PostgreSQL's
  native replication, no custom sharding layer.

- **SQL-native integration** — query and join authorization data with the rest
  of your schema, expose it over HTTP with PostgREST, or front it with OPA — all
  without inventing a new transport or data format.

This is not the right tradeoff for everyone — if you need official polyglot SDKs,
native gRPC streaming, or a fully managed hosted service, see
[When to choose OpenFGA](#when-to-choose-openfga) below for an honest comparison.

## Who is it for?

Primarily **enterprise platform teams** — the people who operate authorization as
shared infrastructure rather than wire it into a single application. The natural
users are:

- **IAM / authorization architects** designing the relationship model
- **central platform engineering teams** operating it as a service
- **security engineering teams** that need explainable, auditable decisions
- **PostgreSQL-focused SaaS vendors** embedding authz in a Postgres-native stack
- **regulated organisations** that must answer "who could do what, when, and why"

It is **less suited to an ordinary application team looking for a drop-in
library**. Those teams are usually better served consuming pgauthz through a
centrally operated service or an opinionated internal SDK than by running the
engine themselves.

The intended adoption model is **central operation, federated ownership**: a
platform team runs pgauthz (schema, upgrades, replication, the OPA front door),
while domain teams own their authorization models and relationship data within
governed boundaries — which **multi-store** isolation and **namespace-based write
control** make enforceable rather than a matter of convention.

## Setup

```bash
cd authz/pgauthz
./bootstrap.sh
```

`bootstrap.sh` starts PostgreSQL, PostgREST, and OPA via docker compose,
installs the engine, loads the **demo** example model, and runs all tests.

To install **only the engine** — schema, functions, OpenFGA import, audit
partitions, and security roles, with no example stores — run `./init.sh`
instead. Example models live in [`examples/`](#example-models) and are
loaded separately (see below).

## Connecting

```bash
docker exec -it $(docker compose ps -q authz-db) psql -U authz -d authz
```

## Compatibility

Versions the stack is built and tested against (the pinned versions in
`compose*.yml` / the build files). The engine is pure PL/pgSQL with no
extensions on the default path, so the only hard requirement is PostgreSQL; the
rest are the components of the reference deployment.

| Component | Version | Required? | Notes |
|---|---|---|---|
| **PostgreSQL** | 18.4 | **required** | The engine. Uses partitioning, generated identity, and JSONB; developed and tested on 18.x. |
| PostgREST | v14.13 | optional | REST bridge (read on 3000, write on 3001). |
| OPA | 1.17.1 | optional | Policy/JWT front door for reads and writes. |
| Go (AuthZEN services) | 1.26 | optional | `authzen-direct` / `authzen-opa`. |
| `sqlx-cli` | 0.9.0 | install/upgrade | Applies the structural migrations in [`db/migrations/`](db/migrations/) (tracked in `public._sqlx_migrations`). Slim Postgres-only build — `cargo install sqlx-cli --no-default-features --features rustls,postgres`. Baked into the [migration image](deploy/migrations/Dockerfile); `init*.sh` use a local install. Not needed at query time. |
| `pg_cel` extension | pgrx 0.19.1, `cel` 0.13 | optional | Only for `lang='cel'` conditions; built per PostgreSQL major (see [`extensions/pg-cel`](extensions/pg-cel/)). |

Pre-1.0 — pin to a tag (latest in the [CHANGELOG](CHANGELOG.md) / Releases) or a
specific commit for reproducible deployments; per semver, 0.x releases may carry
breaking changes between minor versions, so review the CHANGELOG before
upgrading. See [`SECURITY.md`](SECURITY.md) for the supported line.

## API

All public functions take the **store name** (e.g. `'demo'`) as the first parameter.

**User types** identify the kind of subject. They are defined in your authorization model and
can represent any actor category, for example: `internal_user`, `client_user`, `service_account`,
`api_key`, `device`, or `bot`.

**User IDs** in the examples below use human-readable names like `'alice'` or `'grace'` for
illustration purposes. In practice, these will typically be technical identifiers such as UUIDs,
OIDC subject claims, or employee numbers (e.g. `'550e8400-e29b-41d4-a716-446655440000'`).

**Notation:** Throughout this document, `type:id` (e.g. `team:payroll_team`) is shorthand for
an object or subject with the given type and ID. `type:id#relation` (e.g. `team:payroll_team#member`)
denotes a **userset** — the set of all subjects that have the specified relation on that object
(in this case, all members of the payroll team). This is documentation shorthand only; the API
always uses explicit separate parameters for type, ID, and relation.

### check_access — "Can user X do Y on object Z?"

```sql
-- Basic permission check: can Alice read the payroll document?
-- Use this to guard access to a resource before serving it.
SELECT authz.check_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001');
-- => true

-- Permission check with request context: evaluate conditional tuples
-- (e.g. time-limited grants) by passing runtime values like the current time.
SELECT authz.check_access_with_context('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001',
    '{"current_time": "2026-03-11T10:00:00Z"}'::jsonb);
-- => true (within the condition's time window)
```

### check_access_with_contextual_tuples — with ephemeral per-request tuples

Contextual tuples inject temporary relationships into a single access check
without persisting them. This is useful when authorization depends on
runtime context that is not stored as a permanent relationship — for example,
granting access only while a user is connected via VPN, during a specific
time slot, or within a particular client session. Can also be used to implement temporary deputy arrangements.

> **Privilege:** because a caller can inject the very tuple being tested, this
> is gated by a dedicated `authz_contextual_reader` role (not the general
> `authz_reader`). Grant it only to trusted PDP/backend callers; never expose
> it to untrusted clients. See [Access control roles](#access-control-roles).

```sql
-- Frank has no stored viewer tuple on doc_client_001
SELECT authz.check_access('demo',
    'internal_user', 'frank', 'viewer', 'document', 'doc_client_001');
-- => false

-- But with a contextual tuple injected at request time, access is granted
SELECT authz.check_access_with_contextual_tuples('demo',
    'internal_user', 'frank', 'viewer', 'document', 'doc_client_001',
    contextual_tuples => ARRAY[
        --  user_type,       user_id, user_relation (NULL = direct, not via group), relation, object_type, object_id
        ROW('internal_user', 'frank', NULL,          'viewer',  'document',    'doc_client_001')
    ]::authz.tuple_input[]
);
-- => true

-- The contextual tuple was NOT persisted — subsequent checks deny access
SELECT authz.check_access('demo',
    'internal_user', 'frank', 'viewer', 'document', 'doc_client_001');
-- => false
```

### list_objects — "Which objects of type Z can user X do Y on?"

```sql
-- Resource discovery: find all documents Bob is allowed to read.
-- Use this to populate a user's document list or search results.
SELECT * FROM authz.list_objects('demo',
    'internal_user', 'bob', 'can_read', 'document');
-- => doc_payroll_001, doc_acc_001, doc_tax_001
```

`list_objects` finds these by **reverse expansion**: it starts from Bob's
own grants and walks the relationship graph outward, so its cost tracks
how much Bob can reach — not how many documents exist in the store.

### list_subjects — "Which users of type X can do Y on object Z?"

```sql
-- Access review: find all users who can read a specific document.
-- Use this for sharing dialogs or compliance reviews.
SELECT * FROM authz.list_subjects('demo',
    'internal_user', 'can_read', 'document', 'doc_payroll_001');
--  subject_id | is_wildcard
-- ------------+-------------
--  alice      | f
--  bob        | f
--  julia      | f
```

`list_subjects` is the mirror image of `list_objects`: it starts from the
object and walks the relationship graph *up* to the users who can reach
it, so its cost tracks how many users that object is shared with — not the
total number of users in the store. A public object shared via a `*`
wildcard returns a single wildcard row (below) instead of every user.

When a wildcard grant applies, the result includes a typed wildcard row —
`subject_id = '*'` with `is_wildcard = true` — meaning **every user of
this type has access**. `'*'` cannot collide with a real user ID
(`write_tuple` reserves it as the wildcard). Branch on `is_wildcard` and
render it as "Everyone" in sharing panels; never drop the row from access
reviews — it is the one that says the object is public. Take care when
counting or diffing results (the wildcard row is not one user), and when
passing subject IDs into pattern contexts (`*` is a metacharacter in
LDAP filters and globs).

### list_actions — "What can user X do on object Z?"

```sql
-- Action discovery: find all actions Alice can perform on a document.
-- Use this to enable/disable UI buttons based on the user's effective permissions.
SELECT * FROM authz.list_actions('demo',
    'internal_user', 'alice', 'document', 'doc_payroll_001');
-- => can_edit, can_read
```

`list_actions` needs no graph traversal: it checks the handful of
relations the *model* defines for the object's type, so its cost is fixed
by the schema, not the data. (The same holds for `audit_list_actions`;
the `audit_list_user` / `audit_list_object` trail queries are plain
indexed scans of the audit log.)

### explain_access — "WHY was access allowed or denied?"

Like `check_access`, but returns a **structured decision explanation** instead
of a bare boolean — the resolution tree, a typed reason per step, and a minimal
"why". Use it for debugging models, building audit/why views, and powering
"why can/can't I see this?" UIs.

```sql
SELECT authz.explain_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001');
```

Returns JSON:

```jsonc
{
  "result":   true,                  // boolean alias of decision.allowed
  "decision": { "allowed": true,
                "reason":  "ttu" },  // the minimal cause of the outcome
  "summary":  "internal_user:alice → can_read → document:doc_payroll_001 = ALLOWED (ttu)\n  ✓ ...",
  "trace": [                           // flat, evaluation-ordered steps
    { "step": 1, "depth": 4, "rule_type": "direct", "reason": "direct_tuple",
      "subject": "internal_user:alice", "relation": "member",
      "object": "team:payroll_team", "result": true, "detail": "tuple found",
      "model_rule_id": 1889, "group_id": 0, "group_op": "or", "negated": false,
      "duration_ms": 0.07 }
    // ... one object per evaluation step
  ],
  "tree": {                            // the same steps as a nested tree
    "subject": "internal_user:alice", "relation": "can_read",
    "object": "document:doc_payroll_001", "allowed": true, "reason": "ttu",
    "children": [ /* each step's nested children, for direct rendering */ ]
  }
}
```

`trace` is the flat step list; `tree` is the same steps reshaped into the
nested resolution tree (a synthetic root with the decision, the recursion
nested underneath) — render it directly as a collapsible tree.

Each step also carries `model_rule_id`, `group_id`, `group_op`
(`or`/`intersection`/`exclusion`), and `negated`, so a step ties back to the
exact model row — join `model_rule_id` to `authz.models_view` to see the rule
definition. (Group-verdict and cycle steps have no single rule, so
`model_rule_id` is null there.)

A `condition_denied` step also reports `condition_name` and
`condition_missing_keys` — the required request/stored context keys that were
not supplied (e.g. `["request.current_time"]`). An empty list means the
condition simply evaluated to false on the given inputs (e.g. an expired
grant) rather than missing input.

`decision.reason` is a stable, typed code. For **ALLOW** it is the granting
step's reason — `direct_tuple`, `wildcard_tuple`, `object_wildcard_tuple`,
`contextual_tuple`, `computed`, `userset`, `ttu`, or `intersection_satisfied`.
For **DENY** it is one of `excluded`, `intersection_unsatisfied`,
`condition_denied`, or `no_matching_rule`.

```sql
-- Just the winning path (drop the failed branches):
SELECT authz.explain_access('demo', 'internal_user', 'alice',
    'can_read', 'document', 'doc_payroll_001', p_successful_only => true);

-- Redacted "safety mode" for untrusted UIs: strips subject/object identifiers
-- and free-text detail, keeping only types, relations, reasons, and the
-- decision (so a UI can show *why* without leaking tuple/group names).
SELECT authz.explain_access('demo', 'internal_user', 'alice',
    'can_read', 'document', 'doc_payroll_001', p_redact => true);
-- subjects become "internal_user:***", objects "document:***", detail null.
```

> Parse the trace `reason` codes and the `decision` object — they are
> machine-readable; the human-readable `summary` text is not, so don't parse
> it. `explain_access` is granted to `authz_reader` like the other read
> functions; gate it (or use `p_redact`) before exposing it to untrusted
> clients, since an unredacted trace reveals tuple and group names.

### write_tuple — Write a relationship tuple

Returns `true` if a new tuple was created **or an existing tuple's condition
changed** (re-writing with a different condition applies the new one and
audits the change), `false` if an identical tuple already existed (idempotent).
An optional `p_performed_by` parameter records the application user identity in the audit trail.

```sql
-- Add a user to a team
SELECT authz.write_tuple('demo',
    'internal_user', 'grace', 'member', 'team', 'payroll_team');
-- => true

-- Track who performed the write in the audit trail
SELECT authz.write_tuple('demo',
    'internal_user', 'grace', 'member', 'team', 'payroll_team',
    p_performed_by => 'admin');
```

### delete_tuple — Remove a relationship tuple

Returns `true` if deleted, `false` if no matching tuple existed.

```sql
-- Remove a user from a team
SELECT authz.delete_tuple('demo',
    'internal_user', 'grace', 'member', 'team', 'payroll_team');
-- => true (deleted)

-- Deleting an already-removed tuple is a no-op
SELECT authz.delete_tuple('demo',
    'internal_user', 'grace', 'member', 'team', 'payroll_team');
-- => false (already gone)
```

### write_tuples / delete_tuples — Batch operations

Efficiently insert or delete multiple tuples in a single statement.
Returns the number of tuples affected. Duplicates are silently skipped on insert.

```sql
-- Bulk onboarding: assign multiple users to their teams in a single statement.
-- Use this when provisioning accounts from an HR system or directory sync.
SELECT authz.write_tuples('demo', ARRAY[
    ROW('internal_user', 'grace', NULL,      'member', 'team', 'payroll_team'),
    ROW('internal_user', 'hank',  NULL,      'member', 'team', 'accounting_team'),
    ROW('internal_user', 'ivan',  NULL,      'member', 'team', 'tax_team')
]::authz.tuple_input[]);
-- => 3

-- Bulk removal: revoke specific team memberships for multiple users at once
SELECT authz.delete_tuples('demo', ARRAY[
    ROW('internal_user', 'grace', NULL, 'member', 'team', 'payroll_team'),
    ROW('internal_user', 'hank',  NULL, 'member', 'team', 'accounting_team')
]::authz.tuple_input[]);
-- => 2

-- With audit tracking
SELECT authz.write_tuples('demo', ARRAY[
    ROW('internal_user', 'grace', NULL, 'member', 'team', 'payroll_team')
]::authz.tuple_input[], p_performed_by => 'hr_system');
```

All batch functions also accept a **JSONB array** instead of a PostgreSQL composite array.
This is easier to use from HTTP clients (PostgREST) and languages without native composite-type support:

```sql
-- JSONB variant: same as above, but with a JSON array of objects.
-- Use the _jsonb suffix functions from HTTP clients (PostgREST) or
-- languages without native PostgreSQL composite-type support.
SELECT authz.write_tuples_jsonb('demo', '[
    {"user_type":"internal_user","user_id":"grace","relation":"member","object_type":"team","object_id":"payroll_team"},
    {"user_type":"internal_user","user_id":"hank","relation":"member","object_type":"team","object_id":"accounting_team"}
]'::jsonb, p_performed_by => 'hr_system');
-- => 2

-- JSONB batch elements may also carry conditional grants via the
-- optional "condition" / "condition_context" keys (the composite
-- tuple_input type has no condition fields — use this variant or
-- write_tuple for conditional tuples):
SELECT authz.write_tuples_jsonb('demo', '[
    {"user_type":"internal_user","user_id":"alice","relation":"viewer",
     "object_type":"document","object_id":"doc_temp_001",
     "condition":"non_expired_grant",
     "condition_context":{"grant_time":"2026-03-11T09:00:00Z","grant_duration":"2 hours"}}
]'::jsonb);

SELECT authz.delete_tuples_jsonb('demo', '[
    {"user_type":"internal_user","user_id":"grace","relation":"member","object_type":"team","object_id":"payroll_team"}
]'::jsonb);
-- => 1
```

### delete_user_tuples — Remove all tuples for a user

Revokes all permissions for a user in a single call. Useful for offboarding.

```sql
-- Employee offboarding: revoke all permissions for a departing user in one call.
-- Removes every tuple where this user is the subject, regardless of relation or object.
SELECT authz.delete_user_tuples('demo', 'internal_user', 'grace');
-- => 3 (number of tuples deleted)

-- Same with audit tracking to record which service triggered the offboarding
SELECT authz.delete_user_tuples('demo', 'internal_user', 'grace',
    p_performed_by => 'offboarding_service');
```

### audit_check_access — Point-in-time permission check

Reconstructs the tuple state **and the model rules** at any past point in time
by replaying the audit log, then runs a full access check against that snapshot.

```sql
-- Forensic analysis: verify whether a user had access at a specific past moment.
-- Use this for incident investigation or compliance audits.
SELECT authz.audit_check_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001',
    '2026-03-11T14:00:00Z'::timestamptz);
-- => true

-- Conditions that need request data beyond the reconstructed timestamp
-- (client IP, quotas, ...) take it via p_request_context; current_time
-- always reflects the requested point in time.
SELECT authz.audit_check_access('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_vpn_001',
    '2026-03-11T14:00:00Z'::timestamptz,
    p_request_context => '{"client_ip": "10.1.2.3"}'::jsonb);
```

> **Scope of reconstruction:** the audit log versions **tuples**, **model
> rules**, and **condition expressions** (`tuples_audit`, `models_audit`,
> `conditions_audit`), so `audit_check_access` resolves time T against the
> tuples, rules, *and* condition expressions as they were then — adding or
> removing a rule, or editing a condition's expression in place, does not
> rewrite past answers.
>
> **Versioning is transactional.** Audit rows are stamped with the
> *transaction* timestamp, so every change committed in one transaction
> shares a single version and time-travel sees that transaction's effect
> atomically — it can never land in the middle of a multi-step edit. To
> group related changes into one version, make them in one transaction
> (`BEGIN; … COMMIT;`); to make them separately observable in history,
> commit them separately.

### audit_list_user / audit_list_object — Audit trail queries

Query the immutable audit trail for a specific user or object, optionally
filtered by time range.

```sql
-- User audit trail: review all permission changes for a specific user.
-- Use this for access reviews or investigating what changed for a user.
SELECT * FROM authz.audit_list_user('demo', 'internal_user', 'alice');

-- Scoped audit: filter to a specific time range for targeted investigation
SELECT * FROM authz.audit_list_user('demo', 'internal_user', 'alice',
    '2026-03-01'::timestamptz, '2026-03-31'::timestamptz);

-- Object audit trail: review all permission changes on a sensitive resource.
-- Use this to see who was granted/revoked access to a specific document.
SELECT * FROM authz.audit_list_object('demo', 'document', 'doc_payroll_001');
```

Returns columns: `action` (INSERT/DELETE), `performed_at`, `performed_by`,
`relation`, `object_type`, `object_id`, `condition_name`, `condition_context`.

## Authorization as a JOIN (data filtering)

The "which rows can this user see?" problem — *list filtering* — is usually
solved by external engines with **partial evaluation**: evaluate the policy
against the known inputs, emit a residual filter, then translate that filter
(an AST) into a `WHERE` clause via a per-ORM adapter so the database returns
only authorized rows.

**When does this apply?** Only in the **co-located** (or replicated-permissions)
[deployment topology](#deployment-topologies) — when your application data shares
a database with the engine. This is the *minority* setup. Most applications use
pgauthz as a **central authorization service** over REST (OPA → PostgREST) or
AuthZEN, where the authz data and your business tables live in **different
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
[Comparison with OpenFGA](#comparison-with-openfga) and `examples/filtering/`).

## Example Queries

### Permission checks

```sql
-- Team-based access: Alice is a payroll_team member, so she can read payroll docs
SELECT authz.check_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001');
-- => true

-- Team isolation: Alice's payroll_team membership does not grant access to tax docs
SELECT authz.check_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_tax_001');
-- => false

-- Cross-team access via role: Bob is an advisor, which grants read on all
-- internal docs through the internal_collaborator computed relation
SELECT authz.check_access('demo',
    'internal_user', 'bob', 'can_read', 'document', 'doc_payroll_001');
-- => true

-- Role-based permission boundaries: Julia is an assistant (not advisor),
-- so she can read documents but cannot edit them
SELECT authz.check_access('demo',
    'internal_user', 'julia', 'can_read', 'document', 'doc_payroll_001');
-- => true
SELECT authz.check_access('demo',
    'internal_user', 'julia', 'can_edit', 'document', 'doc_payroll_001');
-- => false

-- Client user isolation: Carol belongs to a client org and can read
-- client-space docs, but write access is restricted to internal users
SELECT authz.check_access('demo',
    'client_user', 'carol', 'can_read', 'document', 'doc_client_001');
-- => true
SELECT authz.check_access('demo',
    'client_user', 'carol', 'can_edit', 'document', 'doc_client_001');
-- => false
```

### Search queries

```sql
-- Document listing: populate a user's file browser with only the documents
-- they are authorized to see
SELECT * FROM authz.list_objects('demo',
    'internal_user', 'bob', 'can_read', 'document');
-- => doc_payroll_001, doc_acc_001, doc_tax_001

-- Sharing overview: show all users who currently have read access to a document,
-- useful for a "shared with" panel or access review reports
SELECT * FROM authz.list_subjects('demo',
    'internal_user', 'can_read', 'document', 'doc_payroll_001');
-- => alice, bob, julia

-- UI permission hints: determine which toolbar actions (edit, delete, share)
-- to enable for Alice on this specific document
SELECT * FROM authz.list_actions('demo',
    'internal_user', 'alice', 'document', 'doc_payroll_001');
-- => can_edit, can_read
```

### Writing and deleting tuples

```sql
-- Onboarding: add Grace to the payroll team so she inherits
-- all permissions that payroll_team members have (e.g. can_read on payroll docs)
SELECT authz.write_tuple('demo',
    'internal_user', 'grace', 'member', 'team', 'payroll_team');
-- => true

-- Verify that Grace now inherits can_read on payroll docs through her team membership
SELECT authz.check_access('demo',
    'internal_user', 'grace', 'can_read', 'document', 'doc_payroll_001');
-- => true

-- Batch onboarding: add multiple users to their respective teams in a single call
SELECT authz.write_tuples('demo', ARRAY[
    ROW('internal_user', 'grace', NULL, 'member', 'team', 'payroll_team'),
    ROW('internal_user', 'hank',  NULL, 'member', 'team', 'accounting_team')
]::authz.tuple_input[], p_performed_by => 'hr_system');
-- => 2

-- Role change: remove Grace from the payroll team
SELECT authz.delete_tuple('demo',
    'internal_user', 'grace', 'member', 'team', 'payroll_team');
-- => true

-- Batch offboarding: remove multiple users from their teams at once
SELECT authz.delete_tuples('demo', ARRAY[
    ROW('internal_user', 'grace', NULL, 'member', 'team', 'payroll_team'),
    ROW('internal_user', 'hank',  NULL, 'member', 'team', 'accounting_team')
]::authz.tuple_input[], p_performed_by => 'hr_system');

-- Full offboarding: revoke ALL access for a departing employee in one call
SELECT authz.delete_user_tuples('demo', 'internal_user', 'grace',
    p_performed_by => 'offboarding_service');
```

## Wildcard Tuples (Public Access)

A wildcard tuple grants a relation to **all users of a type** without writing
individual tuples. Write a tuple with `user_id = '*'`:

```sql
-- Make a document publicly readable by all users
SELECT authz.write_tuple('demo', 'user', '*', 'viewer', 'document', 'public_faq');

-- Any user can now view it — no individual tuple needed
SELECT authz.check_access('demo', 'user', 'anyone', 'can_view', 'document', 'public_faq');
-- => true (via wildcard)
```

Wildcards propagate through computed relations and TTU. If `viewer` implies
`can_read`, then `user:*` as `viewer` also grants `can_read` to everyone.

```sql
-- list_objects includes wildcard-granted objects
SELECT * FROM authz.list_objects('demo', 'user', 'anyone', 'can_view', 'document');
-- => includes public_faq

-- list_subjects reports the wildcard as a typed row ('*' with
-- is_wildcard = true, "every user of this type") alongside
-- explicitly granted users
SELECT * FROM authz.list_subjects('demo', 'user', 'can_view', 'document', 'public_faq');
-- => ('*', true), ...

-- explain_access shows wildcard matches in the trace
SELECT authz.explain_access('demo', 'user', 'anyone', 'can_view', 'document', 'public_faq');
-- trace detail: "wildcard tuple (*)"
```

**Constraints:**
- Wildcard tuples cannot have a `user_relation` (`team:*#member` is rejected)
- Wildcards are type-scoped: `user:*` does not grant access to `group:*`

See [MODEL_DESIGN.md](docs/MODEL_DESIGN.md#wildcard-tuples-public-access) for
detailed design guidance and use cases.

## Object Wildcards (Privileged Grants)

The dual of the subject wildcard: a tuple with `object_id = '*'` grants the
subject the relation on **every object of the type** — including objects
created later. This is the efficient way to model super-admin / auditor
roles: one tuple instead of one per object, O(1) checks instead of walking
hierarchies, and O(1) listing.

Object wildcards are **privileged and default-deny**: the direct model rule
must be explicitly marked before such tuples can be written.

```sql
-- 1. Mark the relationship as privileged (admin operation):
SELECT authz.model_add_rule('demo', 'document', 'viewer', 'direct',
    p_allow_object_wildcard => true);

-- 2. Grant: the compliance auditor can view (and via computed relations,
--    read) every document — current and future:
SELECT authz.write_tuple('demo', 'internal_user', 'nadia_auditor', 'viewer', 'document', '*');

-- Checks resolve in O(1), even for objects with no tuples at all:
SELECT authz.check_access('demo', 'internal_user', 'nadia_auditor', 'can_read', 'document', 'doc_created_tomorrow');
-- => true

-- list_objects answers with the typed wildcard row instead of
-- enumerating the store — branch on is_wildcard and list from your
-- application database:
SELECT * FROM authz.list_objects('demo', 'internal_user', 'nadia_auditor', 'can_read', 'document');
--  object_id | is_wildcard
-- -----------+-------------
--  *         | t
```

Usersets compose: `write_tuple('demo', 'group', 'auditors', 'viewer', 'document', '*',
p_user_relation => 'member')` covers all group members × all documents with
one tuple. Conditions compose too — a time-boxed condition on the wildcard
tuple makes a break-glass admin grant that expires.

**Security note:** an unmarked relation rejects `object_id = '*'` writes.
Never pass untrusted external identifiers as object IDs, and keep
`allow_object_wildcard` limited to relations that genuinely need
store-wide grants — one such tuple is equivalent to access to everything
of that type.

## Intersection and Exclusion (Rule Groups)

By default, multiple rules for the same relation are OR'd (any match grants access).
**Rule groups** let you combine rules with AND (intersection) or BUT NOT (exclusion).

### Intersection — all conditions must hold

```sql
-- can_view requires BOTH member AND licensed
INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                          computed_relation, group_id, group_op) VALUES
    (s, t_resource, r_can_view, authz._rel_computed(), r_member,   1, authz._combine_and()),
    (s, t_resource, r_can_view, authz._rel_computed(), r_licensed, 1, authz._combine_and());
```

### Exclusion — access minus denial

```sql
-- can_comment requires member BUT NOT blocked
INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                          computed_relation, group_id, group_op, negated) VALUES
    (s, t_resource, r_can_comment, authz._rel_computed(), r_member,  1, authz._combine_exclusion(), false),
    (s, t_resource, r_can_comment, authz._rel_computed(), r_blocked, 1, authz._combine_exclusion(), true);
```

### Mixing groups

Groups are OR'd together, so you can combine operators:

```sql
-- can_view = (member AND licensed) OR admin
-- Group 1: intersection
(s, t_resource, r_can_view, authz._rel_computed(), r_member,   1, authz._combine_and()),
(s, t_resource, r_can_view, authz._rel_computed(), r_licensed, 1, authz._combine_and()),
-- Group 0: OR (admin bypass)
(s, t_resource, r_can_view, authz._rel_computed(), r_admin,    0, authz._combine_or());
```

See [MODEL_DESIGN.md](docs/MODEL_DESIGN.md#rule-groups--intersection-and-exclusion)
for detailed examples and use cases.

## Conditions (Time-Based / ABAC)

Tuples can carry a **condition** — an expression that must evaluate to `true`
at check time for the tuple to grant access. Conditions are written in SQL by
default (an optional **CEL** language is also available — see
[Condition languages](#condition-languages-lang) below). A SQL condition
receives two JSONB arguments:

- **`$1` = request context** — provided by the caller at check time (e.g., the current timestamp, client IP, usage count)
- **`$2` = stored context** — saved with the tuple when it was written (e.g., the grant start time, allowed CIDR, max quota)

### Defining a condition

Create conditions with `authz.create_condition_sql` (or `create_condition_cel`
for CEL, below). Like the rest of the write API these are `SECURITY DEFINER`, so
no direct table access is needed; re-running with the same name updates the
expression in place.

```sql
-- "non_expired_grant": access is granted only if the current time
-- (from request context $1) is before grant_time + grant_duration
-- (from stored context $2).
SELECT authz.create_condition_sql('demo',
    'non_expired_grant',
    $$
      ($1->>'current_time')::timestamptz                  -- $1 = request context
      < ($2->>'grant_time')::timestamptz                  -- $2 = stored context
        + ($2->>'grant_duration')::interval               -- $2 = stored context
    $$,
    '{"request": ["current_time"], "stored": ["grant_time", "grant_duration"]}'::jsonb
);
```

### Writing a conditional tuple

The stored context (`grant_time`, `grant_duration`) is saved with the tuple
and will be passed as `$2` every time this tuple is evaluated:

```sql
-- Time-limited access: Alice can view doc_temp_001, but only within a 2-hour
-- window starting at 09:00. Useful for temporary document sharing.
SELECT authz.write_tuple('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001',
    'non_expired_grant',
    '{"grant_time": "2026-03-11T09:00:00Z", "grant_duration": "2 hours"}'::jsonb
);
```

### Checking with request context

The request context is passed as `$1` at check time:

```sql
-- 10:00 is within the 09:00-11:00 window => granted
SELECT authz.check_access_with_context('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001',
    '{"current_time": "2026-03-11T10:00:00Z"}'::jsonb);
-- => true

-- 12:00 is after the window => denied
SELECT authz.check_access_with_context('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001',
    '{"current_time": "2026-03-11T12:00:00Z"}'::jsonb);
-- => false

-- No context provided => condition fails safely => denied
SELECT authz.check_access('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001');
-- => false
```

### Other condition examples

```sql
-- IP allowlist: $1 has the client IP, $2 has the allowed CIDR range
SELECT authz.create_condition_sql('demo', 'ip_in_range',
 $$($1->>'client_ip')::inet <<= ($2->>'allowed_cidr')::cidr$$);

-- Office hours only: $1 has the current time, no stored context needed
SELECT authz.create_condition_sql('demo', 'office_hours',
 $$extract(hour from ($1->>'current_time')::timestamptz) BETWEEN 8 AND 17$$);

-- Usage quota: $1 has the current usage count, $2 has the max allowed
SELECT authz.create_condition_sql('demo', 'under_quota',
 $$($1->>'usage_count')::int < ($2->>'max_allowed')::int$$);
```

### Condition languages (`lang`)

Conditions carry a `lang` column selecting the expression language. `'sql'` is
the built-in default shown above — a SQL boolean over `$1` (request context) and
`$2` (stored context), evaluated in a zero-privilege sandbox, no dependencies.

`'cel'` is an **optional** language for friendlier ABAC expressions, evaluated by
the [`extensions/pg-cel`](extensions/pg-cel/) Rust/pgrx extension. The two
context bags are exposed as `request.*` and `stored.*`:

```sql
-- Same "not expired" rule, in CEL (requires the pg_cel extension).
SELECT authz.create_condition_cel('demo', 'cel_not_expired',
    'timestamp(request.current_time) < timestamp(stored.expires)',
    '{"request": ["current_time"], "stored": ["expires"]}');
```

Enable CEL by building the extension into the Postgres image and turning it on:

```bash
PGAUTHZ_CEL=1 ./start.sh    # or ./start.sh --cel — builds the pg_cel image
PGAUTHZ_CEL=1 ./init.sh     # runs CREATE EXTENSION pg_cel SCHEMA authz
```

`lang='cel'` writes are rejected until the evaluator is installed, so the default
stack is never left with conditions it can't run. For a runnable walk-through see
[`examples/models/demo/demo_cel.sql`](examples/models/demo/demo_cel.sql).

**Validation is parse-only.** Both languages are syntax-checked at write time
(SQL test-compile / CEL compile), but undeclared variables, type mismatches, and
value formats are not — those deny at check time. A common CEL gotcha: `duration()`
wants a Go-style string (`"2h"`), not a Postgres interval (`"2 hours"`). Dry-run a
condition against representative context with `validate_condition` to catch such
issues early — it evaluates the real expression and raises on a bad value:

```sql
SELECT authz.validate_condition('demo', 'cel_not_expired',
    '{"expires": "2026-03-11T11:00:00Z"}'::jsonb,         -- stored context
    '{"current_time": "2026-03-11T10:00:00Z"}'::jsonb);   -- request context
-- => true   (a malformed timestamp/duration in the context would raise here)
```

The engine dispatches languages in one place (`authz._eval_condition_expr`), so
adding cedar/rego later is additive. See
[`extensions/pg-cel/README.md`](extensions/pg-cel/README.md) for the build and
the SQL-vs-CEL trade-offs (e.g. IP-range conditions stay `lang='sql'`).

## Audit Trail and Time Travel

Every `write_tuple` and `delete_tuple` call is recorded in `authz.tuples_audit` —
an immutable, append-only log partitioned by month. The audit trail captures
who performed the action, when, and the full tuple details.

### Tracking application users

Since all API functions are `SECURITY DEFINER` (they run as the function
owner, the non-superuser `authz_owner` role),
the optional `p_performed_by` parameter lets your application pass the
authenticated end-user identity down to the audit trail:

```sql
-- Application backend writes a tuple on behalf of the logged-in user
SELECT authz.write_tuple('demo',
    'internal_user', 'grace', 'member', 'team', 'payroll_team',
    p_performed_by => 'admin');

-- The audit trail records who did it
SELECT action, performed_at, performed_by, relation, object_id
  FROM authz.audit_list_user('demo', 'internal_user', 'grace');
--  action | performed_at             | performed_by       | relation | object_id
-- --------+--------------------------+--------------------+----------+------------
--  INSERT | 2026-03-12 09:15:23.456  | admin  | member   | payroll_team
```

### Time-travel: "Could user X do Y at time T?"

`audit_check_access` reconstructs the complete **tuple** state at any past
timestamp by replaying INSERT/DELETE events from the audit log, then runs a
full recursive access check against that snapshot. The model rules and
condition expressions are reconstructed as of T as well (replaying
`models_audit` and `conditions_audit`), so the answer reflects the tuples,
rules, and conditions exactly as they were then (see the note under
[audit_check_access](#audit_check_access--point-in-time-permission-check)).

```sql
-- Grant access, record the timestamp, then revoke it
SELECT authz.write_tuple('demo',
    'internal_user', 'grace', 'member', 'team', 'payroll_team');
-- ... some time passes ...
SELECT authz.delete_tuple('demo',
    'internal_user', 'grace', 'member', 'team', 'payroll_team');

-- Grace no longer has access now
SELECT authz.check_access('demo',
    'internal_user', 'grace', 'can_read', 'document', 'doc_payroll_001');
-- => false

-- But she DID have access at 09:15
SELECT authz.audit_check_access('demo',
    'internal_user', 'grace', 'can_read', 'document', 'doc_payroll_001',
    '2026-03-12T09:15:00Z'::timestamptz);
-- => true

-- What actions did Grace have at that time?
SELECT * FROM authz.audit_list_actions('demo',
    'internal_user', 'grace', 'document', 'doc_payroll_001',
    '2026-03-12T09:15:00Z'::timestamptz);
-- => can_edit, can_read
```

### Querying the audit trail

```sql
-- All permission changes for a user
SELECT * FROM authz.audit_list_user('demo', 'internal_user', 'grace');

-- Filtered to a specific month
SELECT * FROM authz.audit_list_user('demo', 'internal_user', 'grace',
    '2026-03-01'::timestamptz, '2026-03-31'::timestamptz);

-- All permission changes on a document
SELECT * FROM authz.audit_list_object('demo', 'document', 'doc_payroll_001');
```

## Multi-Store Support

Every authorization operation is scoped to a **store** — an independent
authorization namespace. Each store has its own types, relations, models,
conditions, and tuples. Stores are fully isolated from each other.

The demo store is called `'demo'` and is created by the example model
`examples/models/demo/model.sql` (see [Example Models](#example-models)).

```sql
-- Create a new store for testing a model change
INSERT INTO authz.stores (name) VALUES ('v2_experiment');

-- All API functions take the store name as the first parameter
SELECT authz.write_tuple('v2_experiment',
    'internal_user', 'alice', 'can_read', 'document', 'doc_001');
SELECT authz.check_access('v2_experiment',
    'internal_user', 'alice', 'can_read', 'document', 'doc_001');

-- Clean up
SELECT authz.delete_store('v2_experiment');
```

## Namespace-Based Access Control

When multiple applications share a single store, **namespaces** restrict
which application can read or write tuples for which object types. This prevents
one application from accidentally modifying or querying another's authorization data.

- Types with `namespace = NULL` are **unrestricted** — any role can read and write them.
- Types with a non-NULL namespace require the **effective request role** to be a member of a
  granted role. The effective role is the `SET ROLE` identity (what PostgREST switches to
  per request), falling back to the session user for direct connections.
- **Read and write access** is controlled via `authz.namespace_access` using `can_read` and `can_write` flags.

```sql
-- Assign namespaces to types
UPDATE authz.types SET namespace = 'hr'
 WHERE store_id = authz._s('demo')
   AND name IN ('engagement', 'assignment');

UPDATE authz.types SET namespace = 'documents'
 WHERE store_id = authz._s('demo')
   AND name IN ('document', 'upload_request');

-- Grant access per namespace to application roles
INSERT INTO authz.namespace_access (store_id, namespace, db_role, can_read, can_write) VALUES
    (authz._s('demo'), 'hr',        'app_hr',     true, true),
    (authz._s('demo'), 'hr',        'app_portal', true, false),  -- portal can read HR data but not write
    (authz._s('demo'), 'documents', 'app_dms',    true, true);

-- Wire up: DB users get their application role
GRANT app_hr     TO hr_backend_user;
GRANT app_dms    TO dms_backend_user;
GRANT app_portal TO portal_user;
```

Now `hr_backend_user` can read and write tuples for `engagement` and `assignment`,
`dms_backend_user` can read and write tuples for `document` and `upload_request`,
and `portal_user` can read (but not write) HR authorization data.

Write namespace enforcement applies to: `write_tuple`, `delete_tuple`, `write_tuples`,
`delete_tuples`, `delete_user_tuples`.

Read namespace enforcement applies to: `check_access`, `check_access_with_context`,
`check_access_with_contextual_tuples`, `list_objects`, `list_subjects`, `list_actions`,
`explain_access`, `audit_check_access`, `audit_list_actions`.

Namespace read checks apply only to the **top-level object type** being queried.
Internal TTU traversals across type boundaries are not restricted — this ensures
cross-domain models work correctly while still controlling which applications can
initiate queries against which types.

## Architecture

This section is a quick overview. For the full picture — component and
sequence diagrams, deployment scenarios, the security model, design decision
records, and PostgreSQL tuning — see **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.
See also [docs/DESIGN.md](docs/DESIGN.md) for design rationale,
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the operations/integration guide, and
[docs/PRODUCTION.md](docs/PRODUCTION.md) for the production hardening checklist
and role recipes.

```
authz.stores             Independent authorization namespaces
authz.types              Type name -> smallint ID (per store), optional namespace
authz.relations          Relation name -> smallint ID (per store)
authz.conditions         Named SQL condition expressions (per store)
authz.conditions_audit   Immutable condition-expression history (for time-travel)
authz.models             Model resolution rules (per store)
authz.models_audit       Immutable model-rule history (for time-travel)
authz.namespace_access   Namespace -> DB role grants with can_read/can_write flags
authz.tuples             Relationship tuples (per store, partitioned by object type)
authz.tuples_audit       Immutable tuple audit trail (partitioned by month)
```

### How check_access resolves permissions

1. Resolves store name to store_id
2. Looks up direct tuples (index-only scan via partial index)
3. Evaluates conditions on matching tuples (if any)
4. Expands usersets (e.g., `team:payroll_team#member` → all team members)
5. Follows computed relations (e.g., `can_read` → `viewer`)
6. Traverses tuple-to-userset links (e.g., `can_view from in_internal_space`)
7. Unions contextual tuples into each step (if provided)

These steps compose recursively. Here's the simplest real check against the
seeded **demo** store — Carol can read a document because she was granted
`viewer` on it directly, and `can_read` is computed from `viewer`:

```sql
SELECT authz.explain_access('demo',
    'client_user', 'carol', 'can_read', 'document', 'doc_client_private_001') ->> 'summary';
```

```
client_user:carol → can_read → document:doc_client_private_001 = ALLOWED (computed)
  ✓ [direct_tuple] viewer on document:doc_client_private_001 — tuple found (1.174 ms)
✓ [computed] can_read on document:doc_client_private_001 — can_read ← viewer (1.498 ms)
```

Two ideas do most of the work: a **direct tuple** (the stored `viewer` grant)
and a **computed relation** (`can_read` is satisfied by `viewer`). Real models
simply nest more of the same. The check below — *can Alice read
`doc_payroll_001`?* — adds **userset expansion** (group membership) and
**tuple-to-userset (TTU)** steps that hop from a document to the space and
assignment it belongs to, but every line is still one of the same handful of
move types. Ask the engine for this trace with `explain_access`:

```sql
SELECT authz.explain_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001');
```

It returns the structured JSON described under
[explain_access](#explain_access--why-was-access-allowed-or-denied) above. That
JSON already carries a ready-made visualization in its `summary` field — extract
it with the `->>` operator to print the trace as a tree:

```sql
SELECT authz.explain_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001') ->> 'summary';
```

```
internal_user:alice → can_read → document:doc_payroll_001 = ALLOWED (ttu)
  ✗ [no_direct_tuple] viewer on document:doc_payroll_001 — no tuple (1.937 ms)
✗ [computed] can_read on document:doc_payroll_001 — can_read ← viewer (2.347 ms)
    ✗ [no_direct_tuple] viewer on internal_data_space:eng_42_payroll_internal — no tuple (0.610 ms)
  ✗ [computed] can_view on internal_data_space:eng_42_payroll_internal — can_view ← viewer (0.767 ms)
      ✗ [no_direct_tuple] accountant on assignment:eng_42_payroll — no tuple (0.573 ms)
    ✗ [computed] can_view on assignment:eng_42_payroll — can_view ← accountant (0.680 ms)
        ✓ [direct_tuple] member on team:payroll_team — tuple found (0.342 ms)
      ✓ [userset] payroll_clerk on assignment:eng_42_payroll — expand team:payroll_team#member (0.777 ms)
    ✓ [computed] can_view on assignment:eng_42_payroll — can_view ← payroll_clerk (0.839 ms)
  ✓ [ttu] can_view on internal_data_space:eng_42_payroll_internal — can_view ← can_view on assignment:eng_42_payroll (via parent_assignment) (1.822 ms)
✓ [ttu] can_read on document:doc_payroll_001 — can_read ← can_view on internal_data_space:eng_42_payroll_internal (via in_internal_space) (3.020 ms)
```

Read each line as `✓/✗ [reason] relation on object — detail (timing)`. Indentation
is recursion depth and steps are listed in **evaluation order** (children before
their parent), so the bottom line is the top-level decision. Here the engine first
tries the cheap `viewer` paths (all ✗), then follows the TTU chain
`document → internal_data_space → assignment`, where Alice's `team:payroll_team`
membership finally satisfies `payroll_clerk` and the whole check resolves to
ALLOWED. Per-step `duration_ms` timings vary run to run.

The engine stops as soon as any path returns true. Pass `p_successful_only => true`
to drop the ✗ branches and keep only the winning path:

```sql
SELECT authz.explain_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001',
    p_successful_only => true) ->> 'summary';
```

```
internal_user:alice → can_read → document:doc_payroll_001 = ALLOWED (ttu)
        ✓ [direct_tuple] member on team:payroll_team — tuple found (0.345 ms)
      ✓ [userset] payroll_clerk on assignment:eng_42_payroll — expand team:payroll_team#member (0.829 ms)
    ✓ [computed] can_view on assignment:eng_42_payroll — can_view ← payroll_clerk (0.903 ms)
  ✓ [ttu] can_view on internal_data_space:eng_42_payroll_internal — can_view ← can_view on assignment:eng_42_payroll (via parent_assignment) (1.902 ms)
✓ [ttu] can_read on document:doc_payroll_001 — can_read ← can_view on internal_data_space:eng_42_payroll_internal (via in_internal_space) (3.136 ms)
```

The machine-readable `trace` (flat) and `tree` (nested) fields carry the same
steps for programmatic use.

All recursive calls use integer IDs internally. Text-to-ID resolution
happens once at the top-level public function.

### Deployment topologies

Because the engine is just SQL, you choose where it sits relative to your
application data — and that choice, not a rewrite, is what changes the access
pattern:

| Topology | Where authz data lives | How an app reads it | Data filtering |
|---|---|---|---|
| **Central authz service** (common) | its own database / cluster | over the wire — REST (OPA → PostgREST) or AuthZEN | `list_objects` returns the id set; the app filters its own query by it (`WHERE id = ANY(:ids)` + wildcard flag), like an OpenFGA-style engine |
| **Embedded read-only engine** | central, with raw tuples + model replicated into the app DB | the **read-only engine excerpt** runs locally (`init-readonly.sh`) — full `check_access` / `list_*` / `explain` | JOIN `list_objects(...)` locally |
| **Replicated permissions (derived)** | central, with a *flattened* permissions table replicated into the app DB | local lookups on the derived table ([`db/replication/`](db/replication/)) | JOIN the derived table |
| **Co-located** (minority) | inside the app's own database | local SQL | JOIN `list_objects(...)` directly ([Authorization as a JOIN](#authorization-as-a-join-data-filtering)) |

Most deployments are the **central** one: a single authorization database
populated by many applications, each calling it over REST or AuthZEN for checks
and `list_*` queries and writing tuples through the OPA-fronted writer. The other
three put authorization data *inside* an application's database, only when it
genuinely needs that — e.g. to filter large result sets in a single query.

#### Embedded read-only engine

`init-readonly.sh` runs the structural migrations and then loads only the
**substrate + read** profiles of engine code
(see [`db/engine/manifest.sh`](db/engine/manifest.sh)) — access checks, search,
explain, and condition evaluation, with **no write/management API and no audit
trigger functions**. (The migrations create *all* tables, audit included, so the
audit tables are present but stay **inert** — nothing writes to them without the
audit-profile triggers.) Point it at an application database that receives the raw `authz.tuples`
+ model by logical replication ([`db/replication/`](db/replication/)); access
checks then resolve **locally**, with the same engine logic as central — not a
lossy precomputed snapshot like the *derived* permissions approach. Because it
runs in the app's own Postgres you also get [Authorization as a
JOIN](#authorization-as-a-join-data-filtering). It is eventually consistent
(replication lag); route freshness-sensitive checks to the central primary.

The subsections below detail the central stack (PostgREST + OPA, AuthZEN) and
read-replica scaling.

### Deployment with PostgREST and OPA

The authorization engine is designed to run as part of a three-tier stack:

```
                    ┌─────────────────────────────┐
                    │     Application / Client    │
                    └──────────────┬──────────────┘
                                   │ HTTP
                    ┌──────────────▼──────────────┐
                    │     OPA (Policy Agent)      │
                    │  - Rego policies            │
                    │  - Calls PostgREST to check │
                    │    authorization decisions  │
                    └──────────────┬──────────────┘
                                   │ HTTP (internal)
                    ┌──────────────▼──────────────┐
                    │     PostgREST               │
                    │  - Exposes authz functions  │
                    │    as REST endpoints        │
                    │  - Runs as api_anon role    │
                    │    (inherits authz_reader)  │
                    └──────────────┬──────────────┘
                                   │ SQL
                    ┌──────────────▼──────────────┐
                    │     PostgreSQL              │
                    │  - authz schema             │
                    │  - check_access, list_*, ...│
                    └─────────────────────────────┘
```

- **PostgreSQL** stores all authorization data and executes the recursive
  access checks. All logic lives in SQL functions — no application code needed.
- **PostgREST** exposes the `authz` schema functions as a REST API.
  It runs as `api_anon` (which inherits `authz_reader`), so it can only
  perform read operations (check, list) by default.
- **OPA** (Open Policy Agent) acts as the policy decision point. Rego policies
  call PostgREST endpoints to evaluate authorization and can combine the
  result with additional policy logic (environment checks, rate limits, etc.).

Applications call OPA for authorization decisions. OPA calls PostgREST,
which calls PostgreSQL. Write operations (`write_tuple`, `delete_tuple`)
are performed directly by the application backend using a database user
with the `authz_writer` role.

> **Trust boundary:** the read PostgREST accepts **unauthenticated**
> requests — `api_anon` can run every check/list/explain function across
> all stores (subject only to namespace read grants). This is by design:
> OPA (or your own authenticating layer) is the mandatory front door, and
> the compose stack therefore gives the read PostgREST **no host port** —
> it is reachable only by OPA on the internal Docker network. Never expose
> it directly; anyone who can reach it can enumerate your authorization
> data via `list_objects` / `list_subjects`.

**Authentication / OIDC.** OPA is the front door: it verifies the caller's JWT
(issuer, audience, signature via JWKS) and derives the subject from the token
claims, so pgauthz runs behind **any** OAuth2 AS / OIDC provider — just point
OPA's `JWT_ISSUER` / `JWKS_URL` at yours. An **optional bundled Keycloak** demo
(Terraform-provisioned, TLS) lives in [`keycloak/`](keycloak/) for a runnable
end-to-end example — start it with `./start.sh --keycloak`, and see
[`examples/keycloak/query-demo.sh`](examples/keycloak/) for real tokens (human
users via password grant, plus an app-as-a-service via client_credentials)
driving `check_access`.

### AuthZEN 1.0 API

The `authzen/` directory contains a Go API layer implementing the
[AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html) standard.
Two services share a common HTTP handler layer:

- **`authzen-direct`** (port 8090) — Go → PostgreSQL (lowest latency, pure Zanzibar)
- **`authzen-opa`** (port 8091) — Go → OPA → PostgREST → PostgreSQL (app-specific Rego policies)

Both expose identical endpoints:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/access/v1/evaluation` | Single access check |
| POST | `/access/v1/evaluations` | Batch with semantics |
| POST | `/access/v1/search/subject` | Who has access? |
| POST | `/access/v1/search/resource` | What can subject access? |
| POST | `/access/v1/search/action` | What can subject do? |
| GET | `/.well-known/authzen-configuration` | PDP discovery |
| GET | `/healthz` | Health check |

All endpoints require a valid JWT (ES256/RS256). Claims mapping matches
the existing `authn.rego` (`preferred_username` → subject ID,
`subject_type` → subject type).

```bash
# Start with AuthZEN services
docker compose -f compose.yml -f compose-authzen.yml up -d --build

# Test
./tests/test-authzen.sh
```

### Scaling with read replicas

Since `check_access` and all `list_*` functions are pure reads, the
authorization engine scales horizontally by adding PostgreSQL read replicas:

```
                         ┌─────────────────────┐
                         │   Application       │
                         └──────┬─────┬────────┘
                        writes  │     │  reads
                 ┌──────────────▼──┐  │
                 │  Primary (R/W)  │  │
                 │  - write_tuple  │  │
                 │  - delete_tuple │  │
                 │  - model mgmt   │  │
                 └───┬─────────┬─v─┘  │
        replication  │         │      │
           ┌─────────▼───┐  ┌──▼──────▼────────┐
           │ Replica 1   │  │ Replica 2        │
           │ (read-only) │  │ (read-only)      │
           │             │  │                  │
           │ PostgREST   │  │ PostgREST        │
           │ + OPA       │  │ + OPA            │
           └─────────────┘  └──────────────────┘
```

- **Primary instance** handles writes: `write_tuple`, `delete_tuple`,
  `write_tuples`, `delete_tuples`, `delete_user_tuples`, model management.
  Writes are typically low-volume (user onboarding, permission changes).
- **Read replicas** handle the high-volume read traffic: `check_access`,
  `list_objects`, `list_subjects`, `list_actions`. Each replica runs its own
  PostgREST and OPA instance.
- Streaming replication keeps replicas in sync. Authorization data changes
  infrequently (compared to read volume), so replication lag is negligible.
- A load balancer distributes read requests across replicas. Since
  authorization checks are stateless (no session affinity needed), any
  replica can serve any request.

This separation works well because authorization workloads are heavily
read-biased: a typical application performs thousands of `check_access`
calls for every `write_tuple`. A single primary can handle the write
throughput while multiple replicas absorb the read load.

#### Consistency model

A decision is only as fresh as the data the check reads, so the contract
depends on **where the read is routed**:

- **Single instance, or any read on the primary — strong, read-your-writes.**
  PostgreSQL MVCC guarantees a check sees every committed write (grant or
  revoke) immediately. This is the default for the base (non-replicated) stack.
- **Read replicas — eventually consistent, bounded by replication lag.**
  Streaming replication is asynchronous: a write committed on the primary
  becomes visible on a replica only after the lag (typically sub-second, since
  authorization data changes infrequently). A check routed to a replica within
  that window sees the *previous* state.

The asymmetry matters for security:

- **Stale allow after a revoke** is the dangerous case — revoke a grant on the
  primary and a check on a lagging replica may still return `allowed` until the
  change replicates (the ReBAC "new enemy" problem).
- **Stale deny after a grant** is only an availability hiccup — access you just
  granted isn't visible yet.

Getting the consistency you need:

- **Route the affected subject's security-critical checks to the primary** —
  and after a *revoke*, not just the admin's confirming check: the revoked
  subject's own later requests may keep hitting replicas, so route *their*
  sensitive actions (or temporarily pin them) to the primary too. Primary reads
  are read-your-writes given a fresh snapshot (a new transaction, and no stale
  OPA cache hit).
- **Accept bounded staleness** for the high-volume common case (sub-second lag
  is fine for most authorization).
- **Synchronous replication** (`synchronous_commit = remote_apply`) makes the
  standbys in the *synchronous set* read-your-writes, trading write latency for
  zero lag on those replicas (only).

> **No revision tokens (zookies) yet.** Unlike Zanzibar, pgauthz has no
> consistency-token API to pin a read to "at least as fresh as this write." You
> can approximate read-your-writes on a replica manually, but only with a
> **post-commit** position: *after* the write commits, `SELECT
> pg_current_wal_insert_lsn()` on the primary, then wait until the replica's
> `pg_last_wal_replay_lsn()` reaches it (an LSN captured *inside* the write
> transaction is pre-commit and unsound). The documented forward design is a
> per-store signed **revision** token with `at_least_as_fresh` /
> `fully_consistent` modes — see
> [ARCHITECTURE.md → Consistency tokens](docs/ARCHITECTURE.md).

### Performance optimizations

- **Integer IDs** for type/relation names (~2-3x faster lookups, ~50% smaller indexes)
- **Partitioned by object_type** (partition pruning on every query)
- **Covering partial indexes** (separate indexes for direct vs userset lookups)
- **Store-scoped indexes** (store_id as leading column for multi-tenant partition pruning)
- **Audit partitioned by month** (old partitions can be detached and archived)
- **PostgreSQL tuning** (`shared_buffers`, `effective_cache_size`, `work_mem`, `random_page_cost`)

For measured numbers (and a reproducible harness — `./bench/run.sh`), see
**[docs/BENCHMARKS.md](docs/BENCHMARKS.md)**: `check_access` is sub-millisecond
for typical checks, and `list_objects` / `list_subjects` are bounded by the
*reachable set* rather than the store size (a 3-grantee object resolves in
~12 ms in a 50,000-user store).

### Access control roles

| Role | Can do | Inherits |
|---|---|---|
| `authz_auditor` | `audit_check_access`, `audit_list_actions`, `audit_list_user`, `audit_list_object` | `authz_reader` |
| `authz_reader` | `check_access`, `check_access_with_context`, `list_objects`, `list_subjects`, `list_actions`, `validate_condition`, `explain_access` | -- |
| `authz_contextual_reader` | `check_access_with_contextual_tuples`, `check_access_with_contextual_tuples_jsonb` — inject ephemeral tuples into a check. **Separate from `authz_reader`**: a caller could inject the grant being tested, so grant this only to trusted PDP/backend callers, never to a role reachable by untrusted clients. | -- |
| `authz_writer` | `write_tuple`, `delete_tuple`, `write_tuples`, `delete_tuples`, `delete_user_tuples` | `authz_reader` |
| `authz_admin` | `create_store`, `delete_store`, `model_register_type`, `model_register_relation`, manage `namespace_access` table | `authz_writer` |

`authz_auditor` inherits `authz_reader` (can query both live and historical permissions) but cannot write.
The PostgREST anonymous role (`api_anon`) inherits `authz_reader`.
All public functions are `SECURITY DEFINER` — application roles need no
direct table access.

> For which role each component should connect as / be granted (OPA→PostgREST,
> AuthZEN-direct, backend writers, admins, and when to grant
> `authz_contextual_reader`), see the **[Production Hardening guide → Role
> recipes](docs/PRODUCTION.md#role-recipes)**.

The schema and all its objects are owned by **`authz_owner`, a
non-superuser role**, so `SECURITY DEFINER` functions execute with only
the privileges they need (ownership of the `authz` tables) rather than
superuser rights — a flaw in a definer function cannot escalate to
superuser. The condition sandbox (`_exec_condition`) is owned by the
separate zero-privilege `authz_eval` role; the database itself remains
owned by the bootstrap `authz` superuser (break-glass DBA only).

```sql
-- Backend that needs to write tuples
GRANT authz_writer TO my_backend_user;

-- Admin tool that can manage stores
GRANT authz_admin TO my_admin_user;
```

## Example Models

The [`examples/models/`](examples/models/) directory contains ready-to-load
authorization models. They are **not** part of the deployable engine —
`init.sh` installs only the schema and functions, and you load an example on
top of it when you want one. Each model is independent; load any combination
into the same database (every store is isolated). (Runnable setup examples like
the watch/changefeed consumer live alongside under
[`examples/watch/`](examples/watch/).)

| Example | Models | Files |
|---|---|---|
| `examples/models/demo/` | Professional-services engagements: internal/client users, teams, data spaces, documents, conditions, audit | `model.sql`, `seed.sql`, `tests.sql`, `demo.sql` |
| `examples/models/gdrive/` | Google-Drive-style hierarchical folders and documents (deep TTU nesting) | `model.sql`, `seed.sql`, `demo.sql` |
| `examples/models/github/` | GitHub repo roles (`admin → maintainer → writer → triager → reader`), imported from an OpenFGA JSON model | `model.sql`, `seed.sql`, `demo.sql` |

In each: `model.sql` defines the types/relations/rules (creates the store),
`seed.sql` loads sample tuples, `demo.sql` runs a showcase of example
queries, and `tests.sql` (demo only) asserts expected decisions.

### Loading an example

The engine must be installed first (`./init.sh`, or `./bootstrap.sh` which
also loads the demo). Then pipe the model and seed into the database:

```bash
DB=$(docker compose ps -q authz-db)

# Load the gdrive example (model + sample tuples)
cat examples/models/gdrive/model.sql examples/models/gdrive/seed.sql \
  | docker exec -i "$DB" psql -U authz -d authz

# Run its showcase queries
docker exec -i "$DB" psql -U authz -d authz < examples/models/gdrive/demo.sql
```

`./bootstrap.sh` loads the `demo` example automatically (it is also the
fixture for the test suite and the OPA/AuthZEN integration tests, whose
default store is `demo`).

## File Structure

| Path | Purpose |
|---|---|
| `db/engine/` | Core authorization engine — schema, access checks, tuple management, audit, model rules |
| `db/security/` | Role definitions and GRANT/SECURITY DEFINER setup |
| `db/openfga/` | OpenFGA JSON model and tuple import |
| `tests/sql/` | Test suites (API, search, namespace, wildcards, contextual, intersection, etc.) |
| `examples/models/` | Example authorization models (demo, gdrive, github) — **not** part of the deployable engine; see [Example Models](#example-models) |
| `examples/watch/` | Runnable setup example for the watch/changefeed feature (compose overlay + Python consumer) |
| `authzen/` | Go AuthZEN 1.0 HTTP API layer ([see authzen/README.md](authzen/README.md)) |
| `opa/` | Rego policies for JWT authn + Zanzibar authz via PostgREST |
| `docs/` | Design documents, development guide, model design, OPA integration |
| `compose.yml` | PostgreSQL + PostgREST + OPA |
| `compose-authzen.yml` | AuthZEN services (authzen-direct + authzen-opa) |
| `bootstrap.sh` | Full init + test run |

## Comparison with OpenFGA

This engine implements the same [Google Zanzibar](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/)
authorization model as [OpenFGA](https://openfga.dev/). The core authorization
primitives are at full parity — the remaining differences are operational.

### Authorization model — full parity

| Capability | OpenFGA | This solution |
|---|---|---|
| Direct relations (`this`) | ✅ | ✅ |
| Computed relations (`computedUserset`) | ✅ | ✅ |
| Tuple-to-userset (`tupleToUserset`) | ✅ | ✅ |
| Union (OR) | ✅ | ✅ |
| Intersection (AND) | ✅ | ✅ |
| Exclusion / Difference (BUT NOT) | ✅ | ✅ * |
| Wildcard tuples (`user:*`) | ✅ | ✅ |
| Conditions (ABAC) | ✅ | ✅ |
| Contextual tuples | ✅ | ✅ |
| List objects (resource search) | ✅ | ✅ |
| List users (subject search) | ✅ | ✅ |
| Multiple stores | ✅ | ✅ |
| Type restrictions on writes | ✅ | ✅ |
| Idempotent writes/deletes | ✅ opt-in (`on_duplicate` / `on_missing: ignore`) | ✅ default ** |

\* Exclusion semantics differ in one detail: in OpenFGA, the base of a
`difference` is typically a union; here, multiple base rules in one
exclusion group are **AND-ed**. To express `(viewer OR editor) BUT NOT
blocked`, use one exclusion group per base alternative (groups are OR'd).
Exclusion groups must contain at least one base rule — negated-only
groups are rejected at write time. See
[MODEL_DESIGN.md](docs/MODEL_DESIGN.md#exclusion-but-not) for details.

\** Duplicate writes and deletes of non-existent tuples never fail here —
no flag needed. Unlike OpenFGA's ignore mode, the outcome stays
observable: `write_tuple`/`delete_tuple` return whether anything changed,
and the batch functions return effective counts. One deliberate
difference: re-writing an existing tuple with a **different condition**
is not ignored as a duplicate — the new condition is applied (and
audited), so a grant never silently stays more or less permissive than
the caller requested.

### This solution has, OpenFGA doesn't

| Capability | Notes |
|---|---|
| **Full audit trail** | Immutable, monthly-partitioned log with `performed_by` tracking |
| **Time-travel queries** | `audit_check_access` reconstructs the tuple state, **model rules, and condition expressions** at any past timestamp (all three versioned via `*_audit` logs) |
| **`list_actions`** | "What can user X do on object Z?" — OpenFGA has no equivalent |
| **`explain_access`** | Structured decision explanation: resolution tree, a typed `reason` per step, a minimal `decision.reason`, and a redacted safety mode |
| **Namespace write control** | Restrict which applications can write tuples for which object types |
| **Condition validation** | Dry-run conditions before writing tuples |
| **Batch operations** | `write_tuples` / `delete_tuples` in a single statement |
| **No external service** | Pure SQL — no network hop, no separate process to operate |
| **OpenFGA import** | Import existing OpenFGA JSON models directly. `intersection` and `difference` are translated natively into rule groups; operators nested deeper than one level below `union` are rejected (never imported as a more permissive approximation) — see [MODEL_DESIGN.md](docs/MODEL_DESIGN.md#example-how-intersectionexclusion-map-to-rule-groups) |
| **Object wildcards** | `(subject, relation, type, '*')` grants the relation on every object of the type — O(1) super-admin/auditor checks and listing. Default-deny: the direct rule must be marked `allow_object_wildcard`. OpenFGA wildcards are subject-side only |

### OpenFGA has, this solution doesn't

| Capability | Impact | Notes |
|---|---|---|
| **Consistency tokens** | Low–Medium | Zanzibar-style tokens for read-after-write consistency in distributed setups. This solution uses PostgreSQL MVCC — strong consistency on a single instance, eventual consistency with read replicas (negligible lag for authorization data). |
| **Watch API** | Low | OpenFGA can stream tuple changes. This solution provides `authz.watch_changes` (a cursored, lag-gated changefeed over the audit log) plus a `NOTIFY authz_changes` doorbell; a WebSocket/SSE transport bridge is left to the deployment. |
| **gRPC API** | Low | OpenFGA has native gRPC. This solution uses SQL directly or PostgREST for HTTP REST. |
| **SDK ecosystem** | Medium | OpenFGA has official SDKs for Go, JS, Python, Java, .NET. This solution requires direct SQL or HTTP calls via PostgREST — simpler for teams already on PostgreSQL, but lacks the plug-and-play SDK experience. |
| **Modular models** | Low | OpenFGA 1.2 supports splitting models into modules. Less relevant here since the model is SQL rows that can be organized however you like. |

### When to choose this solution over OpenFGA

- You already run PostgreSQL and want to avoid operating another service
- You need audit trails, time-travel queries, or `explain_access` out of the box
- You want the authorization engine co-located with your data (no network hop)
- Your team is comfortable with SQL and prefers it over a DSL

### When to choose OpenFGA

- You need official language SDKs and gRPC for a polyglot microservices architecture
- You want a managed/hosted authorization service (e.g., Okta FGA)
- You need a managed gRPC streaming Watch transport out of the box (this solution provides the changefeed via `watch_changes` + `NOTIFY`, but you bridge it to your transport)
- You prefer the OpenFGA DSL for defining and reviewing models
