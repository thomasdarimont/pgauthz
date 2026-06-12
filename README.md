# PostgreSQL Authorization Engine

A pure PostgreSQL implementation of the [Google Zanzibar](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/) /
[OpenFGA](https://openfga.dev/) authorization model.
No external authorization service needed — just SQL functions
that resolve relationship tuples recursively.

## Features

- **Relationship-based access control (ReBAC)** — Zanzibar/OpenFGA model with direct, computed, and tuple-to-userset rules
- **Wildcard tuples** — `user:*` grants a relation to all users of a type without individual tuples (public/anonymous access)
- **Intersection and exclusion** — rule groups support AND (all rules must match) and BUT NOT (base must match, negated must not) semantics
- **Attribute-based access control (ABAC)** — conditions on tuples (time windows, IP ranges, quotas) evaluated at check time
- **Contextual tuples** — ephemeral per-request relationships that are not persisted (VPN context, org selection)
- **Multi-store** — independent authorization namespaces with isolated types, relations, models, and tuples
- **Batch operations** — `write_tuples` / `delete_tuples` for efficient bulk insert and delete
- **Full audit trail** — immutable, monthly-partitioned audit log with application user tracking (`performed_by`)
- **Time-travel queries** — `audit_check_access` reconstructs permissions at any past point in time from the audit log
- **AuthZen Search API** — `list_objects`, `list_subjects`, `list_actions` for discovery queries
- **OpenFGA import** — import existing OpenFGA JSON models and tuples directly
- **Namespace-based write access control** — restrict which applications can manage tuples for which object types within a shared store
- **PostgREST + OPA integration** — expose authorization as an HTTP API with policy-as-code
- **AuthZEN 1.0 API** — standard [AuthZEN](https://openid.net/specs/authorization-api-1_0.html) Go API layer with two backends: direct PostgreSQL (`authzen-direct`) and OPA (`authzen-opa`)
- **Performance** — integer IDs, LIST partitioning by object type, covering partial indexes, store-scoped index pruning

## Setup

```bash
cd authz/pgauthz
./bootstrap.sh
```

The bootstrap script starts PostgreSQL, PostgREST, and OPA via docker compose,
then loads schema, functions, model, seed data, and runs all tests.

## Connecting

```bash
docker exec -it $(docker compose ps -q authz-db) psql -U authz -d authz
```

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

### list_subjects — "Which users of type X can do Y on object Z?"

```sql
-- Access review: find all users who can read a specific document.
-- Use this for sharing dialogs or compliance reviews.
SELECT * FROM authz.list_subjects('demo',
    'internal_user', 'can_read', 'document', 'doc_payroll_001');
-- => alice, bob, julia
```

### list_actions — "What can user X do on object Z?"

```sql
-- Action discovery: find all actions Alice can perform on a document.
-- Use this to enable/disable UI buttons based on the user's effective permissions.
SELECT * FROM authz.list_actions('demo',
    'internal_user', 'alice', 'document', 'doc_payroll_001');
-- => can_edit, can_read
```

### write_tuple — Write a relationship tuple

Returns `true` if a new tuple was created, `false` if it already existed (idempotent).
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

Reconstructs the tuple state at any past point in time by replaying the audit
log, then runs a full access check against that snapshot.

```sql
-- Forensic analysis: verify whether a user had access at a specific past moment.
-- Use this for incident investigation or compliance audits.
SELECT authz.audit_check_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001',
    '2026-03-11T14:00:00Z'::timestamptz);
-- => true
```

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

-- explain_access shows wildcard matches in the trace
SELECT authz.explain_access('demo', 'user', 'anyone', 'can_view', 'document', 'public_faq');
-- trace detail: "wildcard tuple (*)"
```

**Constraints:**
- Wildcard tuples cannot have a `user_relation` (`team:*#member` is rejected)
- Wildcards are type-scoped: `user:*` does not grant access to `group:*`

See [MODEL_DESIGN.md](docs/MODEL_DESIGN.md#wildcard-tuples-public-access) for
detailed design guidance and use cases.

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

Tuples can carry a **condition** — a SQL expression that must evaluate to `true`
at check time for the tuple to grant access. Conditions receive two JSONB arguments:

- **`$1` = request context** — provided by the caller at check time (e.g., the current timestamp, client IP, usage count)
- **`$2` = stored context** — saved with the tuple when it was written (e.g., the grant start time, allowed CIDR, max quota)

### Defining a condition

```sql
-- "non_expired_grant": access is granted only if the current time
-- (from request context $1) is before grant_time + grant_duration
-- (from stored context $2).
INSERT INTO authz.conditions (store_id, name, expression, required_context) VALUES
(authz._s('demo'),
 'non_expired_grant',
 $$
   ($1->>'current_time')::timestamptz                    -- $1 = request context
   < ($2->>'grant_time')::timestamptz                    -- $2 = stored context
     + ($2->>'grant_duration')::interval                 -- $2 = stored context
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
INSERT INTO authz.conditions (store_id, name, expression) VALUES
(authz._s('demo'), 'ip_in_range',
 $$($1->>'client_ip')::inet <<= ($2->>'allowed_cidr')::cidr$$);

-- Office hours only: $1 has the current time, no stored context needed
INSERT INTO authz.conditions (store_id, name, expression) VALUES
(authz._s('demo'), 'office_hours',
 $$extract(hour from ($1->>'current_time')::timestamptz) BETWEEN 8 AND 17$$);

-- Usage quota: $1 has the current usage count, $2 has the max allowed
INSERT INTO authz.conditions (store_id, name, expression) VALUES
(authz._s('demo'), 'under_quota',
 $$($1->>'usage_count')::int < ($2->>'max_allowed')::int$$);
```

## Audit Trail and Time Travel

Every `write_tuple` and `delete_tuple` call is recorded in `authz.tuples_audit` —
an immutable, append-only log partitioned by month. The audit trail captures
who performed the action, when, and the full tuple details.

### Tracking application users

Since all API functions are `SECURITY DEFINER` (they run as the `authz` DB role),
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

`audit_check_access` reconstructs the complete tuple state at any past timestamp
by replaying INSERT/DELETE events from the audit log, then runs a full
recursive access check against that snapshot:

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

The demo store is called `'demo'` and is created by `db/models/demo/model.sql`.

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

```
authz.stores             Independent authorization namespaces
authz.types              Type name -> smallint ID (per store), optional namespace
authz.relations          Relation name -> smallint ID (per store)
authz.conditions         Named SQL condition expressions (per store)
authz.models             Model resolution rules (per store)
authz.namespace_access   Namespace -> DB role grants with can_read/can_write flags
authz.tuples             Relationship tuples (per store, partitioned by object type)
authz.tuples_audit       Immutable audit trail (partitioned by month)
```

### How check_access resolves permissions

1. Resolves store name to store_id
2. Looks up direct tuples (index-only scan via partial index)
3. Evaluates conditions on matching tuples (if any)
4. Expands usersets (e.g., `team:payroll_team#member` → all team members)
5. Follows computed relations (e.g., `can_read` → `viewer`)
6. Traverses tuple-to-userset links (e.g., `can_view from in_internal_space`)
7. Unions contextual tuples into each step (if provided)

These steps compose recursively. For example, checking if Alice can read
`doc_payroll_001` traverses a tree like this:

```
can_read on document:doc_payroll_001
  ← computed: check viewer → miss (no direct tuple)
  ← computed: check editor → miss
  ← TTU: follow in_internal_space → internal_data_space:eng_42_payroll_internal
    ← can_view on internal_data_space:eng_42_payroll_internal
      ← TTU: follow parent_assignment → assignment:eng_42_payroll
        ← can_view on assignment:eng_42_payroll
          ← computed: check payroll_clerk
            ← direct: team:payroll_team#member is payroll_clerk on assignment
              ← userset expansion: is alice a member of team:payroll_team?
                ← direct: tuple exists → YES
```

The engine stops as soon as any path returns true. Use `explain_access` to
see the full resolution trace for any check.

All recursive calls use integer IDs internally. Text-to-ID resolution
happens once at the top-level public function.

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

### Performance optimizations

- **Integer IDs** for type/relation names (~2-3x faster lookups, ~50% smaller indexes)
- **Partitioned by object_type** (partition pruning on every query)
- **Covering partial indexes** (separate indexes for direct vs userset lookups)
- **Store-scoped indexes** (store_id as leading column for multi-tenant partition pruning)
- **Audit partitioned by month** (old partitions can be detached and archived)
- **PostgreSQL tuning** (`shared_buffers`, `effective_cache_size`, `work_mem`, `random_page_cost`)

### Access control roles

| Role | Can do | Inherits |
|---|---|---|
| `authz_auditor` | `audit_check_access`, `audit_list_actions`, `audit_list_user`, `audit_list_object` | `authz_reader` |
| `authz_reader` | `check_access`, `check_access_with_context`, `check_access_with_contextual_tuples`, `list_objects`, `list_subjects`, `list_actions`, `validate_condition`, `explain_access` | -- |
| `authz_writer` | `write_tuple`, `delete_tuple`, `write_tuples`, `delete_tuples`, `delete_user_tuples` | `authz_reader` |
| `authz_admin` | `create_store`, `delete_store`, `model_register_type`, `model_register_relation`, manage `namespace_access` table | `authz_writer` |

`authz_auditor` inherits `authz_reader` (can query both live and historical permissions) but cannot write.
The PostgREST anonymous role (`api_anon`) inherits `authz_reader`.
All public functions are `SECURITY DEFINER` — application roles need no
direct table access.

```sql
-- Backend that needs to write tuples
GRANT authz_writer TO my_backend_user;

-- Admin tool that can manage stores
GRANT authz_admin TO my_admin_user;
```

## File Structure

| Path | Purpose |
|---|---|
| `db/engine/` | Core authorization engine — schema, access checks, tuple management, audit, model rules |
| `db/security/` | Role definitions and GRANT/SECURITY DEFINER setup |
| `db/openfga/` | OpenFGA JSON model and tuple import |
| `db/models/` | Example authorization models (demo, gdrive, github) with seed data and tests |
| `db/tests/` | Test suites (API, search, namespace, wildcards, contextual, intersection, etc.) |
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
| Exclusion / Difference (BUT NOT) | ✅ | ✅ |
| Wildcard tuples (`user:*`) | ✅ | ✅ |
| Conditions (ABAC) | ✅ | ✅ |
| Contextual tuples | ✅ | ✅ |
| List objects (resource search) | ✅ | ✅ |
| List users (subject search) | ✅ | ✅ |
| Multiple stores | ✅ | ✅ |
| Type restrictions on writes | ✅ | ✅ |

### This solution has, OpenFGA doesn't

| Capability | Notes |
|---|---|
| **Full audit trail** | Immutable, monthly-partitioned log with `performed_by` tracking |
| **Time-travel queries** | `audit_check_access` reconstructs permissions at any past timestamp |
| **`list_actions`** | "What can user X do on object Z?" — OpenFGA has no equivalent |
| **`explain_access`** | Full resolution trace showing every rule evaluated, with timing |
| **Namespace write control** | Restrict which applications can write tuples for which object types |
| **Condition validation** | Dry-run conditions before writing tuples |
| **Batch operations** | `write_tuples` / `delete_tuples` in a single statement |
| **No external service** | Pure SQL — no network hop, no separate process to operate |
| **OpenFGA import** | Import existing OpenFGA JSON models directly |

### OpenFGA has, this solution doesn't

| Capability | Impact | Notes |
|---|---|---|
| **Consistency tokens** | Low–Medium | Zanzibar-style tokens for read-after-write consistency in distributed setups. This solution uses PostgreSQL MVCC — strong consistency on a single instance, eventual consistency with read replicas (negligible lag for authorization data). |
| **Watch API** | Low | OpenFGA can stream tuple changes. This solution has the audit log for polling; PostgreSQL LISTEN/NOTIFY could fill the gap if needed. |
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
- You need the Watch API for real-time streaming of tuple changes
- You prefer the OpenFGA DSL for defining and reviewing models
