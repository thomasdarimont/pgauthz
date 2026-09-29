# Audit trail, time travel, and the changefeed

Every tuple, model, condition and gate change is captured by triggers into
immutable, monthly-partitioned audit tables with the acting application user
(`performed_by`). The same log answers three questions: **who changed what**
(audit queries), **what was true at time T** (`audit_check_access` replays the
tuples, rules, conditions and gates as of any past instant), and **what
changed since** (`watch_changes`, a cursored changefeed with a `NOTIFY`
doorbell). Retention and partition maintenance are operational topics in
[PRODUCTION → Audit retention](PRODUCTION.md#audit-retention); the action log
(what principals *did*, as opposed to what changed) is
[ADR 0012](adr/0012-action-log.md) and `record_event` / `list_events` in the
[API reference](API.md#record_event--list_events--the-action-log).

## Contents

- [Audit trail and time travel](#audit-trail-and-time-travel)
  - [Tracking application users](#tracking-application-users)
  - [Time-travel: "Could user X do Y at time T?"](#time-travel-could-user-x-do-y-at-time-t)
  - [Querying the audit trail](#querying-the-audit-trail)
- [Watching for changes (changefeed)](#watching-for-changes-changefeed)

## Audit trail and time travel

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
[audit_check_access](API.md#audit_check_access--point-in-time-permission-check)).

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

## Watching for changes (changefeed)

To react to tuple changes in real time — cache invalidation, materialization,
sync — stream them from the audit log instead of polling. Two pieces:

- **`NOTIFY authz_changes`** — the audit trigger emits a doorbell on every write,
  deduplicated to **one per store per transaction** (a 50-tuple batch → one
  notification). Payload is the `store_id`.
- **`authz.watch_changes(store, after_at, after_seq, …)`** — returns the decoded
  changes after a `(performed_at, seq)` cursor. The notify is only a doorbell;
  the cursor is the source of truth, so nothing is lost if a notification is
  missed, and a consumer resumes from its persisted cursor after a restart.

```sql
-- everything in 'demo' since a cursor:
SELECT * FROM authz.watch_changes('demo', '2026-06-01', 0);

-- filter by object types, namespaces, and/or relations (one watch covers many —
-- pass arrays; each is OR-within, all AND together; NULL = all). e.g. "viewer on
-- document/folder within the dms namespace":
SELECT * FROM authz.watch_changes('acme',
    p_object_types => ARRAY['document','folder'],
    p_namespaces   => ARRAY['dms'],
    p_relations    => ARRAY['viewer']);
-- The feed reports the raw changed tuple, not derived permission impact.

-- current high-water cursor (to start "from now"):
SELECT * FROM authz.watch_cursor('demo');
```

Consumer loop: `LISTEN authz_changes` → on notification call `watch_changes`
after the last cursor → process → persist the new cursor.

**Store lifecycle.** Most events are tuple changes (`action` `INSERT` / `DELETE`).
Retiring a store (`retire_store`) emits one **store-wide** `STORE_RETIRED` event
(with no tuple fields) instead of a delete per tuple — a consumer should treat it
as "invalidate everything for this store". It bypasses the object-type /
namespace / relation filters (a narrowly-scoped watcher still sees it), and
`watch_changes` / `watch_cursor` keep resolving a retired store so the consumer
can drain the changefeed's final events.

**Safety / lag.** `seq` is assigned at INSERT time, not commit time, so changes
are cursored by `(performed_at, seq)` and gated by a stability lag (`p_lag`,
default 1s): only rows older than `now() - p_lag` are returned. Because the
writer roles carry a `statement_timeout`, a write transaction cannot outlive it
— a lag at or above that bound is a hard no-skip guarantee; a smaller lag trades
that for lower latency (fine for at-least-once cache invalidation). For strict
exactly-once streaming, use logical replication on `tuples_audit`.

A runnable end-to-end demo (a `LISTEN` consumer + compose overlay) is in
[`examples/watch/`](../examples/watch/README.md).
