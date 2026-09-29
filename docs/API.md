# SQL API reference

The public SQL surface of the engine: one section per function, with its
signature, what it returns, and a worked call. Every function takes the
**store name** as its first parameter and is `SECURITY DEFINER`, so
application roles never need table access. Reads are granted to
`authz_reader`, writes to `authz_writer`, model changes to `authz_admin`,
history to `authz_auditor` — see [PRODUCTION → Role recipes](PRODUCTION.md#role-recipes).
For the HTTP surface (pgauthzd, AuthZEN) see [`pgauthzd/README.md`](../pgauthzd/README.md);
for modelling see [MODEL_DESIGN.md](MODEL_DESIGN.md); for the shortest
end-to-end walkthrough, the [complete example](../README.md#a-complete-example)
in the README.


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

## Contents

- [Functions](#functions)
  - [check_access — "Can user X do Y on object Z?"](#check_access--can-user-x-do-y-on-object-z)
  - [check_access_with_contextual_tuples — with ephemeral per-request tuples](#check_access_with_contextual_tuples--with-ephemeral-per-request-tuples)
  - [list_objects — "Which objects of type Z can user X do Y on?"](#list_objects--which-objects-of-type-z-can-user-x-do-y-on)
  - [list_subjects — "Which users of type X can do Y on object Z?"](#list_subjects--which-users-of-type-x-can-do-y-on-object-z)
  - [list_actions — "What can user X do on object Z?"](#list_actions--what-can-user-x-do-on-object-z)
  - [explain_access — "WHY was access allowed or denied?"](#explain_access--why-was-access-allowed-or-denied)
  - [write_tuple — Write a relationship tuple](#write_tuple--write-a-relationship-tuple)
  - [delete_tuple — Remove a relationship tuple](#delete_tuple--remove-a-relationship-tuple)
  - [write_tuples / delete_tuples — Batch operations](#write_tuples--delete_tuples--batch-operations)
  - [delete_user_tuples — Remove all tuples for a user](#delete_user_tuples--remove-all-tuples-for-a-user)
  - [audit_check_access — Point-in-time permission check](#audit_check_access--point-in-time-permission-check)
  - [audit_list_user / audit_list_object — Audit trail queries](#audit_list_user--audit_list_object--audit-trail-queries)
  - [record_event / list_events — The action log](#record_event--list_events--the-action-log)
- [Recipes](#recipes)
  - [Permission checks](#permission-checks)
  - [Search queries](#search-queries)
  - [Writing and deleting tuples](#writing-and-deleting-tuples)

## Functions

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
> it to untrusted clients. See [Access control roles](ARCHITECTURE.md#access-control-roles).

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
-- => doc_acc_001, doc_folder_payroll_q1_001, doc_folder_tax_001,
--    doc_payroll_001, doc_tax_001
--    (3 engagement docs as advisor + 2 docs in the workpapers folder bob owns)
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
      "matched_tuple": "internal_user:alice → member → team:payroll_team",
      //               ^ the exact stored tuple that granted this step
      //                 (wildcards resolved; null when redacted)
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
`condition_denied`, or `no_matching_rule`. A step whose conditional tuple
counted **only by assumption** — a subtracted term (`BUT NOT …`) whose
condition lacked request context and was therefore taken as holding, fail
closed — carries `condition_assumed` with its `condition_name` and
`condition_missing_keys` (see [Missing context](MODEL_DESIGN.md#missing-context)).

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
This is easier to use from HTTP clients (e.g. pgauthzd's HTTP API) and languages without native composite-type support:

```sql
-- JSONB variant: same as above, but with a JSON array of objects.
-- Use the _jsonb suffix functions from HTTP clients (pgauthzd's HTTP API) or
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

### record_event / list_events — The action log

The audit trail records how the *graph* changed. The action log records what
subjects **actually did** — reported by your application/PEP *after* the
action ran, never inferred from a decision (an "allow" is not an action). It
is the substrate for history-dependent rules ("at most 5 transfers per hour",
"only if an approver approved this within the hour") and, on its own, a
per-store, per-principal action trail next to the graph. See
[ADR 0012](adr/0012-action-log.md).

```sql
-- Declare the action once: an action is a relation of the store (the model is
-- the action vocabulary — a typo fails loud at record time).
SELECT authz.model_register_relation('demo', 'transfer');

-- Record that alice transferred from acc-1 (the PEP calls this after the
-- action ran). kind: request | response | denied. The payload is the
-- authz-relevant projection, not your domain object.
SELECT authz.record_event('demo', 'internal_user', 'alice', 'transfer',
    p_object_type => 'account', p_object_id => 'acc-1',
    p_kind        => 'response',
    p_payload     => '{"input": {"amount": 1200}, "output": {"status": "ok"}}',
    p_occurred_at => '2026-09-17T10:15:02Z',      -- required with an event_id
    p_event_id    => 'req-7f3a/response');        -- idempotency key: re-delivery = duplicate, not a row

-- Batch form (what pgauthzd's POST /pgauthz/v1/events calls); atomic.
SELECT authz.record_events_jsonb('demo', '[
  {"subject_type": "internal_user", "subject_id": "alice", "action": "transfer",
   "object_type": "account", "object_id": "acc-1", "kind": "request",
   "payload": {"input": {"amount": 1200}}}
]');
-- → {"recorded": 1, "duplicates": 0, "seqs": [42]}

-- What did alice do in the last hour? (auditor role; every filter optional;
-- keyset cursor over (occurred_at, seq) like watch_changes)
SELECT occurred_at, action, kind, object_type, object_id, payload
  FROM authz.list_events('demo', p_subject_type => 'internal_user',
                         p_subject_id => 'alice', p_since => now() - interval '1 hour');
```

Recording needs the `authz_recorder` role (granted to every writer; an app
that only reports actions never needs tuple-write rights). **Treat it as a
PEP-only credential:** the log is what a recorder *claims* happened and gates
decide on it, so grant the role — and the `RECORDER_ROLE` claim on the HTTP
API — to enforcement points and ingestion services, never to end-user-facing
clients; see the [ADR 0012 trust model](adr/0012-action-log.md#3-trust-model-for-recorded-events).
`occurred_at` is
caller-supplied but bounded (`authz.event_max_future_skew`, default 5 s;
`authz.event_max_backdate`, default 24 h); `recorded_at` and `recorded_by`
are server-set. The log is append-only and monthly-partitioned like the audit
trail (`ensure_event_partitions`, `drop_event_partitions_before`).

The model can own the payload shape: `model_set_payload_schema('demo',
'transfer', '{"required": {"input.amount": "number"}, "kinds": {"response":
{"required": {"output.status": "string"}}}}')` makes `record_event` reject a
transfer without a numeric `input.amount` (400 over HTTP, batch atomic) and
makes `add_gate` refuse a clause that sums or matches a path no recorder is
obliged to send. Actions without a schema accept any object payload; see
[MODEL_DESIGN §17 → Payload schemas](MODEL_DESIGN.md#payload-schemas-the-model-owns-the-projection).

## Recipes

Copy-paste queries against the `demo` example model
(`examples/models/demo/`).


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
-- => doc_acc_001, doc_folder_payroll_q1_001, doc_folder_tax_001,
--    doc_payroll_001, doc_tax_001
--    (3 engagement docs as advisor + 2 docs in the workpapers folder bob owns)

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
