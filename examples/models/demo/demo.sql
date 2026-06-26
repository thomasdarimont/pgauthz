-- ============================================================================
-- Eurodata Authorization Engine — Interactive Demo
-- ============================================================================
--
-- This file walks through the core features of the Zanzibar-style
-- authorization engine implemented in pure PostgreSQL.
--
-- Prerequisites: run ./bootstrap.sh (or ./init.sh) to load schema + seed data.
--
-- Tip: run individual sections in a SQL console to see the results.
-- ============================================================================


-- ============================================================================
-- 1. ACCESS CHECKS — "Can user X do action Y on resource Z?"
-- ============================================================================

-- The seed data models a professional services firm (Eurodata) with:
--
--   Internal users:  alice (payroll), bob (advisor), julia (assistant),
--                    eva (accounting), frank (tax)
--   Client users:    carol, dave (both members of client_org:acme)
--   Engagement:      eng_42 (client: acme, advisor: bob, assistant: julia)
--   Assignments:     eng_42_payroll, eng_42_accounting, eng_42_tax
--   Documents:       in internal and client data spaces

-- Alice is on the payroll team → payroll_clerk on eng_42_payroll assignment
-- → can_view on the internal data space → can_read on documents in that space.
SELECT authz.check_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001');
-- => true

-- Alice is NOT on the tax team, so she cannot read tax documents.
SELECT authz.check_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_tax_001');
-- => false

-- Bob is advisor on the engagement → internal_collaborator on all assignments
-- → can read ALL internal documents across payroll, accounting, and tax.
SELECT authz.check_access('demo',
    'internal_user', 'bob', 'can_read', 'document', 'doc_payroll_001');
-- => true

SELECT authz.check_access('demo',
    'internal_user', 'bob', 'can_read', 'document', 'doc_tax_001');
-- => true

-- Julia is assistant (not advisor) → she can read but NOT edit.
SELECT authz.check_access('demo',
    'internal_user', 'julia', 'can_read', 'document', 'doc_payroll_001');
-- => true

SELECT authz.check_access('demo',
    'internal_user', 'julia', 'can_edit', 'document', 'doc_payroll_001');
-- => false  (only advisors and assigned role holders can edit)

-- Carol is a member of client_org:acme → client on eng_42
-- → can read documents in the client data space.
SELECT authz.check_access('demo',
    'client_user', 'carol', 'can_read', 'document', 'doc_client_001');
-- => true

-- But clients cannot edit client-space documents.
SELECT authz.check_access('demo',
    'client_user', 'carol', 'can_edit', 'document', 'doc_client_001');
-- => false

-- Carol has an viewer grant on a private doc that Dave doesn't have.
SELECT authz.check_access('demo',
    'client_user', 'carol', 'can_read', 'document', 'doc_client_private_001');
-- => true

SELECT authz.check_access('demo',
    'client_user', 'dave', 'can_read', 'document', 'doc_client_private_001');
-- => false


-- ============================================================================
-- 1b. BATCH ACCESS CHECKS — AuthZEN Evaluations API
-- ============================================================================
--
-- check_access_batch evaluates multiple access checks in a single call.
-- This maps directly to the AuthZEN POST /access/v1/evaluations endpoint.
-- Returns SETOF authz.access_check_result (one row per input check, same order).

-- Check multiple permissions in one call (execute_all — default).
-- "Can Alice read the payroll doc? Can she edit it? Can she delete it?"
SELECT * FROM authz.check_access_batch_typed('demo', ARRAY[
    ('internal_user', 'alice', 'can_read',   'document', 'doc_payroll_001'),
    ('internal_user', 'alice', 'can_edit',   'document', 'doc_payroll_001'),
    ('internal_user', 'alice', 'can_delete', 'document', 'doc_payroll_001')
]::authz.access_check[]);
-- => (internal_user, alice, can_read,   document, doc_payroll_001, t)
--    (internal_user, alice, can_edit,   document, doc_payroll_001, t)
--    (internal_user, alice, can_delete, document, doc_payroll_001, f)

-- Different users, different resources in one batch.
-- Useful for rendering a UI with multiple permission-gated elements.
SELECT * FROM authz.check_access_batch_typed('demo', ARRAY[
    ('internal_user', 'alice', 'can_read',  'document', 'doc_payroll_001'),
    ('internal_user', 'bob',   'can_read',  'document', 'doc_payroll_001'),
    ('internal_user', 'eva',   'can_read',  'document', 'doc_payroll_001'),
    ('client_user',   'carol', 'can_read',  'document', 'doc_client_001'),
    ('internal_user', 'frank', 'can_edit',  'document', 'doc_tax_001')
]::authz.access_check[]);
-- => decisions: t, t, f, t, t  (eva can't read payroll — wrong team)

-- Short-circuit: deny_on_first_deny.
-- Stops evaluating as soon as any check returns false.
-- Remaining rows have decision = NULL (not evaluated).
-- Use case: "user must have ALL of these permissions to proceed"
SELECT * FROM authz.check_access_batch_typed('demo', ARRAY[
    ('internal_user', 'alice', 'can_read',   'document', 'doc_payroll_001'),
    ('internal_user', 'alice', 'can_edit',   'document', 'doc_payroll_001'),
    ('internal_user', 'alice', 'can_delete', 'document', 'doc_payroll_001'),
    ('internal_user', 'alice', 'can_read',   'document', 'doc_acc_001')
]::authz.access_check[], p_semantic => 'deny_on_first_deny');
-- => decisions: t, t, f, NULL  (stops at can_delete=false, never checks doc_acc_001)

-- Short-circuit: permit_on_first_permit.
-- Stops evaluating as soon as any check returns true.
-- Use case: "user needs at least ONE of these permissions"
SELECT * FROM authz.check_access_batch_typed('demo', ARRAY[
    ('internal_user', 'eva',   'can_read',  'document', 'doc_payroll_001'),
    ('internal_user', 'eva',   'can_read',  'document', 'doc_acc_001'),
    ('internal_user', 'eva',   'can_read',  'document', 'doc_tax_001')
]::authz.access_check[], p_semantic => 'permit_on_first_permit');
-- => decisions: f, t, NULL  (eva can't read payroll, but CAN read accounting — stops there)


-- ============================================================================
-- 2. SEARCH APIs — AuthZen-compatible resource, subject, and action search
-- ============================================================================

-- Which documents can Bob read?
-- (advisor → all three internal docs, but not client docs)
SELECT * FROM authz.list_objects('demo',
    'internal_user', 'bob', 'can_read', 'document');
-- => doc_payroll_001, doc_acc_001, doc_tax_001

-- Which documents can Alice read?
-- (payroll team only → just the payroll doc)
SELECT * FROM authz.list_objects('demo',
    'internal_user', 'alice', 'can_read', 'document');
-- => doc_payroll_001

-- Which documents can Carol read?
-- (acme member → client docs + viewer on private doc)
SELECT * FROM authz.list_objects('demo',
    'client_user', 'carol', 'can_read', 'document');
-- => doc_client_001, doc_client_002, doc_client_private_001

-- Which internal users can read the payroll document?
SELECT * FROM authz.list_subjects('demo',
    'internal_user', 'can_read', 'document', 'doc_payroll_001');
-- => alice, bob, julia

-- Which internal users can EDIT the payroll document?
-- (Julia is excluded — assistant, not advisor/payroll_clerk)
SELECT * FROM authz.list_subjects('demo',
    'internal_user', 'can_edit', 'document', 'doc_payroll_001');
-- => alice, bob

-- What can Alice do on the payroll doc?
SELECT * FROM authz.list_actions('demo',
    'internal_user', 'alice', 'document', 'doc_payroll_001');
-- => can_read, can_edit

-- What can Bob do on the payroll doc?
-- (advisor gets can_delete via can_manage_access from engagement)
SELECT * FROM authz.list_actions('demo',
    'internal_user', 'bob', 'document', 'doc_payroll_001');
-- => can_read, can_edit, can_delete

-- What can Carol do on a client doc?
SELECT * FROM authz.list_actions('demo',
    'client_user', 'carol', 'document', 'doc_client_001');
-- => can_read


-- ============================================================================
-- 3. WRITING TUPLES — adding new relationships
-- ============================================================================

-- 3a. Explicit parameters — no string parsing, each field is a separate argument.
SELECT authz.write_tuple('demo',
    'internal_user', 'grace',       -- user_type, user_id
    'member',                       -- relation
    'team', 'payroll_team'          -- object_type, object_id
);

-- Grace is now on the payroll team → inherits payroll_clerk on eng_42_payroll
-- → can read payroll documents.
SELECT authz.check_access('demo',
    'internal_user', 'grace', 'can_read', 'document', 'doc_payroll_001');
-- => true

-- Explicit parameters with a userset (e.g. team:payroll_team#member → role on assignment).
SELECT authz.write_tuple('demo',
    'team', 'payroll_team',             -- user_type, user_id
    'payroll_clerk',                    -- relation
    'assignment', 'eng_42_demo',        -- object_type, object_id
    p_user_relation => 'member'         -- userset relation
);

-- 3b. More examples with explicit parameters.
SELECT authz.write_tuple('demo',
    'internal_user', 'hank', 'member', 'team', 'payroll_team');

SELECT authz.check_access('demo',
    'internal_user', 'hank', 'can_read', 'document', 'doc_payroll_001');
-- => true

SELECT authz.write_tuple('demo',
    'internal_user', 'ivan', 'member', 'team', 'payroll_team');

-- 3c. Batch insert — multiple tuples in a single statement.
-- Uses the authz.tuple_input composite type. Much more efficient than
-- calling write_tuple in a loop (one INSERT, one transaction).
-- Returns the number of tuples actually inserted (duplicates are skipped).
SELECT authz.write_tuples('demo', ARRAY[
    ('internal_user','grace', NULL, 'viewer', 'document','doc_finance_001'),
    ('internal_user','hank',  NULL, 'viewer', 'document','doc_finance_001'),
    ('internal_user','ivan',  NULL, 'viewer', 'document','doc_finance_001')
]::authz.tuple_input[]);
-- => 3

-- Inserting the same tuples again returns 0 (all skipped as duplicates):
SELECT authz.write_tuples('demo', ARRAY[
    ('internal_user','grace', NULL, 'viewer', 'document','doc_finance_001'),
    ('internal_user','hank',  NULL, 'viewer', 'document','doc_finance_001')
]::authz.tuple_input[]);
-- => 0

-- 3e. Batch delete — remove multiple tuples in a single statement.
-- Returns the number of tuples actually deleted.
SELECT authz.delete_tuples('demo', ARRAY[
    ('internal_user','grace', NULL, 'viewer', 'document','doc_finance_001'),
    ('internal_user','hank',  NULL, 'viewer', 'document','doc_finance_001'),
    ('internal_user','ivan',  NULL, 'viewer', 'document','doc_finance_001')
]::authz.tuple_input[]);
-- => 3

-- Both batch functions support the p_performed_by parameter:
SELECT authz.write_tuples('demo', ARRAY[
    ('internal_user','grace', NULL, 'viewer', 'document','doc_finance_001')
]::authz.tuple_input[], p_performed_by => 'admin');

SELECT authz.delete_tuples('demo', ARRAY[
    ('internal_user','grace', NULL, 'viewer', 'document','doc_finance_001')
]::authz.tuple_input[], p_performed_by => 'admin');

-- 3f. Remove all access for a user — revokes every tuple for that user.
-- Useful for offboarding or emergency access revocation.
SELECT authz.write_tuples('demo', ARRAY[
    ('internal_user','grace', NULL, 'viewer', 'document','doc_finance_001'),
    ('internal_user','grace', NULL, 'editor', 'document','doc_finance_002')
]::authz.tuple_input[]);

SELECT authz.delete_user_tuples('demo', 'internal_user', 'grace',
    p_performed_by => 'admin');
-- => 3 (all of grace's direct tuples removed)

-- Note: this removes direct grants only. If the user has access through
-- group/team membership, remove them from the group as well:
--   SELECT authz.delete_tuple('demo', 'internal_user', 'grace', 'member',
--       'team', 'payroll_team', p_performed_by => 'admin');

-- Clean up demo tuples
DELETE FROM authz.tuples
 WHERE user_id IN ('grace', 'hank', 'ivan')
   AND user_type = authz._t('demo', 'internal_user');

DELETE FROM authz.tuples
 WHERE object_id = 'eng_42_demo'
   AND object_type = authz._t('demo', 'assignment');


-- ============================================================================
-- 4. CONDITIONS — attribute-based access control (ABAC)
-- ============================================================================

-- Conditions are SQL expressions evaluated at check time. They receive:
--   $1 = request context (passed by the caller at check time)
--   $2 = stored context  (saved with the tuple when written)

-- First, register a "viewer" relation on documents (if not already present).
INSERT INTO authz.relations (store_id, name)
SELECT authz._s('demo'), 'viewer' WHERE NOT EXISTS (
    SELECT 1 FROM authz.relations WHERE store_id = authz._s('demo') AND name = 'viewer'
);

INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                                computed_relation, tupleset_relation, tupleset_computed)
SELECT authz._s('demo'),
       authz._t('demo', 'document'),
       authz._r('demo', 'viewer'),
       1, NULL, NULL, NULL
WHERE NOT EXISTS (
    SELECT 1 FROM authz.models
     WHERE store_id    = authz._s('demo')
       AND object_type = authz._t('demo', 'document')
       AND relation    = authz._r('demo', 'viewer')
       AND rule_type   = 1
);

-- Create a time-based condition: access expires after a grant window.
SELECT authz.create_condition_sql('demo',
    'non_expired_grant',
    $cond$
        ($1->>'current_time')::timestamptz
        < ($2->>'grant_time')::timestamptz + ($2->>'grant_duration')::interval
    $cond$,
    '{"request": ["current_time"], "stored": ["grant_time", "grant_duration"]}'::jsonb
);

-- Write a conditional tuple: Alice can view doc_temp_001, but only for 2 hours.
SELECT authz.write_tuple('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001',
    p_condition => 'non_expired_grant',
    p_condition_context => '{"grant_time": "2026-03-11T09:00:00Z", "grant_duration": "2 hours"}'::jsonb
);

-- Within the grant window (09:00–11:00) → allowed.
SELECT authz.check_access_with_context('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001',
    '{"current_time": "2026-03-11T10:00:00Z"}'::jsonb);
-- => true

-- After the window expires → denied.
SELECT authz.check_access_with_context('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001',
    '{"current_time": "2026-03-11T12:00:00Z"}'::jsonb);
-- => false

-- Without context → denied (condition cannot be evaluated, fails safely).
SELECT authz.check_access('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001');
-- => false

-- Clean up
DELETE FROM authz.tuples
 WHERE object_id = 'doc_temp_001'
   AND object_type = authz._t('demo', 'document');


-- 4b. Composite condition: time window AND IP range -------------------------

-- For use cases that require multiple constraints (AND/OR), define a single
-- composite condition that combines them in one SQL expression.
-- No schema changes needed — just a more specific expression.

SELECT authz.create_condition_sql('demo',
    'non_expired_grant_and_ip',
    $cond$
        -- Time window: $1.current_time must be before $2.grant_time + $2.grant_duration
        ($1->>'current_time')::timestamptz
        < ($2->>'grant_time')::timestamptz + ($2->>'grant_duration')::interval
        -- AND IP allowlist: $1.client_ip must be within $2.allowed_cidr
        AND ($1->>'client_ip')::inet <<= ($2->>'allowed_cidr')::cidr
    $cond$,
    '{"request": ["current_time", "client_ip"], "stored": ["grant_time", "grant_duration", "allowed_cidr"]}'::jsonb
);

-- Write a conditional tuple: Bob can view doc_secure_001, but only
-- within a 2-hour window AND from the 10.0.0.0/8 network.
SELECT authz.write_tuple('demo',
    'internal_user', 'bob', 'viewer', 'document', 'doc_secure_001',
    p_condition => 'non_expired_grant_and_ip',
    p_condition_context => '{"grant_time": "2026-03-11T09:00:00Z", "grant_duration": "2 hours", "allowed_cidr": "10.0.0.0/8"}'::jsonb
);

-- Within the time window AND from the allowed network → granted.
SELECT authz.check_access_with_context('demo',
    'internal_user', 'bob', 'viewer', 'document', 'doc_secure_001',
    '{"current_time": "2026-03-11T10:00:00Z", "client_ip": "10.0.1.42"}'::jsonb);
-- => true

-- Within the time window BUT from an outside network → denied.
SELECT authz.check_access_with_context('demo',
    'internal_user', 'bob', 'viewer', 'document', 'doc_secure_001',
    '{"current_time": "2026-03-11T10:00:00Z", "client_ip": "192.168.1.1"}'::jsonb);
-- => false

-- From the allowed network BUT after the time window → denied.
SELECT authz.check_access_with_context('demo',
    'internal_user', 'bob', 'viewer', 'document', 'doc_secure_001',
    '{"current_time": "2026-03-11T12:00:00Z", "client_ip": "10.0.1.42"}'::jsonb);
-- => false

-- Clean up
DELETE FROM authz.tuples
 WHERE object_id = 'doc_secure_001'
   AND object_type = authz._t('demo', 'document');


-- ============================================================================
-- 5. CONTEXTUAL TUPLES — ephemeral per-request relationships
-- ============================================================================

-- Contextual tuples grant access for a single check without persisting anything.
-- They are useful when the application knows something is temporarily true
-- but it shouldn't be stored as a permanent relationship.

-- 5a. Direct grant --------------------------------------------------------

-- Frank normally cannot view this client document.
SELECT authz.check_access('demo',
    'internal_user', 'frank', 'viewer', 'document', 'doc_client_001');
-- => false

-- But with a contextual tuple, he can.
SELECT authz.check_access_with_contextual_tuples('demo',
    'internal_user', 'frank', 'viewer', 'document', 'doc_client_001',
    contextual_tuples => ARRAY[
        ROW('internal_user', 'frank', NULL, 'viewer', 'document', 'doc_client_001')
    ]::authz.tuple_input[]
);
-- => true

-- The tuple did not persist — Frank is denied again.
SELECT authz.check_access('demo',
    'internal_user', 'frank', 'viewer', 'document', 'doc_client_001');
-- => false

-- 5b. Delegation --------------------------------------------------------
-- Bob (advisor) is on vacation and delegates approval rights to Julia.
-- Rather than writing a permanent tuple and remembering to clean it up,
-- the application injects a contextual tuple for each request during
-- the delegation period.

-- Julia normally cannot approve on the payroll assignment (she's assistant, not advisor).
SELECT authz.check_access('demo',
    'internal_user', 'julia', 'can_approve', 'assignment', 'eng_42_payroll');
-- => false

-- With a contextual tuple granting her the accountant role, she can.
SELECT authz.check_access_with_contextual_tuples('demo',
    'internal_user', 'julia', 'can_approve', 'assignment', 'eng_42_payroll',
    contextual_tuples => ARRAY[
        ROW('internal_user', 'julia', NULL, 'accountant', 'assignment', 'eng_42_payroll')
    ]::authz.tuple_input[]
);
-- => true  (accountant → can_approve via computed rule)

-- Nothing persisted — Julia is back to assistant-only access.
SELECT authz.check_access('demo',
    'internal_user', 'julia', 'can_approve', 'assignment', 'eng_42_payroll');
-- => false

-- 5c. Preview / dry-run --------------------------------------------------
-- "What would happen if we gave the tax team access to the engagement
--  as assistants? Would Frank be able to read payroll documents?"
--
-- We can test the effect of a proposed relationship change without
-- writing anything to the database.

-- Frank currently cannot read the payroll doc (tax team, wrong assignment).
SELECT authz.check_access('demo',
    'internal_user', 'frank', 'can_read', 'document', 'doc_payroll_001');
-- => false

-- Dry-run: inject a contextual userset tuple making tax_team#member
-- an assistant on engagement eng_42.
SELECT authz.check_access_with_contextual_tuples('demo',
    'internal_user', 'frank', 'can_read', 'document', 'doc_payroll_001',
    contextual_tuples => ARRAY[
        ROW('team', 'tax_team', 'member', 'assistant', 'engagement', 'eng_42')
    ]::authz.tuple_input[]
);
-- => true  (tax_team#member → assistant → internal_collaborator → can_view
--           on internal_data_space → can_read on document)

-- The real data is unchanged — Frank still can't read payroll docs.
SELECT authz.check_access('demo',
    'internal_user', 'frank', 'can_read', 'document', 'doc_payroll_001');
-- => false


-- ============================================================================
-- 6. HISTORICAL ACCESS & AUDIT TRAIL
-- ============================================================================

-- Time-based conditional tuples remain in the database even after they expire.
-- This means you can answer two questions:
--   1. Did a user ever have access?
--   2. What access did a user have at a specific point in time?

-- Set up a time-limited grant (reusing the condition from section 4).
INSERT INTO authz.relations (store_id, name)
SELECT authz._s('demo'), 'viewer' WHERE NOT EXISTS (
    SELECT 1 FROM authz.relations WHERE store_id = authz._s('demo') AND name = 'viewer'
);

INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                                computed_relation, tupleset_relation, tupleset_computed)
SELECT authz._s('demo'),
       authz._t('demo', 'document'),
       authz._r('demo', 'viewer'),
       1, NULL, NULL, NULL
WHERE NOT EXISTS (
    SELECT 1 FROM authz.models
     WHERE store_id    = authz._s('demo')
       AND object_type = authz._t('demo', 'document')
       AND relation    = authz._r('demo', 'viewer')
       AND rule_type   = 1
);

SELECT authz.create_condition_sql('demo',
    'non_expired_grant',
    $cond$
        ($1->>'current_time')::timestamptz
        < ($2->>'grant_time')::timestamptz + ($2->>'grant_duration')::interval
    $cond$,
    '{"request": ["current_time"], "stored": ["grant_time", "grant_duration"]}'::jsonb
);

-- Alice gets temporary viewer access to a document (2-hour window on March 11).
SELECT authz.write_tuple('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001',
    p_condition => 'non_expired_grant',
    p_condition_context => '{"grant_time": "2026-03-11T09:00:00Z", "grant_duration": "2 hours"}'::jsonb
);

-- 6a. Point-in-time access check ------------------------------------------
-- "What access did Alice have at 10:00 on March 11?"
-- Just pass the historical timestamp as request context.

SELECT authz.check_access_with_context('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001',
    '{"current_time": "2026-03-11T10:00:00Z"}'::jsonb)
    AS "alice had access at 10:00";
-- => true (within the 09:00–11:00 window)

SELECT authz.check_access_with_context('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001',
    '{"current_time": "2026-03-11T23:00:00Z"}'::jsonb)
    AS "alice had no access at 23:00";
-- => false (after the window)

-- 6b. Finding expired grants -----------------------------------------------
-- "Did Alice ever have access to doc_temp_001?"
-- The conditional tuple is still in the database — query it directly.

SELECT
    ut.name AS user_type, t.user_id,
    r.name  AS relation,
    ot.name AS object_type, t.object_id,
    c.name  AS condition_name,
    t.condition_context->>'grant_time' AS grant_time,
    t.condition_context->>'grant_duration' AS grant_duration
  FROM authz.tuples t
  JOIN authz.types ut     ON ut.id = t.user_type
  JOIN authz.relations r  ON r.id  = t.relation
  JOIN authz.types ot     ON ot.id = t.object_type
  LEFT JOIN authz.conditions c ON c.id = t.condition_id
 WHERE t.store_id    = authz._s('demo')
   AND t.user_type   = authz._t(authz._s('demo'), 'internal_user')
   AND t.user_id     = 'alice'
   AND t.object_type = authz._t(authz._s('demo'), 'document')
   AND t.object_id   = 'doc_temp_001';
-- => Shows the tuple with grant_time and grant_duration, proving access was granted.

-- 6c. Audit trail ---------------------------------------------------------
-- Every tuple INSERT and DELETE is recorded in authz.tuples_audit.
-- This covers ALL changes, not just conditional tuples.

-- Write and then delete a tuple to see both events in the audit log.
SELECT authz.write_tuple('demo', 'internal_user', 'grace', 'member', 'team', 'payroll_team');
SELECT authz.delete_tuple('demo', 'internal_user', 'grace', 'member', 'team', 'payroll_team');

-- View the audit trail (human-readable view).
SELECT action, performed_at, performed_by,
       user_type, user_id, relation, object_type, object_id
  FROM authz.tuples_audit_view
 WHERE store = 'demo'
   AND user_id = 'grace'
 ORDER BY performed_at;
-- => Two rows: INSERT then DELETE, with timestamps and who performed each action.

-- You can also query the audit log for a specific resource:
-- "Who has ever had any relationship with doc_temp_001?"
SELECT action, performed_at, user_type, user_id, relation,
       condition_name, condition_context
  FROM authz.tuples_audit_view
 WHERE store = 'demo'
   AND object_type = 'document'
   AND object_id = 'doc_temp_001'
 ORDER BY performed_at;

-- Or audit all changes in a time window:
-- "What tuple changes happened in the last hour?"
SELECT action, performed_at, user_type, user_id, relation, object_type, object_id
  FROM authz.tuples_audit_view
 WHERE store = 'demo'
   AND performed_at >= now() - interval '1 hour'
 ORDER BY performed_at;

-- Clean up
SELECT authz.delete_tuple('demo', 'internal_user', 'alice', 'viewer', 'document', 'doc_temp_001');

-- 6d. Time-travel permissions review ---------------------------------------
-- "What permissions did a user have at a specific point in the past?"
-- audit_check_access and audit_list_actions reconstruct the tuple state from
-- the audit log and run access checks against that historical snapshot.

-- Set up a scenario: grant Grace team membership, then revoke it.
SELECT authz.write_tuple('demo', 'internal_user', 'grace', 'member', 'team', 'payroll_team');

-- Grace can now read payroll documents.
SELECT authz.check_access('demo',
    'internal_user', 'grace', 'can_read', 'document', 'doc_payroll_001')
    AS "grace can read now";
-- => true

-- Capture the current time (while Grace still has access), then revoke.
-- We use set_config to store the timestamp in a session variable so it
-- survives across statements — this is more reliable than clock arithmetic.
SELECT set_config('demo.grace_had_access_at', clock_timestamp()::text, false);
SELECT authz.delete_tuple('demo', 'internal_user', 'grace', 'member', 'team', 'payroll_team');

-- Grace can no longer read payroll documents.
SELECT authz.check_access('demo',
    'internal_user', 'grace', 'can_read', 'document', 'doc_payroll_001')
    AS "grace cannot read anymore";
-- => false

-- But we can check what she could do at the saved timestamp (before revocation):
SELECT authz.audit_check_access('demo',
    'internal_user', 'grace', 'can_read', 'document', 'doc_payroll_001',
    current_setting('demo.grace_had_access_at')::timestamptz)
    AS "grace could read before revocation";
-- => true

-- What actions could she perform at that time?
SELECT * FROM authz.audit_list_actions('demo',
    'internal_user', 'grace', 'document', 'doc_payroll_001',
    current_setting('demo.grace_had_access_at')::timestamptz);
-- => can_read, can_edit (via payroll_team membership)

-- Compare with her current permissions (none):
SELECT * FROM authz.list_actions('demo',
    'internal_user', 'grace', 'document', 'doc_payroll_001');
-- => (empty)

-- 6e. Audit trail queries --------------------------------------------------
-- audit_list_user: "What permission changes happened to this user?"

SELECT * FROM authz.audit_list_user('demo', 'internal_user', 'grace');
-- => Shows INSERT (member of payroll_team) and DELETE (revoked)

-- audit_list_object: "What permission changes happened on this object?"
SELECT * FROM authz.audit_list_object('demo', 'document', 'doc_payroll_001');
-- => Shows all permission changes on doc_payroll_001 (from seed data + demo)

-- Both support optional time range filters:
SELECT * FROM authz.audit_list_user('demo', 'internal_user', 'alice',
    now() - interval '1 hour', now());

-- 6f. Tracking who made changes (application user) -------------------------
-- By default, performed_by records the DB session user. Applications can
-- pass the authenticated end-user via the p_performed_by parameter:

SELECT authz.write_tuple('demo',
    'internal_user', 'frank', 'viewer', 'document', 'doc_payroll_001',
    p_performed_by => 'admin');

-- The audit trail now shows who in the application made the change:
SELECT * FROM authz.audit_list_user('demo', 'internal_user', 'frank');
-- => performed_by = 'admin'

SELECT authz.delete_tuple('demo',
    'internal_user', 'frank', 'viewer', 'document', 'doc_payroll_001',
    p_performed_by => 'admin');

-- 6g. Audit partition management --------------------------------------------
-- The audit table is partitioned by RANGE on performed_at (monthly).
-- ensure_audit_partitions() creates the current month plus N months
-- ahead (default 1). init.sh runs it at setup; schedule it (e.g. daily)
-- so rows never accumulate in the default partition:

SELECT authz.ensure_audit_partitions();        -- current + next month
SELECT authz.ensure_audit_partitions(3);       -- current + three ahead

-- To drop old audit data, just detach and drop old partitions:
-- ALTER TABLE authz.tuples_audit DETACH PARTITION authz.tuples_audit_2025_01;
-- DROP TABLE authz.tuples_audit_2025_01;


-- ============================================================================
-- 7. MULTI-STORE — independent authorization namespaces
-- ============================================================================

-- Each store has its own types, relations, model rules, tuples, and
-- conditions. Useful for multi-tenant deployments or staging vs. production.

-- Create a second, independent store.
SELECT authz.create_store('demo2');

-- Give demo2 a minimal model (the same shape as the query below) so name
-- resolution succeeds. demo2 has NO tuples, so the check returns false —
-- alice's payroll access in the 'demo' store does not leak into 'demo2'.
SELECT authz.model_register_type('demo2', 'internal_user');
SELECT authz.model_register_type('demo2', 'document');
SELECT authz.model_register_relation('demo2', 'can_read');
SELECT authz.model_add_rule('demo2', 'document', 'can_read', 'direct');

SELECT authz.check_access('demo2',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001');
-- => false  (demo2 has the model but no tuples — isolated from 'demo')

-- Meanwhile the original 'demo' store is unaffected.
SELECT authz.check_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001');
-- => true

-- Clean up the second store (drops its types, relations, models, and tuples).
SELECT authz.delete_store('demo2');


-- ============================================================================
-- 8. PERMISSION RESOLUTION WALKTHROUGH
-- ============================================================================

-- How does "Alice can_read doc_payroll_001" get resolved?
-- The engine follows three rule types recursively:
--
-- Step 1: can_read on document has a tuple-to-userset (TTU) rule:
--         "can_read = can_view FROM in_internal_space"
--         → find which internal_data_space the document is in:

SELECT t.user_id AS linked_space
  FROM authz.tuples t
 WHERE t.store_id    = authz._s('demo')
   AND t.object_type = authz._t('demo', 'document')
   AND t.object_id   = 'doc_payroll_001'
   AND t.relation    = authz._r('demo', 'in_internal_space');
-- => eng_42_payroll_internal

-- Step 2: can_view on internal_data_space has a TTU rule:
--         "can_view = can_view FROM parent_assignment"
--         → find the parent assignment:

SELECT t.user_id AS linked_assignment
  FROM authz.tuples t
 WHERE t.store_id    = authz._s('demo')
   AND t.object_type = authz._t('demo', 'internal_data_space')
   AND t.object_id   = 'eng_42_payroll_internal'
   AND t.relation    = authz._r('demo', 'parent_assignment');
-- => eng_42_payroll

-- Step 3: can_view on assignment has a computed rule:
--         "can_view = payroll_clerk"
--         → check if Alice is payroll_clerk on eng_42_payroll:

SELECT EXISTS (
    SELECT 1 FROM authz.tuples t
     WHERE t.store_id    = authz._s('demo')
       AND t.object_type = authz._t('demo', 'assignment')
       AND t.object_id   = 'eng_42_payroll'
       AND t.relation    = authz._r('demo', 'payroll_clerk')
);
-- => false (Alice is not directly a payroll_clerk — it's a USERSET)

-- Step 4: The tuple is team:payroll_team#member → payroll_clerk → assignment:eng_42_payroll
--         So the engine checks: is Alice a member of payroll_team?

SELECT authz.check_access('demo',
    'internal_user', 'alice', 'member', 'team', 'payroll_team');
-- => true  ✓

-- The full resolution: alice ∈ payroll_team#member → payroll_clerk on assignment
--   → can_view on assignment → can_view on internal_data_space → can_read on document.


-- ============================================================================
-- 9. EXPLAIN — "WHY was access allowed or denied?"
-- ============================================================================
--
-- Section 8 traced the resolution by hand. explain_access does it for you:
-- it returns a structured decision explanation:
--
--   { "result":   bool,                         -- alias of decision.allowed
--     "decision": { "allowed": bool,
--                   "reason":  <typed reason> }, -- the minimal cause
--     "summary":  text,                          -- human-readable tree
--     "trace":    [ { step, depth, rule_type, reason, subject, relation,
--                     object, result, detail, duration_ms }, ... ] }

-- 9a. Human-readable summary — the resolution tree from section 8, automatically.
SELECT authz.explain_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001')->>'summary';
-- => internal_user:alice → can_read → document:doc_payroll_001 = ALLOWED (ttu)
--      ✗ [no_direct_tuple] viewer on document:doc_payroll_001 — no tuple
--    ✗ [computed] can_read on document:doc_payroll_001 — can_read ← viewer
--      ... (the failed paths) ...
--        ✓ [direct_tuple] member on team:payroll_team — tuple found
--      ✓ [userset] payroll_clerk on assignment:eng_42_payroll — expand team:payroll_team#member
--      ✓ [ttu] can_read on document:doc_payroll_001 — can_read ← can_view ... (via in_internal_space)

-- 9b. Structured decision — machine-readable "why".
SELECT authz.explain_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001')->'decision';
-- => {"allowed": true, "reason": "ttu"}   (the grant came through a tuple-to-userset chain)

-- 9c. Winning path only — pass p_successful_only to drop the failed branches.
SELECT authz.explain_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001',
    p_successful_only => true)->>'summary';
-- => only the ✓ steps that make up the decisive path.

-- 9c'. Nested 'tree' — the same steps as a renderable tree (a root node
-- with the decision, the recursion nested in 'children'). Combine with
-- p_successful_only for just the winning path.
SELECT jsonb_pretty(authz.explain_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001',
    p_successful_only => true)->'tree');
-- => can_read (ttu) → can_view (ttu) → can_view (computed)
--      → payroll_clerk (userset) → member (direct_tuple)

-- 9c''. Rule references — every step carries the model_rule_id, group_id,
-- group_op, and negated flag, so a decision ties back to the exact model
-- row. Join model_rule_id to authz.models_view to see which rule each
-- step used:
SELECT (s->>'step')::int          AS step,
       s->>'reason'               AS reason,
       s->>'relation'             AS relation,
       (s->>'model_rule_id')::int AS rule_id,
       mv.rule_type,
       mv.group_op
  FROM jsonb_array_elements(authz.explain_access('demo',
           'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001',
           p_successful_only => true)->'trace') AS t(s)
  LEFT JOIN authz.models_view mv ON mv.id = (s->>'model_rule_id')::int
 ORDER BY 1;
-- => each ✓ step resolved to its exact model rule. group_op is 'or' here
--    (the demo model uses unions); on a model with rule groups it shows
--    'intersection' / 'exclusion', and negated = true on subtracted rules.

-- 9d. A DENY explains itself too.
SELECT authz.explain_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_tax_001')->'decision';
-- => {"allowed": false, "reason": "no_matching_rule"}  (Alice is on payroll, not tax)

-- 9e. Conditions: when a time/ABAC condition blocks access, the reason says so.
-- Give Alice a 2-hour conditional grant, then explain a check with no context.
SELECT authz.write_tuple('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_explain_001',
    p_condition => 'non_expired_grant',
    p_condition_context => '{"grant_time": "2026-03-11T09:00:00Z", "grant_duration": "2 hours"}'::jsonb
);

SELECT authz.explain_access('demo',
    'internal_user', 'alice', 'viewer', 'document', 'doc_explain_001')->'decision';
-- => {"allowed": false, "reason": "condition_denied"}  (no current_time supplied)

-- The condition_denied step says WHICH condition denied and which required
-- context keys were missing — pinpointing the cause of an ABAC denial:
SELECT s->>'condition_name'         AS condition,
       s->'condition_missing_keys'  AS missing_keys
  FROM jsonb_array_elements(authz.explain_access('demo',
           'internal_user', 'alice', 'viewer', 'document', 'doc_explain_001')->'trace') AS t(s)
 WHERE s->>'condition_name' IS NOT NULL;
-- => non_expired_grant | ["request.current_time"]
--    (the stored keys grant_time/grant_duration were present on the tuple,
--     so they are not listed; an empty list would mean the condition simply
--     evaluated to false on the given inputs, e.g. the grant had expired.)

-- Other decision.reason values you may see: direct_tuple, wildcard_tuple,
-- object_wildcard_tuple, contextual_tuple, computed, userset,
-- intersection_satisfied / intersection_unsatisfied, excluded.

-- doc_explain_001's conditional grant is left in place so the queries above
-- stay re-runnable on their own; re-running this section is idempotent
-- (write_tuple upserts the same tuple).

-- 9f. Redacted "safety mode" — surface the explanation to an untrusted UI
-- without leaking tuple/group identifiers. Subject/object ids and free-text
-- detail are stripped; types, relations, reasons, and the decision remain.
SELECT authz.explain_access('demo',
    'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001',
    p_redact => true);
-- => subjects become "internal_user:***", objects "document:***", detail null,
--    but "decision" and each step's typed "reason" are preserved.
