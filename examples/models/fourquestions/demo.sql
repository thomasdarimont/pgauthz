-- ============================================================================
-- Four questions — Interactive Demo
-- ============================================================================
--
-- Prerequisites: run model.sql and seed.sql first. Each block prints what the
-- sentence promised; the comments show the expected result.

-- 1. WHO ARE YOU / HOW ARE YOU RELATED — the team, and Bob
SELECT authz.check_access('fourq', 'user', 'alice', 'can_edit', 'doc', 'brief')  AS "alice (marketing) edits brief";   -- true
SELECT authz.check_access('fourq', 'user', 'bob',   'can_read', 'doc', 'brief')  AS "bob (blocked) reads brief";       -- false
SELECT authz.explain_access('fourq', 'user', 'bob', 'can_read', 'doc', 'brief')->>'summary';
--   user:bob → can_read → doc:brief = DENIED (excluded)
--     ✓ [userset] editor on folder:campaign — expand team:marketing#member
--     ✓ [direct_tuple] blocked on folder:campaign — tuple found
--   ✗ [exclusion_failed] can_read on folder:campaign — base not matched or excluded

-- Who can read the brief? Every team member except Bob — one query.
SELECT * FROM authz.list_subjects('fourq', 'user', 'can_read', 'doc', 'brief');   -- alice, dave

-- 2. WHAT HAS ALREADY HAPPENED — the NDA (a gate on doc#review)
SELECT authz.check_access('fourq', 'user', 'carol', 'review', 'doc', 'brief')    AS "carol (NDA accepted) reviews";   -- true
SELECT authz.check_access('fourq', 'user', 'erin',  'review', 'doc', 'brief')    AS "erin (no NDA yet) reviews";      -- false
SELECT e->>'gate' AS gate, e->>'reason' AS reason
  FROM jsonb_array_elements(authz.explain_access('fourq', 'user', 'erin', 'review', 'doc', 'brief')->'trace') e
 WHERE e->>'rule_type' = 'temporal_gate';
--   nda_first | gate_denied
-- The review portal records erin's acceptance …
SELECT authz.record_event('fourq', 'user', 'erin', 'accept_nda', p_kind => 'response', p_recorded_by => 'svc:review-portal');
SELECT authz.check_access('fourq', 'user', 'erin',  'review', 'doc', 'brief')    AS "erin reviews after accepting";   -- true
-- … and the gate never applied to the team (it hangs on `review`, the question the portal asks):
SELECT authz.check_access('fourq', 'user', 'alice', 'can_read', 'doc', 'brief')  AS "alice unaffected by the NDA gate"; -- true

-- 3. WHAT IS TRUE RIGHT NOW — "until next Friday" is expiry on the reviewer's tuple
SELECT ut.name AS user_type, t.user_id, r.name AS relation, t.expires_at
  FROM authz.tuples t
  JOIN authz.types ut     ON ut.id = t.user_type
  JOIN authz.relations r  ON r.id  = t.relation
 WHERE t.store_id = authz._s('fourq') AND r.name = 'reviewer';
--   user | carol | reviewer | <load time + 7 days>
--   user | erin  | reviewer | <load time + 7 days>
-- Once expires_at has passed the same check answers false; the tuple is
-- garbage-collected with its audit history intact (audit_check_access still
-- answers for the day before).

-- 4. WHAT HAS ALREADY HAPPENED — three downloads a day
SELECT authz.record_event('fourq', 'user', 'alice', 'download', 'doc', 'brief', 'response') FROM generate_series(1, 3);
SELECT authz.check_access('fourq', 'user', 'alice', 'download', 'doc', 'budget') AS "alice's 4th download today";    -- false
SELECT authz.check_access('fourq', 'user', 'dave',  'download', 'doc', 'budget') AS "dave's 1st download";           -- true
SELECT * FROM authz.list_objects('fourq', 'user', 'alice', 'download', 'doc');   -- empty: a capped subject sees nothing

-- 5. WHAT HAS ALREADY HAPPENED — two distinct approvers, and not yourself
SELECT authz.check_access('fourq', 'user', 'dave', 'execute', 'payment', 'p2')       AS "dave executes p2 (500)";      -- true
-- The PEP passes the caller's id in the request context (`self`); the gate uses
-- it to make sure none of the approvals are the executor's own.
SELECT authz.check_access_with_context('fourq', 'user', 'dave', 'execute_large', 'payment', 'p1', '{"self": "dave"}') AS "dave executes p1 (12k)";      -- false
-- The payments service records each approval on the requester's behalf, naming the approver:
SELECT authz.record_event('fourq', 'user', 'dave', 'approval_received', 'payment', 'p1', 'response',
    '{"input": {"approver": "carol", "amount": 12000}}', p_recorded_by => 'svc:payments');
SELECT authz.record_event('fourq', 'user', 'dave', 'approval_received', 'payment', 'p1', 'response',
    '{"input": {"approver": "grace", "amount": 12000}}', p_recorded_by => 'svc:payments');
SELECT authz.check_access_with_context('fourq', 'user', 'dave', 'execute_large', 'payment', 'p1', '{"self": "dave"}') AS "after two distinct approvals"; -- true
-- Separation of duties: had dave approved his own payment, the second clause
-- would veto — it reads the same approval events and matches the approver
-- against `$request.self`. Without `self` in the context the gate fails closed.
SELECT authz.check_access('fourq', 'user', 'dave', 'execute_large', 'payment', 'p1') AS "no self in context → denied";  -- false (gate_missing_context)
-- The strict tier: reserve the execution under the per-subject lock, then act.
SELECT authz.reserve_event('fourq', 'user', 'dave', 'execute_large', 'payment', 'p1',
    p_payload => '{"input": {"amount": 12000}}', p_request_context => '{"self": "dave"}');
--   {"allowed": true, "kind": "request", "reason": "allowed", "gates": [ … four_eyes … ]}

-- 6. THE MODEL READS BACK AS THE SENTENCE
SELECT authz.describe_model('fourq');
