-- ============================================================================
-- Agents — Interactive Demo (Authorization in Action ch. 18 / appendix C)
-- ============================================================================
-- Prerequisites: run model.sql and seed.sql first.

-- 1. THE MODEL
SELECT authz.describe_model('agents');

-- ============================================================================
-- 2. C.3 REACTIVE — every tool call is a check; denial is feedback
-- ============================================================================
-- acme_assist's task is about CustCo: CustCo docs yes, Globex no (even though
-- the agent is allowed on Globex in general).
SELECT d AS doc,
       authz.check_access('agents', 'agent', 'acme_assist', 'documents_read', 'customer_doc', d) AS "documents.read"
FROM unnest(ARRAY['custco-briefing', 'custco-contract', 'globex-plan']) AS d;

-- Why not Globex? The planner gets a reason, not just "no".
SELECT authz.explain_access('agents', 'agent', 'acme_assist', 'documents_read', 'customer_doc', 'globex-plan') ->> 'summary';

-- The control plane has no agent path at all (18.5): run yes, create no.
SELECT a AS action,
       authz.check_access('agents', 'agent', 'acme_assist', a, 'automation', 'nightly-report') AS "acme_assist"
FROM unnest(ARRAY['run', 'create', 'update', 'delete']) AS a;

-- ============================================================================
-- 3. C.4 CONSTRAINT-AWARE PLANNING — ask before acting
-- ============================================================================
-- "Given my identity and the current task, which actions may I perform here?"
-- (the book's permitted_actions residual, as a concrete set)
SELECT action AS permitted_action
  FROM authz.list_actions('agents', 'agent', 'acme_assist', 'customer_doc', 'custco-briefing');

-- "For documents.read, which documents can I reach?"
SELECT object_id AS reachable_doc
  FROM authz.list_objects('agents', 'agent', 'acme_assist', 'documents_read', 'customer_doc');

-- ============================================================================
-- 4. SEQUENCING — email only after a summary (a gate over the action log)
-- ============================================================================
SELECT authz.check_access('agents', 'agent', 'acme_assist', 'send_email', 'mailbox', 'alice') AS "send before summarizing";
-- the PEP records that documents.summarize ran (kind: response)
SELECT authz.record_event('agents', 'agent', 'acme_assist', 'documents_summarize', 'customer_doc', 'custco-briefing', 'response') AS recorded_seq;
SELECT authz.check_access('agents', 'agent', 'acme_assist', 'send_email', 'mailbox', 'alice') AS "send after summarizing";

-- ============================================================================
-- 5. C.5 DELEGATION AS DATA — scoped, expiring, attenuated at evaluation time
-- ============================================================================
-- research_agent was delegated "read CustCo docs for 4 hours" by acme_assist:
-- a `delegate` link into acme_assist's reach + its own task_scope (CustCo only)
SELECT d AS doc,
       authz.check_access('agents', 'agent', 'research_agent', 'documents_read', 'customer_doc', d) AS "research_agent"
FROM unnest(ARRAY['custco-briefing', 'globex-plan']) AS d;
-- the record, as tuples (with their expiry)
SELECT r.name AS relation, t.object_type_name AS object_type, t.object_id, t.expires_at
  FROM (SELECT t.*, ot.name AS object_type_name FROM authz.tuples t JOIN authz.types ot ON ot.id = t.object_type) t
  JOIN authz.relations r ON r.id = t.relation
 WHERE t.store_id = authz._s('agents') AND t.user_id = 'research_agent' AND r.name IN ('delegate', 'task_scope');
-- the delegate reads THROUGH the delegator's reach: revoke acme_assist's CustCo
-- grant and research_agent loses it in the same instant (its task_scope is still there)
SELECT authz.delete_tuple('agents', 'agent', 'acme_assist', 'agent_reader', 'customer', 'CustCo', p_user_relation => 'reach');
SELECT authz.check_access('agents', 'agent', 'research_agent', 'documents_read', 'customer_doc', 'custco-briefing') AS "delegate after delegator lost CustCo";
SELECT authz.write_tuple('agents', 'agent', 'acme_assist', 'agent_reader', 'customer', 'CustCo', p_user_relation => 'reach');
-- delegating what the delegator does not hold is refused up front (nothing written):
DO $$
BEGIN
    PERFORM authz.write_tuples_checked('agents',
        p_preconditions => '[{"match": "exists", "user_type": "agent", "user_id": "acme_assist", "user_relation": "reach",
                              "relation": "agent_reader", "object_type": "customer", "object_id": "Initech"}]',
        p_writes => '[{"user_type": "agent", "user_id": "research_agent", "relation": "task_scope",
                       "object_type": "customer", "object_id": "Initech"}]');
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'delegation refused: %', SQLERRM;
END $$;

-- ============================================================================
-- 6. 18.7 PARTNER REPUTATION — outcomes recorded, delegation gated
-- ============================================================================
SELECT authz.check_access('agents', 'agent', 'acme_assist', 'delegate_pay', 'partner_agent', 'payco') AS "may delegate to payco";
-- three broken promises in the window ...
SELECT authz.record_event('agents', 'agent', 'acme_assist', 'pay', 'partner_agent', 'payco', 'response',
    '{"output": {"promise_kept": false}}') FROM generate_series(1, 3);
-- ... and the gate says no, with the count
SELECT authz.explain_access('agents', 'agent', 'acme_assist', 'delegate_pay', 'partner_agent', 'payco') ->> 'summary';
