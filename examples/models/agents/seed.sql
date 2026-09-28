-- ============================================================================
-- Agents — Seed Data (the ACME Assist scenario of chapter 18 / appendix C)
-- ============================================================================
--
--   alice           — ACME employee; operates agent:acme_assist; on CustCo's account team
--   agent:acme_assist — the primary agent; may work on CustCo AND Globex documents
--                       (agent_reader), but its CURRENT TASK is about CustCo
--                       (task_scope, expires with the task)
--   agent:research_agent — a subagent; acme_assist delegates "read CustCo docs
--                       for the next 4 hours" to it: a `delegate` link into
--                       acme_assist's reach + research_agent's own task_scope
--   customers        — CustCo (docs custco-briefing, custco-contract), Globex (globex-plan),
--                      Initech (nothing granted — used to show a refused delegation)
--   automation:nightly-report — agents may run it; only alice may create/update/delete
--   mailbox:alice    — acme_assist may send from it, gated on a prior summary
--   partner_agent:payco — the payment partner acme_assist may delegate payments to

DO $$
DECLARE v_out jsonb;
BEGIN
    -- Humans
    PERFORM authz.write_tuple('agents', 'user', 'alice', 'member', 'team', 'custco-account-team');
    PERFORM authz.write_tuple('agents', 'team', 'custco-account-team', 'member', 'customer', 'CustCo', p_user_relation => 'member');
    PERFORM authz.write_tuple('agents', 'user', 'alice', 'operator', 'agent', 'acme_assist');
    -- Every agent is in its own reach (written when the agent is registered).
    PERFORM authz.write_tuple('agents', 'agent', 'acme_assist', 'reach', 'agent', 'acme_assist');
    PERFORM authz.write_tuple('agents', 'agent', 'research_agent', 'reach', 'agent', 'research_agent');

    -- Documents belong to customers
    PERFORM authz.write_tuple('agents', 'customer', 'CustCo', 'customer', 'customer_doc', 'custco-briefing');
    PERFORM authz.write_tuple('agents', 'customer', 'CustCo', 'customer', 'customer_doc', 'custco-contract');
    PERFORM authz.write_tuple('agents', 'customer', 'Globex', 'customer', 'customer_doc', 'globex-plan');

    -- The primary agent may work on two customers' documents. Grants go to
    -- the agent's REACH (itself + delegates), never to the agent directly —
    -- so whatever it delegates later is revoked with this one tuple.
    PERFORM authz.write_tuple('agents', 'agent', 'acme_assist', 'agent_reader', 'customer', 'CustCo', p_user_relation => 'reach');
    PERFORM authz.write_tuple('agents', 'agent', 'acme_assist', 'agent_reader', 'customer', 'Globex', p_user_relation => 'reach');
    -- ... but the task it is running right now is about CustCo (18.3.2). The PEP
    -- writes this when the task starts, with the task's deadline; when the
    -- task ends it deletes it (or lets it expire).
    PERFORM authz.write_tuple('agents', 'agent', 'acme_assist', 'task_scope', 'customer', 'CustCo',
        p_expires_at => now() + interval '8 hours');

    -- Operational vs control plane (18.5)
    PERFORM authz.write_tuple('agents', 'agent', 'acme_assist', 'run', 'automation', 'nightly-report');
    PERFORM authz.write_tuple('agents', 'user', 'alice', 'create', 'automation', 'nightly-report');
    PERFORM authz.write_tuple('agents', 'user', 'alice', 'update', 'automation', 'nightly-report');
    PERFORM authz.write_tuple('agents', 'user', 'alice', 'delete', 'automation', 'nightly-report');

    -- Sequencing (18.4 sidebar): the agent may send from alice's mailbox — once it has summarized
    PERFORM authz.write_tuple('agents', 'user', 'alice', 'owner', 'mailbox', 'alice');
    PERFORM authz.write_tuple('agents', 'agent', 'acme_assist', 'send_email', 'mailbox', 'alice');

    -- Cross-domain delegation (18.7): acme_assist may delegate payments to PayCo
    PERFORM authz.write_tuple('agents', 'agent', 'acme_assist', 'delegate_pay', 'partner_agent', 'payco');
    PERFORM authz.write_tuple('agents', 'agent', 'acme_assist', 'pay', 'partner_agent', 'payco');

    -- Delegation as data (18.6). The record
    --   {delegator: acme_assist, delegate: research_agent,
    --    actions: [documents.search, documents.read, documents.summarize],
    --    resourceScope: CustCo, expires: +4h}
    -- becomes two expiring tuples: the `delegate` link (research_agent joins
    -- acme_assist's reach → it can use whatever acme_assist holds, for as
    -- long as acme_assist holds it) and research_agent's own task_scope
    -- (the explicit narrowing: CustCo only, not Globex). Written ATOMICALLY
    -- under the precondition that the delegator's reach holds the scope —
    -- refused early instead of silently useless (18.6.5).
    v_out := authz.write_tuples_checked('agents',
        p_preconditions => '[{"match": "exists", "user_type": "agent", "user_id": "acme_assist", "user_relation": "reach",
                              "relation": "agent_reader", "object_type": "customer", "object_id": "CustCo"}]',
        p_writes => jsonb_build_array(
            jsonb_build_object('user_type', 'agent', 'user_id', 'research_agent', 'relation', 'delegate',
                               'object_type', 'agent', 'object_id', 'acme_assist',
                               'expires_at', (now() + interval '4 hours')::text),
            jsonb_build_object('user_type', 'agent', 'user_id', 'research_agent', 'relation', 'task_scope',
                               'object_type', 'customer', 'object_id', 'CustCo',
                               'expires_at', (now() + interval '4 hours')::text)),
        p_performed_by => 'agent:acme_assist');
    IF (v_out ->> 'written')::int <> 2 THEN
        RAISE EXCEPTION 'delegation not written: %', v_out;
    END IF;
END;
$$;
