-- Authorization checks for the agents model: appendix C's three demos
-- (reactive loop, constraint-aware planning, delegation as data) plus the
-- chapter-18 sidebars (sequencing, control plane, partner reputation).
-- Uses the shared test helpers (tests/sql/tests_helpers.sql); run via
-- tests/test.sh after model.sql + seed.sql.

SELECT _test_reset();

-- ── C.3 Reactive authorization: every tool call is a check ──────────────
DO $$
DECLARE v_err text; v jsonb;
BEGIN
    -- the task is about CustCo: its docs are reachable, Globex's are not — even
    -- though the agent is an agent_reader of Globex (18.3.2 "within the scope of
    -- the current customer")
    PERFORM _test_assert('ag_reactive_read_in_task',
        authz.check_access('agents', 'agent', 'acme_assist', 'documents_read', 'customer_doc', 'custco-briefing')::text, 'true');
    PERFORM _test_assert('ag_reactive_search_in_task',
        authz.check_access('agents', 'agent', 'acme_assist', 'documents_search', 'customer_doc', 'custco-contract')::text, 'true');
    PERFORM _test_assert('ag_reactive_other_customer_denied',
        authz.check_access('agents', 'agent', 'acme_assist', 'documents_read', 'customer_doc', 'globex-plan')::text, 'false');
    -- the denial names the boundary (feedback for the planner)
    v := authz.check_access_detailed('agents', 'agent', 'acme_assist', 'documents_read', 'customer_doc', 'globex-plan');
    PERFORM _test_assert('ag_reactive_denial_reason', v ->> 'reason', 'intersection_unsatisfied');
    -- humans reach docs through the account, no task scope needed
    PERFORM _test_assert('ag_reactive_human_via_account',
        authz.check_access('agents', 'user', 'alice', 'documents_read', 'customer_doc', 'custco-briefing')::text, 'true');
    PERFORM _test_assert('ag_reactive_human_other_account_denied',
        authz.check_access('agents', 'user', 'alice', 'documents_read', 'customer_doc', 'globex-plan')::text, 'false');

    -- one-shot task scope as a CONTEXTUAL tuple: the PEP asserts "this request
    -- is about Globex" without storing anything
    PERFORM _test_assert('ag_reactive_contextual_task_scope',
        authz.check_access_with_contextual_tuples_jsonb('agents', 'agent', 'acme_assist', 'documents_read', 'customer_doc', 'globex-plan',
            NULL, '[{"user_type": "agent", "user_id": "acme_assist", "relation": "task_scope", "object_type": "customer", "object_id": "Globex"}]')::text, 'true');

    -- task ends: scope deleted → nothing readable
    PERFORM authz.delete_tuple('agents', 'agent', 'acme_assist', 'task_scope', 'customer', 'CustCo');
    PERFORM _test_assert('ag_reactive_task_over',
        authz.check_access('agents', 'agent', 'acme_assist', 'documents_read', 'customer_doc', 'custco-briefing')::text, 'false');
    PERFORM authz.write_tuple('agents', 'agent', 'acme_assist', 'task_scope', 'customer', 'CustCo', p_expires_at => now() + interval '8 hours');

    -- 18.5 control plane: run yes; create/update/delete have no agent path ...
    PERFORM _test_assert('ag_control_run_allowed',
        authz.check_access('agents', 'agent', 'acme_assist', 'run', 'automation', 'nightly-report')::text, 'true');
    PERFORM _test_assert('ag_control_create_denied',
        authz.check_access('agents', 'agent', 'acme_assist', 'create', 'automation', 'nightly-report')::text, 'false');
    -- ... and a grant cannot even be written (type restriction)
    v_err := NULL;
    BEGIN
        PERFORM authz.write_tuple('agents', 'agent', 'acme_assist', 'delete', 'automation', 'nightly-report');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ag_control_grant_rejected', v_err IS NOT NULL, coalesce(v_err, 'tuple was written'));
END;
$$;

-- ── C.4 Constraint-aware planning: the residual is a set ────────────────
DO $$
DECLARE v_planned text; v_checked text; v_objs text; v_rel text;
BEGIN
    -- "which actions may I perform on this resource?" (the book's permitted_actions)
    SELECT string_agg(action, ',' ORDER BY action) INTO v_planned
      FROM authz.list_actions('agents', 'agent', 'acme_assist', 'customer_doc', 'custco-briefing');
    PERFORM _test_assert('ag_plan_permitted_actions', v_planned, 'documents_read,documents_search,documents_summarize');
    -- guidance ≡ enforcement (18.4.2): the planned set equals the checks that pass
    v_checked := NULL;
    FOR v_rel IN SELECT r.name FROM authz.relations r WHERE r.store_id = authz._s('agents') ORDER BY r.name LOOP
        IF authz.check_access('agents', 'agent', 'acme_assist', v_rel, 'customer_doc', 'custco-briefing') THEN
            v_checked := concat_ws(',', v_checked, v_rel);
        END IF;
    END LOOP;
    PERFORM _test_assert('ag_plan_equals_checks', v_checked, v_planned);
    -- "for a given action, which resources can I access?"
    SELECT string_agg(object_id, ',' ORDER BY object_id) INTO v_objs
      FROM authz.list_objects('agents', 'agent', 'acme_assist', 'documents_read', 'customer_doc');
    PERFORM _test_assert('ag_plan_reachable_docs', v_objs, 'custco-briefing,custco-contract');
    -- nothing to plan on the control plane
    SELECT string_agg(action, ',' ORDER BY action) INTO v_planned
      FROM authz.list_actions('agents', 'agent', 'acme_assist', 'automation', 'nightly-report');
    PERFORM _test_assert('ag_plan_automation_actions', v_planned, 'run');
END;
$$;

-- ── 18.4 sidebar: sequencing with a gate ────────────────────────────────
DO $$
DECLARE v jsonb;
BEGIN
    -- no summary yet → send_email vetoed by the gate, not by the graph
    v := authz.check_access_detailed('agents', 'agent', 'acme_assist', 'send_email', 'mailbox', 'alice');
    PERFORM _test_assert('ag_seq_email_before_summary_denied', v ->> 'decision', 'false');
    PERFORM _test_assert('ag_seq_email_reason_is_gate', v ->> 'reason', 'gate_denied');
    -- the planner's view agrees: send_email is not among the permitted actions
    PERFORM _test_assert('ag_seq_planner_hides_email',
        coalesce((SELECT string_agg(action, ',') FROM authz.list_actions('agents', 'agent', 'acme_assist', 'mailbox', 'alice')), ''), '');
    -- the PEP records the summarize RESPONSE after the tool ran ...
    PERFORM authz.record_event('agents', 'agent', 'acme_assist', 'documents_summarize', 'customer_doc', 'custco-briefing', 'response');
    -- ... and email is now permitted, for the next hour
    PERFORM _test_assert('ag_seq_email_after_summary_allowed',
        authz.check_access('agents', 'agent', 'acme_assist', 'send_email', 'mailbox', 'alice')::text, 'true');
    PERFORM _test_assert('ag_seq_planner_shows_email',
        (SELECT string_agg(action, ',') FROM authz.list_actions('agents', 'agent', 'acme_assist', 'mailbox', 'alice')), 'send_email');
    -- the human owner is not sequenced (owner path, gate passes trivially? no: gates apply
    -- to the relation — the owner has no summary either, so she is vetoed too. Gates
    -- are per relation, not per principal type; put humans on their own relation if
    -- they must be exempt.)
    PERFORM _test_assert('ag_seq_gate_is_per_relation',
        authz.check_access('agents', 'user', 'alice', 'send_email', 'mailbox', 'alice')::text, 'false');
END;
$$;

-- ── C.5 Delegation as data ──────────────────────────────────────────────
DO $$
DECLARE v_err text; v jsonb;
BEGIN
    -- the subagent works within the delegated scope ...
    PERFORM _test_assert('ag_deleg_subagent_reads_scope',
        authz.check_access('agents', 'agent', 'research_agent', 'documents_read', 'customer_doc', 'custco-briefing')::text, 'true');
    -- ... and not beyond it (Globex was never delegated, though the delegator holds it)
    PERFORM _test_assert('ag_deleg_subagent_outside_scope_denied',
        authz.check_access('agents', 'agent', 'research_agent', 'documents_read', 'customer_doc', 'globex-plan')::text, 'false');
    -- the delegation link carries its expiry
    PERFORM _test_assert_true('ag_deleg_expires',
        (SELECT t.expires_at IS NOT NULL FROM authz.tuples t
          WHERE t.store_id = authz._s('agents') AND t.user_id = 'research_agent'
            AND t.relation = authz._r('agents', 'delegate') AND t.object_id = 'acme_assist'));

    -- EVALUATION-TIME attenuation: the delegate reads through the delegator's
    -- reach, so when the delegator loses CustCo, the delegate loses it in the
    -- same instant — its own task_scope tuple notwithstanding.
    PERFORM authz.delete_tuple('agents', 'agent', 'acme_assist', 'agent_reader', 'customer', 'CustCo', p_user_relation => 'reach');
    PERFORM _test_assert('ag_deleg_revoking_delegator_revokes_delegate',
        authz.check_access('agents', 'agent', 'research_agent', 'documents_read', 'customer_doc', 'custco-briefing')::text, 'false');
    PERFORM authz.write_tuple('agents', 'agent', 'acme_assist', 'agent_reader', 'customer', 'CustCo', p_user_relation => 'reach');
    PERFORM _test_assert('ag_deleg_restored',
        authz.check_access('agents', 'agent', 'research_agent', 'documents_read', 'customer_doc', 'custco-briefing')::text, 'true');
    -- the narrowing is the delegate's own task_scope: widen it and the delegate
    -- reaches Globex — but only because the delegator holds Globex too
    PERFORM authz.write_tuple('agents', 'agent', 'research_agent', 'task_scope', 'customer', 'Globex');
    PERFORM _test_assert('ag_deleg_scope_bounded_by_delegator',
        authz.check_access('agents', 'agent', 'research_agent', 'documents_read', 'customer_doc', 'globex-plan')::text, 'true');
    PERFORM authz.write_tuple('agents', 'agent', 'research_agent', 'task_scope', 'customer', 'Initech');
    PERFORM authz.write_tuple('agents', 'customer', 'Initech', 'customer', 'customer_doc', 'initech-memo');
    PERFORM _test_assert('ag_deleg_cannot_exceed_delegator',
        authz.check_access('agents', 'agent', 'research_agent', 'documents_read', 'customer_doc', 'initech-memo')::text, 'false');
    PERFORM authz.delete_tuple('agents', 'agent', 'research_agent', 'task_scope', 'customer', 'Globex');
    PERFORM authz.delete_tuple('agents', 'agent', 'research_agent', 'task_scope', 'customer', 'Initech');

    -- a direct grant to an agent (bypassing the reach convention) cannot be written
    v_err := NULL;
    BEGIN
        PERFORM authz.write_tuple('agents', 'agent', 'research_agent', 'agent_reader', 'customer', 'CustCo');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ag_deleg_direct_grant_rejected', v_err IS NOT NULL, coalesce(v_err, 'tuple was written'));

    -- chains: a sub-subagent delegated by research_agent sits in acme_assist's
    -- reach transitively; cutting the middle link cuts the subtree
    PERFORM authz.write_tuple('agents', 'agent', 'summarizer', 'reach', 'agent', 'summarizer');
    PERFORM authz.write_tuple('agents', 'agent', 'summarizer', 'delegate', 'agent', 'research_agent');
    PERFORM authz.write_tuple('agents', 'agent', 'summarizer', 'task_scope', 'customer', 'CustCo');
    PERFORM _test_assert('ag_deleg_chain_reads',
        authz.check_access('agents', 'agent', 'summarizer', 'documents_read', 'customer_doc', 'custco-briefing')::text, 'true');
    PERFORM authz.delete_tuple('agents', 'agent', 'research_agent', 'delegate', 'agent', 'acme_assist');
    PERFORM _test_assert('ag_deleg_chain_cut_at_middle',
        authz.check_access('agents', 'agent', 'summarizer', 'documents_read', 'customer_doc', 'custco-briefing')::text, 'false');
    PERFORM _test_assert('ag_deleg_middle_cut_too',
        authz.check_access('agents', 'agent', 'research_agent', 'documents_read', 'customer_doc', 'custco-briefing')::text, 'false');
    PERFORM authz.write_tuple('agents', 'agent', 'research_agent', 'delegate', 'agent', 'acme_assist', p_expires_at => now() + interval '1 second');

    -- an expired delegation link grants nothing (observed from the next statement)
END;
$$;
-- Live expiry is judged per STATEMENT (statement_timestamp), so the expiry
-- must be observed from a new statement — as every HTTP request is.
SELECT pg_sleep(1.2);
DO $$
DECLARE v_err text;
BEGIN
    PERFORM _test_assert('ag_deleg_expired_link_grants_nothing',
        authz.check_access('agents', 'agent', 'research_agent', 'documents_read', 'customer_doc', 'custco-briefing')::text, 'false');
    -- issuance-time check on top: delegating a scope the delegator's reach does
    -- not hold is refused atomically (18.6.5) — early, instead of a useless grant
    v_err := NULL;
    BEGIN
        PERFORM authz.write_tuples_checked('agents',
            p_preconditions => '[{"match": "exists", "user_type": "agent", "user_id": "acme_assist", "user_relation": "reach",
                                  "relation": "agent_reader", "object_type": "customer", "object_id": "Initech"}]',
            p_writes => '[{"user_type": "agent", "user_id": "research_agent", "relation": "task_scope",
                           "object_type": "customer", "object_id": "Initech"}]');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ag_deleg_cannot_delegate_unheld', v_err LIKE '%precondition failed%', coalesce(v_err, 'delegation was written'));
    PERFORM _test_assert('ag_deleg_unheld_not_written',
        authz.check_access('agents', 'agent', 'research_agent', 'task_scope', 'customer', 'Initech')::text, 'false');
END;
$$;

-- ── 18.7 Partner reputation over recorded outcomes ──────────────────────
DO $$
DECLARE v jsonb; v_err text;
BEGIN
    PERFORM _test_assert('ag_rep_delegation_allowed_initially',
        authz.check_access('agents', 'agent', 'acme_assist', 'delegate_pay', 'partner_agent', 'payco')::text, 'true');
    -- the recorder must send the declared outcome shape (payload schema)
    v_err := NULL;
    BEGIN
        PERFORM authz.record_event('agents', 'agent', 'acme_assist', 'pay', 'partner_agent', 'payco', 'response', '{"output": {}}');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ag_rep_outcome_shape_enforced', v_err LIKE '%output.promise_kept%', coalesce(v_err, 'accepted'));
    -- two broken promises: still within the cap
    PERFORM authz.record_event('agents', 'agent', 'acme_assist', 'pay', 'partner_agent', 'payco', 'response', '{"output": {"promise_kept": false}}') FROM generate_series(1, 2);
    PERFORM authz.record_event('agents', 'agent', 'acme_assist', 'pay', 'partner_agent', 'payco', 'response', '{"output": {"promise_kept": true}}');
    PERFORM _test_assert('ag_rep_two_broken_still_ok',
        authz.check_access('agents', 'agent', 'acme_assist', 'delegate_pay', 'partner_agent', 'payco')::text, 'true');
    -- the third one flips the gate
    PERFORM authz.record_event('agents', 'agent', 'acme_assist', 'pay', 'partner_agent', 'payco', 'response', '{"output": {"promise_kept": false}}');
    v := authz.check_access_detailed('agents', 'agent', 'acme_assist', 'delegate_pay', 'partner_agent', 'payco');
    PERFORM _test_assert('ag_rep_third_broken_denied', v ->> 'decision', 'false');
    PERFORM _test_assert('ag_rep_denied_by_gate', v ->> 'reason', 'gate_denied');
    -- explain names the gate and the observed count
    v := authz.explain_access('agents', 'agent', 'acme_assist', 'delegate_pay', 'partner_agent', 'payco');
    PERFORM _test_assert_true('ag_rep_explain_shows_gate',
        (SELECT count(*) FROM jsonb_array_elements(v -> 'tree' -> 'children') c
          WHERE c ->> 'gate' = 'broken_promises' AND (c ->> 'observed')::int = 3 AND (c ->> 'result')::boolean = false) = 1,
        v::text);
END;
$$;

SELECT _test_report('agents model checks');
