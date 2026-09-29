-- Four questions — assertions for every clause of the sentence. Uses the shared
-- test helpers (tests/sql/tests_helpers.sql); run via tests/test.sh after
-- model.sql + seed.sql.

SELECT _test_reset();

DO $$
DECLARE r jsonb; v_objs text; v_subj text;
BEGIN
    -- ── Who are you / how are you related: the team, and Bob ────────────────
    PERFORM _test_assert('fq_01_team_member_reads',  authz.check_access('fourq','user','alice','can_read','doc','brief')::text, 'true');
    PERFORM _test_assert('fq_02_team_member_edits',  authz.check_access('fourq','user','alice','can_edit','doc','budget')::text, 'true');
    PERFORM _test_assert('fq_03_bob_blocked_read',   authz.check_access('fourq','user','bob','can_read','doc','brief')::text, 'false');
    PERFORM _test_assert('fq_04_bob_blocked_edit',   authz.check_access('fourq','user','bob','can_edit','doc','brief')::text, 'false');
    PERFORM _test_assert('fq_05_bob_reason_excluded',
        authz.explain_access('fourq','user','bob','can_read','doc','brief')->'decision'->>'reason', 'excluded');
    PERFORM _test_assert('fq_06_stranger_denied',    authz.check_access('fourq','user','zed','can_read','doc','brief')::text, 'false');

    -- ── What has already happened: the NDA (gate on doc#review) ─────────────
    PERFORM _test_assert('fq_07_reviewer_with_nda_reviews', authz.check_access('fourq','user','carol','review','doc','brief')::text, 'true');
    PERFORM _test_assert('fq_08_reviewer_cannot_edit',      authz.check_access('fourq','user','carol','can_edit','doc','brief')::text, 'false');
    PERFORM _test_assert('fq_09_reviewer_without_nda_denied', authz.check_access('fourq','user','erin','review','doc','brief')::text, 'false');
    PERFORM _test_assert('fq_10_nda_reason_gate_denied',
        authz.explain_access('fourq','user','erin','review','doc','brief')->'decision'->>'reason', 'gate_denied');
    -- an NDA acceptance recorded by anyone but the portal does not count
    PERFORM authz.record_event('fourq', 'user', 'erin', 'accept_nda', p_kind => 'response', p_recorded_by => 'user:erin');
    PERFORM _test_assert('fq_11_nda_needs_trusted_recorder', authz.check_access('fourq','user','erin','review','doc','brief')::text, 'false');
    PERFORM authz.record_event('fourq', 'user', 'erin', 'accept_nda', p_kind => 'response', p_recorded_by => 'svc:review-portal');
    PERFORM _test_assert('fq_12_nda_accepted_unlocks',      authz.check_access('fourq','user','erin','review','doc','brief')::text, 'true');
    -- the gate never touches the team (it hangs on `review`, not on `can_read`)
    PERFORM _test_assert('fq_13_gate_not_on_team_path',     authz.check_access('fourq','user','alice','can_read','doc','brief')::text, 'true');
    -- enumeration agrees: who can review the brief?
    SELECT string_agg(subject_id, ',' ORDER BY subject_id) INTO v_subj
      FROM authz.list_subjects('fourq', 'user', 'review', 'doc', 'brief');
    PERFORM _test_assert('fq_14_list_subjects_review', v_subj, 'carol,erin');

    -- ── What is true right now: "until next Friday" is expiry on the tuple ────────
    -- (expiry is judged per STATEMENT, so the after-expiry check runs in a
    -- separate statement below, after a pg_sleep)
    PERFORM authz.record_event('fourq', 'user', 'frank', 'accept_nda', p_kind => 'response', p_recorded_by => 'svc:review-portal');
    PERFORM authz.write_tuple('fourq', 'user', 'frank', 'reviewer', 'folder', 'campaign',
        p_expires_at => clock_timestamp() + interval '0.6 seconds');
    PERFORM _test_assert('fq_15_reviewer_before_expiry', authz.check_access('fourq','user','frank','review','doc','brief')::text, 'true');

    -- ── What has already happened: three downloads a day ────────────────────
    PERFORM _test_assert('fq_17_download_allowed_initially', authz.check_access('fourq','user','alice','download','doc','brief')::text, 'true');
    PERFORM authz.record_event('fourq', 'user', 'alice', 'download', 'doc', 'brief', 'response') FROM generate_series(1, 3);
    PERFORM _test_assert('fq_18_fourth_download_denied',      authz.check_access('fourq','user','alice','download','doc','budget')::text, 'false');
    PERFORM _test_assert('fq_19_quota_is_per_principal',      authz.check_access('fourq','user','dave','download','doc','budget')::text, 'true');
    SELECT count(*)::text INTO v_objs FROM authz.list_objects('fourq', 'user', 'alice', 'download', 'doc');
    PERFORM _test_assert('fq_20_list_objects_empty_when_capped', v_objs, '0');
    -- reviewers download too, under the same quota
    PERFORM _test_assert('fq_21_reviewer_downloads',          authz.check_access('fourq','user','carol','download','doc','brief')::text, 'true');

    -- ── What has already happened: two distinct approvers, not yourself ─────
    PERFORM _test_assert('fq_22_small_payment_no_gate',       authz.check_access('fourq','user','dave','execute','payment','p2')::text, 'true');
    PERFORM _test_assert('fq_23_large_payment_unapproved',    authz.check_access_with_context('fourq','user','dave','execute_large','payment','p1','{"self":"dave"}')::text, 'false');
    PERFORM authz.record_event('fourq', 'user', 'dave', 'approval_received', 'payment', 'p1', 'response',
        '{"input": {"approver": "carol", "amount": 12000}}', p_recorded_by => 'svc:payments');
    PERFORM _test_assert('fq_24_one_approver_not_enough',     authz.check_access_with_context('fourq','user','dave','execute_large','payment','p1','{"self":"dave"}')::text, 'false');
    PERFORM authz.record_event('fourq', 'user', 'dave', 'approval_received', 'payment', 'p1', 'response',
        '{"input": {"approver": "carol", "amount": 12000}}', p_recorded_by => 'svc:payments');
    PERFORM _test_assert('fq_25_same_approver_twice_not_enough', authz.check_access_with_context('fourq','user','dave','execute_large','payment','p1','{"self":"dave"}')::text, 'false');
    PERFORM authz.record_event('fourq', 'user', 'dave', 'approval_received', 'payment', 'p1', 'response',
        '{"input": {"approver": "grace", "amount": 12000}}', p_recorded_by => 'svc:payments');
    PERFORM _test_assert('fq_26_two_distinct_approvers_allow', authz.check_access_with_context('fourq','user','dave','execute_large','payment','p1','{"self":"dave"}')::text, 'true');
    PERFORM _test_assert('fq_27_approvals_are_per_payment',    authz.check_access_with_context('fourq','user','dave','execute_large','payment','p2','{"self":"dave"}')::text, 'false');
    -- the caller's id is required: without it the gate fails CLOSED, never open
    PERFORM _test_assert('fq_27b_missing_self_fails_closed',   authz.check_access('fourq','user','dave','execute_large','payment','p1')::text, 'false');
    PERFORM _test_assert('fq_27c_missing_self_reason',
        (SELECT e->>'reason' FROM jsonb_array_elements(jsonb_path_query_array(
                authz.explain_access('fourq','user','dave','execute_large','payment','p1'),
                '$.trace[*] ? (@.gate == "four_eyes" && @.clause == "1:count_within")')) e),
        'gate_missing_context');
    -- the strict tier: reserve records the request under the per-subject lock
    r := authz.reserve_event('fourq', 'user', 'dave', 'execute_large', 'payment', 'p1',
             p_payload => '{"input": {"amount": 12000}}', p_request_context => '{"self": "dave"}');
    PERFORM _test_assert('fq_28_reserve_allowed', (r->>'allowed') || ' ' || (r->>'kind') || ' ' || (r->>'reason'), 'true request allowed');
    -- separation of duties: if one of the approvals names the executor, it vetoes —
    -- read from the same events clause 1 counts, so a recorder cannot satisfy
    -- one clause without the other seeing it
    PERFORM authz.record_event('fourq', 'user', 'dave', 'approval_received', 'payment', 'p1', 'response',
        '{"input": {"approver": "dave", "amount": 12000}}', p_recorded_by => 'svc:payments');
    PERFORM _test_assert('fq_29_own_approval_vetoes',          authz.check_access_with_context('fourq','user','dave','execute_large','payment','p1','{"self":"dave"}')::text, 'false');
    PERFORM _test_assert('fq_30_sod_clause_named',
        (SELECT string_agg((e->>'clause') || ':' || (e->>'reason'), ' ' ORDER BY e->>'clause')
           FROM jsonb_array_elements(jsonb_path_query_array(
                authz.explain_access('fourq','user','dave','execute_large','payment','p1','{"self":"dave"}'),
                '$.trace[*] ? (@.gate == "four_eyes")')) e),
        '0:count_distinct_within:gate_passed 1:count_within:gate_denied');
    -- approvals are recorded FOR the requester: another requester of the same
    -- payment has no approval record of their own and is denied by clause 1
    PERFORM authz.write_tuple('fourq', 'user', 'hank', 'requester', 'payment', 'p1');
    PERFORM _test_assert('fq_30b_approvals_belong_to_requester', authz.check_access_with_context('fourq','user','hank','execute_large','payment','p1','{"self":"hank"}')::text, 'false');
    -- the payload schema makes the approver field mandatory
    BEGIN
        PERFORM authz.record_event('fourq', 'user', 'dave', 'approval_received', 'payment', 'p2', 'response',
            '{"input": {"amount": 500}}', p_recorded_by => 'svc:payments');
        PERFORM _test_assert('fq_31_schema_rejects_missing_approver', 'no error', 'error');
    EXCEPTION WHEN OTHERS THEN
        PERFORM _test_assert_true('fq_31_schema_rejects_missing_approver', SQLERRM LIKE '%input.approver%', SQLERRM);
    END;

    -- ── The model reads back as the sentence ────────────────────────────────
    PERFORM _test_assert_true('fq_32_describe_editor_facets',
        position('define editor: [team#member, user]' in authz.describe_model('fourq')) > 0, authz.describe_model('fourq'));
    PERFORM _test_assert_true('fq_33_describe_gates',
        position('# gate four_eyes' in authz.describe_model('fourq')) > 0
        AND position('# gate nda_first' in authz.describe_model('fourq')) > 0
        AND position('# gate three_a_day' in authz.describe_model('fourq')) > 0, authz.describe_model('fourq'));
END;
$$;

-- "until next Friday": the reviewer tuple written above expires; a new statement sees it gone
SELECT pg_sleep(0.8);
DO $$
BEGIN
    PERFORM _test_assert('fq_16_reviewer_after_expiry',
        authz.check_access('fourq','user','frank','review','doc','brief')::text, 'false');
    PERFORM _test_assert('fq_16b_expired_reviewer_not_listed',
        (SELECT count(*)::text FROM authz.list_subjects('fourq', 'user', 'review', 'doc', 'brief') WHERE subject_id = 'frank'), '0');
END;
$$;

SELECT _test_report('four questions (pitch example)');
