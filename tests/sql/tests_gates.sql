-- Tests for temporal gates (ADR 0012, phase 2): declarative history-dependent
-- clauses over the action log, evaluated after the graph allows.
--
-- Covers: the four primitives and their thresholds, sliding vs calendar
-- windows and their boundaries, containment matching with $request references
-- and recorded_by allowlists, the fail-closed table (missing context ⇒
-- conditional, bad values ⇒ hard deny), AND composition across gates, the
-- userset seam (gates apply to the question asked, not sub-questions),
-- enumeration consistency (list_* agree with check), explain steps, spec
-- validation, time-travel exactness, registry propagation, describe_model.
--
-- One relation per scenario on type `account` so gates do not interfere.

SELECT _test_reset();

DROP FUNCTION IF EXISTS _test_setup_gates();
CREATE FUNCTION _test_setup_gates() RETURNS void LANGUAGE plpgsql AS $$
DECLARE v_rel text;
BEGIN
    BEGIN PERFORM authz.delete_store('test_gates',  p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END;
    BEGIN PERFORM authz.delete_store('test_gates2', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END;
    DELETE FROM authz.model_registry WHERE name = 'test_gates_model';

    PERFORM authz.create_store('test_gates');
    PERFORM authz.model_register_type('test_gates', 'user');
    PERFORM authz.model_register_type('test_gates', 'account');
    PERFORM authz.model_register_type('test_gates', 'doc');
    PERFORM authz.model_register_type('test_gates', 'group');
    FOREACH v_rel IN ARRAY ARRAY['transfer', 'withdraw', 'approve', 'peek', 'download', 'pay', 'audit_note'] LOOP
        PERFORM authz.model_register_relation('test_gates', v_rel);
    END LOOP;
    PERFORM authz.model_register_relation('test_gates', 'approve_sale');   -- vocabulary only
    PERFORM authz.model_register_relation('test_gates', 'viewer');
    PERFORM authz.model_register_relation('test_gates', 'editor');
    PERFORM authz.model_register_relation('test_gates', 'member');
    PERFORM authz.model_register_relation('test_gates', 'submit');
    PERFORM authz.model_register_relation('test_gates', 'approve_doc');
    FOREACH v_rel IN ARRAY ARRAY['transfer', 'withdraw', 'approve', 'peek', 'download', 'pay'] LOOP
        PERFORM authz.model_add_rule('test_gates', 'account', v_rel, 'direct');
        PERFORM authz.write_tuple('test_gates', 'user', 'alice', v_rel, 'account', 'acc-1');
    END LOOP;
    PERFORM authz.model_add_rule('test_gates', 'doc', 'viewer', 'direct');
    PERFORM authz.model_add_rule('test_gates', 'doc', 'editor', 'direct');
    PERFORM authz.model_add_rule('test_gates', 'group', 'member', 'direct');
    PERFORM authz.model_add_rule('test_gates', 'doc', 'submit', 'direct');
    PERFORM authz.model_add_rule('test_gates', 'doc', 'approve_doc', 'direct');
END;
$$;

DROP FUNCTION IF EXISTS _test_teardown_gates();
CREATE FUNCTION _test_teardown_gates() RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    BEGIN PERFORM authz.delete_store('test_gates',  p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END;
    BEGIN PERFORM authz.delete_store('test_gates2', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END;
    DELETE FROM authz.model_registry WHERE name = 'test_gates_model';
    RETURN QUERY DELETE FROM _test_results RETURNING *;
END;
$$;

CREATE OR REPLACE FUNCTION pg_temp._g(p_rel text, p_ctx jsonb DEFAULT NULL, p_user text DEFAULT 'alice') RETURNS boolean
LANGUAGE sql AS $$
    SELECT authz.check_access_with_context('test_gates', 'user', p_user, p_rel, 'account', 'acc-1', p_ctx);
$$;
CREATE OR REPLACE FUNCTION pg_temp._gstate(p_rel text, p_ctx jsonb DEFAULT NULL) RETURNS text
LANGUAGE sql AS $$
    SELECT authz.check_access_detailed('test_gates', 'user', 'alice', p_rel, 'account', 'acc-1', p_ctx) ->> 'state';
$$;
CREATE OR REPLACE FUNCTION pg_temp._greason(p_rel text, p_ctx jsonb DEFAULT NULL) RETURNS text
LANGUAGE sql AS $$
    SELECT authz.explain_access('test_gates', 'user', 'alice', p_rel, 'account', 'acc-1', p_ctx) -> 'decision' ->> 'reason';
$$;
CREATE OR REPLACE FUNCTION pg_temp._gsteps(p_rel text, p_ctx jsonb DEFAULT NULL) RETURNS jsonb
LANGUAGE sql AS $$
    SELECT jsonb_path_query_array(authz.explain_access('test_gates', 'user', 'alice', p_rel, 'account', 'acc-1', p_ctx),
                                  '$.trace[*] ? (@.rule_type == "temporal_gate")');
$$;

SELECT _test_setup_gates();

-- ================================================================
-- count_within + sum_within, AND composition, explain
-- ================================================================
DO $$
DECLARE v_steps jsonb;
BEGIN
    PERFORM authz.add_gate('test_gates', 'account', 'transfer', 'velocity', '{
        "description": "transfer velocity backstop",
        "all_of": [
            {"count_within": {"window": "1h", "max": 2}},
            {"sum_within":   {"window": "1h", "kind": "response", "field": "input.amount",
                              "plus": "$request.amount", "max": 5000}}
        ]}');

    -- g_01: no history → allow; the graph must still allow (bob has no tuple)
    PERFORM _test_assert('g_01_no_history_allows', pg_temp._g('transfer', '{"amount": 100}')::text, 'true');
    PERFORM _test_assert('g_01_graph_deny_still_denies', pg_temp._g('transfer', '{"amount": 100}', 'bob')::text, 'false');

    PERFORM authz.record_event('test_gates', 'user', 'alice', 'transfer', 'account', 'acc-1', 'request');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'transfer', 'account', 'acc-1', 'response', '{"input": {"amount": 3000}}');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'transfer', 'account', 'acc-1', 'request');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'transfer', 'account', 'acc-1', 'response', '{"input": {"amount": 1500}}');

    -- g_02: count 2 <= max 2 (inclusive); sum 4500 + 400 <= 5000 → allow
    PERFORM _test_assert('g_02_inclusive_thresholds_allow', pg_temp._g('transfer', '{"amount": 400}')::text, 'true');
    -- g_03: sum 4500 + 600 > 5000 → deny; explain reason gate_denied, clause 1 failed, clause 0 passed
    PERFORM _test_assert('g_03_sum_plus_request_denies', pg_temp._g('transfer', '{"amount": 600}')::text, 'false');
    PERFORM _test_assert('g_03_reason_gate_denied', pg_temp._greason('transfer', '{"amount": 600}'), 'gate_denied');
    v_steps := pg_temp._gsteps('transfer', '{"amount": 600}');
    PERFORM _test_assert('g_03_two_gate_steps', jsonb_array_length(v_steps)::text, '2');
    PERFORM _test_assert('g_03_step0_passed', v_steps -> 0 ->> 'reason', 'gate_passed');
    PERFORM _test_assert('g_03_step1_denied_observed_threshold',
        (v_steps -> 1 ->> 'reason') || ' ' || (v_steps -> 1 ->> 'observed') || '/' || (v_steps -> 1 ->> 'threshold') || ' ' || (v_steps -> 1 ->> 'clause'),
        'gate_denied 5100/5000 1:sum_within');
    PERFORM _test_assert('g_03_step_depth_zero', v_steps -> 0 ->> 'depth', '0');
    PERFORM _test_assert('g_03_step_no_payload_leak', (v_steps::text LIKE '%3000%' OR v_steps::text LIKE '%1500%')::text, 'false');

    -- g_04: a 3rd request breaks the count clause → deny even with a tiny amount
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'transfer', 'account', 'acc-1', 'request');
    PERFORM _test_assert('g_04_count_exceeded_denies', pg_temp._g('transfer', '{"amount": 1}')::text, 'false');
    -- and it is a HARD deny: the count clause fails with complete context
    PERFORM _test_assert('g_04_state_deny_not_conditional', pg_temp._gstate('transfer', '{"amount": 1}'), 'deny');
    -- g_05: missing $request.amount → the sum clause lacks context, but the count clause is a hard deny → deny
    PERFORM _test_assert('g_05_missing_ctx_with_hard_deny_is_deny', pg_temp._gstate('transfer'), 'deny');
    -- g_04b: "plus: 1" counts the request being decided — with 3 prior requests,
    -- max 3 fails only because this request is included (3 + 1 > 3)
    PERFORM authz.add_gate('test_gates', 'account', 'transfer', 'incl', '{"all_of": [{"count_within": {"window": "1h", "max": 3, "plus": 1}}]}');
    PERFORM _test_assert('g_04b_plus_counts_this_request',
        (SELECT e ->> 'observed' || '/' || (e ->> 'threshold') || ' ' || (e ->> 'reason')
           FROM jsonb_array_elements(pg_temp._gsteps('transfer', '{"amount": 1}')) e WHERE e ->> 'gate' = 'incl'),
        '4/3 gate_denied');
    PERFORM authz.drop_gate('test_gates', 'account', 'transfer', 'incl');
    -- g_06: non-numeric request value → gate_bad_request_value, hard deny
    PERFORM _test_assert('g_06_bad_request_value_reason',
        (SELECT string_agg(e ->> 'reason', ',') FROM jsonb_array_elements(pg_temp._gsteps('transfer', '{"amount": "lots"}')) e),
        'gate_denied,gate_bad_request_value');
END;
$$;

-- ================================================================
-- formerly_within: match with $request reference, recorded_by, tri-state
-- ================================================================
DO $$
DECLARE v_detail jsonb;
BEGIN
    PERFORM authz.add_gate('test_gates', 'account', 'withdraw', 'four_eyes', '{
        "all_of": [{"formerly_within": {"window": "1h", "action": "approve_sale", "kind": "response",
                                        "match": {"input.stock": "$request.stock", "output.approved": true},
                                        "recorded_by": ["svc:approvals"]}}]}');
    -- g_07: no approval → deny; state conditional? No — context is complete, so hard deny
    PERFORM _test_assert('g_07_no_approval_denies', pg_temp._g('withdraw', '{"stock": "ACME"}')::text, 'false');
    PERFORM _test_assert('g_07_hard_deny_with_context', pg_temp._gstate('withdraw', '{"stock": "ACME"}'), 'deny');

    PERFORM authz.record_event('test_gates', 'user', 'alice', 'approve_sale', NULL, NULL, 'response',
        '{"input": {"stock": "ACME"}, "output": {"approved": true}}', NULL, NULL, 'svc:approvals');
    -- g_08: matching approval → allow; other stock → deny; approved:false variant → deny
    PERFORM _test_assert('g_08_matching_approval_allows', pg_temp._g('withdraw', '{"stock": "ACME"}')::text, 'true');
    PERFORM _test_assert('g_08_other_stock_denies', pg_temp._g('withdraw', '{"stock": "OTHER"}')::text, 'false');
    -- g_09: missing $request.stock → the ONLY blocker is context → conditional, missing_context names it
    v_detail := authz.check_access_detailed('test_gates', 'user', 'alice', 'withdraw', 'account', 'acc-1');
    PERFORM _test_assert('g_09_missing_ctx_is_conditional', v_detail ->> 'state', 'conditional');
    PERFORM _test_assert('g_09_missing_context_key', (v_detail -> 'missing_context')::text, '["request.stock"]');
    PERFORM _test_assert('g_09_boolean_api_still_denies', pg_temp._g('withdraw')::text, 'false');
    PERFORM _test_assert('g_09_explain_reason_missing_context',
        pg_temp._gsteps('withdraw') -> 0 ->> 'reason', 'gate_missing_context');
    -- g_10: an approval recorded by someone else does not satisfy the allowlist
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'approve_sale', NULL, NULL, 'response',
        '{"input": {"stock": "ZZZ"}, "output": {"approved": true}}', NULL, NULL, 'svc:rogue');
    PERFORM _test_assert('g_10_recorded_by_allowlist', pg_temp._g('withdraw', '{"stock": "ZZZ"}')::text, 'false');
END;
$$;

-- ================================================================
-- Windows: sliding boundary, calendar buckets; count_distinct; payload errors
-- ================================================================
DO $$
BEGIN
    -- g_11: sliding window is half-open — an event just outside is excluded, just inside counts
    PERFORM authz.add_gate('test_gates', 'account', 'peek', 'cooldown', '{"all_of": [{"count_within": {"window": "10m", "max": 0}}]}');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'peek', 'account', 'acc-1', 'request', '{}', now() - interval '11 minutes');
    PERFORM _test_assert('g_11_event_outside_window_ignored', pg_temp._g('peek')::text, 'true');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'peek', 'account', 'acc-1', 'request', '{}', now() - interval '9 minutes');
    PERFORM _test_assert('g_11_event_inside_window_counts', pg_temp._g('peek')::text, 'false');

    -- g_12: calendar day (UTC): yesterday's event is outside today's bucket
    PERFORM authz.add_gate('test_gates', 'account', 'approve', 'daily_quota', '{"all_of": [{"count_within": {"calendar": "day", "tz": "UTC", "max": 1}}]}');
    PERFORM set_config('authz.event_max_backdate', '48 hours', true);
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'approve', 'account', 'acc-1', 'request', '{}',
        (date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC') - interval '1 minute');
    PERFORM set_config('authz.event_max_backdate', '', true);
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'approve', 'account', 'acc-1', 'request');
    PERFORM _test_assert('g_12_calendar_excludes_yesterday', pg_temp._g('approve')::text, 'true');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'approve', 'account', 'acc-1', 'request');
    PERFORM _test_assert('g_12_calendar_counts_today', pg_temp._g('approve')::text, 'false');
    PERFORM _test_assert('g_12_window_rendered_as_calendar',
        pg_temp._gsteps('approve') -> 0 ->> 'window', 'day/UTC');

    -- g_13: count_distinct_within on object_id — 2 distinct objects allowed, a 3rd denies
    PERFORM authz.add_gate('test_gates', 'account', 'download', 'exfil_brake', '{"all_of": [{"count_distinct_within": {"window": "1h", "key": "object_id", "max": 2}}]}');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'download', 'account', 'acc-1');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'download', 'account', 'acc-1');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'download', 'account', 'acc-2');
    PERFORM _test_assert('g_13_distinct_within_cap', pg_temp._g('download')::text, 'true');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'download', 'account', 'acc-3');
    PERFORM _test_assert('g_13_distinct_over_cap', pg_temp._g('download')::text, 'false');

    -- g_14: sum_within over a matched event lacking a numeric field is a hard deny
    PERFORM authz.add_gate('test_gates', 'account', 'pay', 'spend_cap', '{"all_of": [{"sum_within": {"window": "1h", "field": "input.cost", "max": 100}}]}');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'pay', 'account', 'acc-1', 'request', '{"input": {"cost": 40}}');
    PERFORM _test_assert('g_14_sum_ok', pg_temp._g('pay')::text, 'true');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'pay', 'account', 'acc-1', 'request', '{"input": {"cost": "forty"}}');
    PERFORM _test_assert('g_14_non_numeric_payload_denies', pg_temp._g('pay')::text, 'false');
    PERFORM _test_assert('g_14_reason_payload_not_numeric', pg_temp._gsteps('pay') -> 0 ->> 'reason', 'gate_payload_not_numeric');
END;
$$;

-- ================================================================
-- Seam: gates apply to the question asked, not to userset sub-questions;
-- enumeration agrees with check
-- ================================================================
DO $$
DECLARE n int; v_subjects text; v_actions text;
BEGIN
    -- g_15: a gate on group#member does not fire while resolving doc#editor through group:eng#member
    PERFORM authz.write_tuple('test_gates', 'user', 'alice', 'member', 'group', 'eng');
    PERFORM authz.write_tuple('test_gates', 'group', 'eng', 'editor', 'doc', 'doc1', p_user_relation => 'member');
    PERFORM authz.add_gate('test_gates', 'group', 'member', 'needs_prior_event', '{"all_of": [{"count_within": {"window": "1h", "min": 1}}]}');
    PERFORM _test_assert('g_15_gated_relation_denies',
        authz.check_access('test_gates', 'user', 'alice', 'member', 'group', 'eng')::text, 'false');
    PERFORM _test_assert('g_15_userset_resolution_not_gated',
        authz.check_access('test_gates', 'user', 'alice', 'editor', 'doc', 'doc1')::text, 'true');

    -- g_16: list_subjects / list_objects / list_actions agree with check
    PERFORM authz.write_tuple('test_gates', 'user', 'alice', 'viewer', 'doc', 'doc1');
    PERFORM authz.write_tuple('test_gates', 'user', 'bob',   'viewer', 'doc', 'doc1');
    PERFORM authz.add_gate('test_gates', 'doc', 'viewer', 'lockout', '{"all_of": [{"count_within": {"window": "1h", "kind": "denied", "max": 0}}]}');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'viewer', 'doc', 'doc1', 'denied');
    SELECT string_agg(subject_id, ',' ORDER BY subject_id) INTO v_subjects
      FROM authz.list_subjects('test_gates', 'user', 'viewer', 'doc', 'doc1');
    PERFORM _test_assert('g_16_list_subjects_excludes_gated', v_subjects, 'bob');
    SELECT count(*) INTO n FROM authz.list_objects('test_gates', 'user', 'alice', 'viewer', 'doc');
    PERFORM _test_assert('g_16_list_objects_empty_when_gated', n::text, '0');
    SELECT count(*) INTO n FROM authz.list_objects('test_gates', 'user', 'bob', 'viewer', 'doc');
    PERFORM _test_assert('g_16_list_objects_other_subject_unaffected', n::text, '1');
    SELECT string_agg(action, ',' ORDER BY action) INTO v_actions
      FROM authz.list_actions('test_gates', 'user', 'alice', 'doc', 'doc1');
    PERFORM _test_assert('g_16_list_actions_excludes_gated', v_actions, 'editor');
    -- batch checks go through the same seam
    PERFORM _test_assert('g_16_batch_agrees',
        (authz.check_access_batch('test_gates',
            '[{"user_type":"user","user_id":"alice","relation":"viewer","object_type":"doc","object_id":"doc1"},
              {"user_type":"user","user_id":"bob","relation":"viewer","object_type":"doc","object_id":"doc1"}]'))::text,
        '[{"decision": false}, {"decision": true}]');
END;
$$;

-- ================================================================
-- Validation
-- ================================================================
DO $body$
DECLARE v_bad text[] := ARRAY[
    '{"all_of": []}',
    '{"all_of": [{"nope": {"window": "1h"}}]}',
    '{"all_of": [{"count_within": {"window": "1h", "calendar": "day", "tz": "UTC", "max": 1}}]}',
    '{"all_of": [{"count_within": {"max": 1}}]}',
    '{"all_of": [{"count_within": {"window": "1mon", "max": 1}}]}',
    '{"all_of": [{"count_within": {"window": "P1M", "max": 1}}]}',
    '{"all_of": [{"count_within": {"window": "1h", "tz": "UTC", "max": 1}}]}',
    '{"all_of": [{"count_within": {"calendar": "day", "max": 1}}]}',
    '{"all_of": [{"count_within": {"calendar": "day", "tz": "Mars/Olympus", "max": 1}}]}',
    '{"all_of": [{"count_within": {"window": "1h", "action": "no_such_action", "max": 1}}]}',
    '{"all_of": [{"count_within": {"window": "1h", "kind": "started", "max": 1}}]}',
    '{"all_of": [{"count_within": {"window": "1h"}}]}',
    '{"all_of": [{"count_within": {"window": "1h", "min": 5, "max": 2}}]}',
    '{"all_of": [{"count_within": {"window": "1h", "max": "$foo"}}]}',
    '{"all_of": [{"count_within": {"window": "1h", "max": "five"}}]}',
    '{"all_of": [{"count_within": {"window": "1h", "max": 1, "key": "object_id"}}]}',
    '{"all_of": [{"count_distinct_within": {"window": "1h", "max": 1}}]}',
    '{"all_of": [{"sum_within": {"window": "1h", "max": 1}}]}',
    '{"all_of": [{"formerly_within": {"window": "1h", "match": {}}}]}',
    '{"all_of": [{"formerly_within": {"window": "1h", "match": {"a[0]": 1}}}]}',
    '{"all_of": [{"formerly_within": {"window": "1h", "recorded_by": []}}]}',
    '{"all_of": [{"formerly_within": {"window": "1h"}}], "extra": 1}',
    '{"all_of": [{"formerly_within": {"window": "1h", "window2": "x"}}]}',
    '{"all_of": [{"count_within": {"window": "1h", "scope": "resource", "max": 1}}]}'
];
    v_spec text; v_state text; v_ok int := 0;
BEGIN
    FOREACH v_spec IN ARRAY v_bad LOOP
        v_state := NULL;
        BEGIN
            PERFORM authz.add_gate('test_gates', 'account', 'audit_note', 'bad', v_spec::jsonb);
        EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
        IF v_state = '23514' THEN v_ok := v_ok + 1;
        ELSE RAISE NOTICE 'g_17: spec % → SQLSTATE %', v_spec, coalesce(v_state, 'accepted');
        END IF;
    END LOOP;
    PERFORM _test_assert('g_17_all_invalid_specs_rejected_check_violation', v_ok::text, array_length(v_bad, 1)::text);

    -- g_18: normalization — window canonicalized, required_context derived, doubled-sigil literal, no-op re-add
    PERFORM authz.add_gate('test_gates', 'account', 'audit_note', 'norm', '{
        "all_of": [{"formerly_within": {"window": "PT30M", "match": {"tag": "$$literal", "who": "$request.actor.id"}}},
                   {"count_within": {"window": "2 hours", "max": "$request.limit"}}]}');
    PERFORM _test_assert('g_18_window_canonical',
        (SELECT g.spec -> 'all_of' -> 0 -> 'formerly_within' ->> 'window' FROM authz.model_gates g WHERE g.name = 'norm'), '00:30:00');
    PERFORM _test_assert('g_18_required_context_derived',
        (SELECT (g.spec -> 'required_context')::text FROM authz.model_gates g WHERE g.name = 'norm'),
        '{"request": ["actor", "limit"]}');
    PERFORM _test_assert('g_18_reread_is_noop',
        (SELECT count(*) FROM authz.model_gates_audit a WHERE a.name = 'norm' AND a.store_id = authz._s('test_gates'))::text, '1');
    PERFORM authz.add_gate('test_gates', 'account', 'audit_note', 'norm', '{
        "all_of": [{"formerly_within": {"window": "PT30M", "match": {"tag": "$$literal", "who": "$request.actor.id"}}},
                   {"count_within": {"window": "2 hours", "max": "$request.limit"}}]}');
    PERFORM _test_assert('g_18_reread_is_noop_after',
        (SELECT count(*) FROM authz.model_gates_audit a WHERE a.name = 'norm' AND a.store_id = authz._s('test_gates'))::text, '1');
    -- g_19: a spec change is versioned as DELETE + INSERT; drop_gate logs a DELETE
    PERFORM authz.add_gate('test_gates', 'account', 'audit_note', 'norm', '{"all_of": [{"count_within": {"window": "1h", "max": 3}}]}');
    PERFORM _test_assert('g_19_update_versioned',
        (SELECT string_agg(a.action, ',' ORDER BY a.seq) FROM authz.model_gates_audit a WHERE a.name = 'norm' AND a.store_id = authz._s('test_gates')), 'INSERT,DELETE,INSERT');
    PERFORM _test_assert('g_19_drop_returns_true', authz.drop_gate('test_gates', 'account', 'audit_note', 'norm')::text, 'true');
    PERFORM _test_assert('g_19_drop_logged',
        (SELECT a.action FROM authz.model_gates_audit a WHERE a.name = 'norm' AND a.store_id = authz._s('test_gates') ORDER BY a.seq DESC LIMIT 1), 'DELETE');
    PERFORM _test_assert('g_19_drop_missing_false', authz.drop_gate('test_gates', 'account', 'audit_note', 'norm')::text, 'false');
END;
$body$;

-- ================================================================
-- Time-travel: definitions as of p_at, events bounded by recorded_at
-- ================================================================
-- tx1: a gate requiring one prior transfer request within the hour
DO $$
BEGIN
    PERFORM authz.drop_gate('test_gates', 'account', 'transfer', 'velocity');
    PERFORM authz.write_tuple('test_gates', 'user', 'carol', 'transfer', 'account', 'acc-1');
    PERFORM authz.add_gate('test_gates', 'account', 'transfer', 'needs_request', '{"all_of": [{"count_within": {"window": "1h", "min": 1}}]}');
    PERFORM _test_assert('g_20_live_denies_without_event',
        authz.check_access('test_gates', 'user', 'carol', 'transfer', 'account', 'acc-1')::text, 'false');
END;
$$;
SELECT set_config('test.g_t1', clock_timestamp()::text, false);
SELECT pg_sleep(0.01);
-- tx2: the event arrives
DO $$
BEGIN
    PERFORM authz.record_event('test_gates', 'user', 'carol', 'transfer', 'account', 'acc-1', 'request');
    PERFORM _test_assert('g_20_live_allows_with_event',
        authz.check_access('test_gates', 'user', 'carol', 'transfer', 'account', 'acc-1')::text, 'true');
END;
$$;
SELECT set_config('test.g_t2', clock_timestamp()::text, false);
SELECT pg_sleep(0.01);
-- tx3: a BACKDATED event (occurred before t1, recorded after t2) must not change what was knowable at t1
DO $$
BEGIN
    PERFORM authz.record_event('test_gates', 'user', 'carol', 'transfer', 'account', 'acc-1', 'request', '{}', now() - interval '30 minutes');
END;
$$;
DO $$
DECLARE t1 timestamptz := current_setting('test.g_t1')::timestamptz;
        t2 timestamptz := current_setting('test.g_t2')::timestamptz;
BEGIN
    PERFORM _test_assert('g_21_as_of_t1_denies_gate_existed_no_event',
        authz.audit_check_access('test_gates', 'user', 'carol', 'transfer', 'account', 'acc-1', t1)::text, 'false');
    PERFORM _test_assert('g_21_as_of_t2_allows',
        authz.audit_check_access('test_gates', 'user', 'carol', 'transfer', 'account', 'acc-1', t2)::text, 'true');
    PERFORM _test_assert('g_21_audit_list_actions_as_of_t1_excludes',
        (SELECT count(*) FROM authz.audit_list_actions('test_gates', 'user', 'carol', 'account', 'acc-1', t1) a WHERE a.action = 'transfer')::text, '0');
    PERFORM _test_assert('g_21_audit_list_actions_as_of_t2_includes',
        (SELECT count(*) FROM authz.audit_list_actions('test_gates', 'user', 'carol', 'account', 'acc-1', t2) a WHERE a.action = 'transfer')::text, '1');
END;
$$;
-- tx4: drop the gate; live allows regardless, t1 still denies (the gate existed then)
DO $$
DECLARE t1 timestamptz := current_setting('test.g_t1')::timestamptz;
BEGIN
    PERFORM authz.drop_gate('test_gates', 'account', 'transfer', 'needs_request');
END;
$$;
DO $$
DECLARE t1 timestamptz := current_setting('test.g_t1')::timestamptz;
BEGIN
    PERFORM _test_assert('g_22_live_after_drop_allows',
        authz.check_access('test_gates', 'user', 'carol', 'transfer', 'account', 'acc-1')::text, 'true');
    PERFORM _test_assert('g_22_as_of_t1_still_denies_after_drop',
        authz.audit_check_access('test_gates', 'user', 'carol', 'transfer', 'account', 'acc-1', t1)::text, 'false');
    PERFORM _test_assert('g_22_as_of_now_allows',
        authz.audit_check_access('test_gates', 'user', 'carol', 'transfer', 'account', 'acc-1', clock_timestamp())::text, 'true');
END;
$$;

-- ================================================================
-- Registry propagation, checksum stability, describe_model
-- ================================================================
DO $$
DECLARE v_def jsonb; v_ver int; v_sum text; v_desc text;
BEGIN
    v_def := authz.export_model('test_gates');
    PERFORM _test_assert_true('g_23_export_has_gates', jsonb_array_length(v_def -> 'gates') >= 5,
        (jsonb_array_length(v_def -> 'gates'))::text);
    -- a gate-free store hashes as before the key existed
    PERFORM authz.create_store('test_gates2');
    PERFORM _test_assert('g_23_empty_gates_checksum_stable',
        (authz._model_checksum(authz.export_model('test_gates2')) = authz._model_checksum(authz.export_model('test_gates2') - 'gates'))::text, 'true');
    PERFORM _test_assert('g_23_nonempty_gates_change_checksum',
        (authz._model_checksum(v_def) = authz._model_checksum(v_def - 'gates'))::text, 'false');

    -- publish + apply propagates the gates and passes the post-apply self-check
    v_ver := authz.publish_model('test_gates_model', 'test_gates');
    PERFORM authz.apply_model('test_gates2', 'test_gates_model');
    PERFORM _test_assert('g_24_apply_propagates_gates',
        (SELECT count(*) FROM authz.model_gates g WHERE g.store_id = authz._s('test_gates2'))::text,
        jsonb_array_length(v_def -> 'gates')::text);
    PERFORM _test_assert('g_24_plan_reports_no_gate_changes',
        (authz.plan_model_apply('test_gates2', 'test_gates_model') -> 'changes' -> 'gates')::text,
        '{"add": [], "remove": []}');
    -- a gate dropped at the source is removed at the target on the next version
    PERFORM authz.drop_gate('test_gates', 'account', 'pay', 'spend_cap');
    PERFORM authz.publish_model('test_gates_model', 'test_gates');
    PERFORM _test_assert('g_24_plan_reports_removal',
        jsonb_array_length(authz.plan_model_apply('test_gates2', 'test_gates_model') -> 'changes' -> 'gates' -> 'remove')::text, '1');
    PERFORM authz.apply_model('test_gates2', 'test_gates_model');
    PERFORM _test_assert('g_24_apply_removes_stale_gate',
        (SELECT count(*) FROM authz.model_gates g WHERE g.store_id = authz._s('test_gates2') AND g.name = 'spend_cap')::text, '0');

    -- g_25: describe_model renders gates as comment lines (relation-prefixed when rule-less)
    v_desc := authz.describe_model('test_gates');
    PERFORM _test_assert_true('g_25_describe_gate_header', position('    # gate four_eyes' in v_desc) > 0, v_desc);
    PERFORM _test_assert_true('g_25_describe_clause_line',
        position('#   formerly_within{window: "01:00:00", action: "approve_sale", kind: "response", match:' in v_desc) > 0, v_desc);
    PERFORM authz.add_gate('test_gates', 'account', 'audit_note', 'vocab_only', '{"all_of": [{"count_within": {"window": "1h", "max": 1}}]}');
    v_desc := authz.describe_model('test_gates');
    PERFORM _test_assert_true('g_25_describe_ruleless_relation_prefixed', position('    # gate audit_note/vocab_only' in v_desc) > 0, v_desc);
END;
$$;

-- ================================================================
-- Object-scoped clauses (scope = object)
-- ================================================================
DO $$
DECLARE v_objs text; v_step jsonb;
BEGIN
    -- alice edits doc1 via group:eng#member (g_15) and doc2 directly
    PERFORM authz.write_tuple('test_gates', 'user', 'alice', 'editor', 'doc', 'doc2');
    -- "at most 3 edits of THIS document per hour" (plus 1 counts the request)
    PERFORM authz.add_gate('test_gates', 'doc', 'editor', 'per_doc_limit', '{
        "all_of": [{"count_within": {"window": "1h", "scope": "object", "max": 3, "plus": 1}}]}');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'editor', 'doc', 'doc1');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'editor', 'doc', 'doc1');
    -- g_26: 2 prior edits of doc1 → a 3rd is allowed; doc2 is untouched by them
    PERFORM _test_assert('g_26_under_per_object_cap',
        authz.check_access('test_gates', 'user', 'alice', 'editor', 'doc', 'doc1')::text, 'true');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'editor', 'doc', 'doc1');
    PERFORM _test_assert('g_26_over_per_object_cap',
        authz.check_access('test_gates', 'user', 'alice', 'editor', 'doc', 'doc1')::text, 'false');
    PERFORM _test_assert('g_26_other_object_unaffected',
        authz.check_access('test_gates', 'user', 'alice', 'editor', 'doc', 'doc2')::text, 'true');
    -- the same clause subject-scoped would count doc1's edits against doc2 too
    PERFORM authz.add_gate('test_gates', 'doc', 'editor', 'per_doc_limit', '{
        "all_of": [{"count_within": {"window": "1h", "max": 3, "plus": 1}}]}');
    PERFORM _test_assert('g_26_subject_scope_contrast',
        authz.check_access('test_gates', 'user', 'alice', 'editor', 'doc', 'doc2')::text, 'false');
    PERFORM authz.add_gate('test_gates', 'doc', 'editor', 'per_doc_limit', '{
        "all_of": [{"count_within": {"window": "1h", "scope": "object", "max": 3, "plus": 1}}]}');

    -- g_27: explain reports the scope; list_objects evaluates per candidate
    SELECT e INTO v_step FROM jsonb_array_elements(jsonb_path_query_array(
        authz.explain_access('test_gates', 'user', 'alice', 'editor', 'doc', 'doc1'),
        '$.trace[*] ? (@.rule_type == "temporal_gate")')) e LIMIT 1;
    PERFORM _test_assert('g_27_explain_step_scope',
        (v_step ->> 'scope') || ' ' || (v_step ->> 'reason') || ' ' || (v_step ->> 'observed'), 'object gate_denied 4');
    SELECT string_agg(object_id, ',' ORDER BY object_id) INTO v_objs
      FROM authz.list_objects('test_gates', 'user', 'alice', 'editor', 'doc');
    PERFORM _test_assert('g_27_list_objects_per_candidate', v_objs, 'doc2');
    PERFORM _test_assert('g_27_helper_detects_object_scope',
        authz._event_gates_object_scoped(authz._event_resolve_gates(authz._s('test_gates'), authz._t('test_gates', 'doc'), authz._r('test_gates', 'editor')))::text, 'true');
    PERFORM _test_assert('g_27_helper_subject_only',
        authz._event_gates_object_scoped(authz._event_resolve_gates(authz._s('test_gates'), authz._t('test_gates', 'doc'), authz._r('test_gates', 'viewer')))::text, 'false');
    PERFORM authz.drop_gate('test_gates', 'doc', 'editor', 'per_doc_limit');

    -- g_28: separation of duties — whoever submitted THIS document may not approve it
    PERFORM authz.write_tuple('test_gates', 'user', 'alice', 'approve_doc', 'doc', 'doc1');
    PERFORM authz.write_tuple('test_gates', 'user', 'alice', 'approve_doc', 'doc', 'doc2');
    PERFORM authz.write_tuple('test_gates', 'user', 'bob',   'approve_doc', 'doc', 'doc1');
    PERFORM authz.add_gate('test_gates', 'doc', 'approve_doc', 'four_eyes_sod', '{
        "description": "the submitter may not approve",
        "all_of": [{"count_within": {"window": "30d", "action": "submit", "kind": "response", "scope": "object", "max": 0}}]}');
    PERFORM authz.record_event('test_gates', 'user', 'alice', 'submit', 'doc', 'doc1', 'response');
    PERFORM _test_assert('g_28_submitter_cannot_approve',
        authz.check_access('test_gates', 'user', 'alice', 'approve_doc', 'doc', 'doc1')::text, 'false');
    PERFORM _test_assert('g_28_other_approver_can',
        authz.check_access('test_gates', 'user', 'bob', 'approve_doc', 'doc', 'doc1')::text, 'true');
    PERFORM _test_assert('g_28_submitter_can_approve_other_doc',
        authz.check_access('test_gates', 'user', 'alice', 'approve_doc', 'doc', 'doc2')::text, 'true');
    PERFORM _test_assert_true('g_28_describe_renders_scope',
        position('scope: "object"' in authz.describe_model('test_gates')) > 0, authz.describe_model('test_gates'));
    PERFORM _test_assert('g_28_list_subjects_agrees',
        (SELECT string_agg(subject_id, ',' ORDER BY subject_id) FROM authz.list_subjects('test_gates', 'user', 'approve_doc', 'doc', 'doc1')), 'bob');
END;
$$;

-- ================================================================
-- Retention guard: gate_windows / max_gate_window, drop + purge refuse a
-- cutoff inside a live gate window unless forced
-- ================================================================
DO $$
DECLARE v_state text; v_err text; n int; v_max interval;
BEGIN
    -- the four_eyes_sod gate above has a 30d window; daily_quota is calendar day
    v_max := authz.max_gate_window('test_gates');
    PERFORM _test_assert('rg_01_max_gate_window_is_longest', v_max::text, '30 days');
    PERFORM _test_assert('rg_01_calendar_day_bucket_is_25h',
        (SELECT w."window"::text FROM authz.gate_windows('test_gates') w WHERE w.gate = 'daily_quota'), '25:00:00');
    PERFORM _test_assert_true('rg_01_windows_list_every_clause',
        (SELECT count(*) FROM authz.gate_windows('test_gates')) >= 6,
        (SELECT count(*)::text FROM authz.gate_windows('test_gates')));
    PERFORM _test_assert_true('rg_01_fleet_wide_includes_store',
        authz.max_gate_window() >= v_max, authz.max_gate_window()::text);

    -- rg_02: purge inside the window is refused with the gate named; forced or outside → runs
    v_state := NULL; v_err := NULL;
    BEGIN PERFORM authz.purge_events('test_gates', now() - interval '10 days');
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; v_err := SQLERRM; END;
    PERFORM _test_assert('rg_02_purge_inside_window_refused', v_state, '23514');
    PERFORM _test_assert_true('rg_02_refusal_names_gate', v_err LIKE '%four_eyes_sod%' AND v_err LIKE '%30 days%', coalesce(v_err, 'no error'));
    PERFORM _test_assert_true('rg_02_purge_outside_window_runs',
        authz.purge_events('test_gates', now() - interval '31 days') >= 0);
    PERFORM _test_assert_true('rg_02_purge_forced_runs',
        authz.purge_events('test_gates', now() - interval '10 days', p_force => true) >= 0);

    -- rg_03: the fleet-wide partition drop is guarded the same way
    v_state := NULL;
    BEGIN PERFORM authz.drop_event_partitions_before((now() - interval '10 days')::date);
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('rg_03_drop_inside_window_refused', v_state, '23514');
    PERFORM _test_assert_true('rg_03_drop_outside_window_runs',
        authz.drop_event_partitions_before((now() - interval '40 days')::date) >= 0);

    -- rg_04: a store without gates is unrestricted
    BEGIN PERFORM authz.delete_store('test_gates_nogate', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_gates_nogate');
    PERFORM _test_assert('rg_04_no_gates_null_window', COALESCE(authz.max_gate_window('test_gates_nogate')::text, 'null'), 'null');
    PERFORM _test_assert('rg_04_no_gates_purge_unrestricted', authz.purge_events('test_gates_nogate', now())::text, '0');
    PERFORM authz.delete_store('test_gates_nogate', p_purge_audit => true);
END;
$$;

-- ================================================================
-- Shadow mode: per-gate mode = shadow and the authz.gates_mode switch
-- ================================================================
DO $$
DECLARE v_explain jsonb; v_step jsonb; v_detail jsonb; r jsonb; v_state text; v_subjects text;
BEGIN
    -- sanity: the cooldown gate on peek enforces today (alice has a peek event 9 min ago)
    PERFORM _test_assert('sh_00_enforced_denies', pg_temp._g('peek')::text, 'false');

    -- sh_01: the same gate in shadow mode reports but never denies
    PERFORM authz.add_gate('test_gates', 'account', 'peek', 'cooldown',
        '{"mode": "shadow", "all_of": [{"count_within": {"window": "10m", "max": 0}}]}');
    PERFORM _test_assert('sh_01_shadow_allows', pg_temp._g('peek')::text, 'true');
    v_explain := authz.explain_access('test_gates', 'user', 'alice', 'peek', 'account', 'acc-1');
    v_step := pg_temp._gsteps('peek') -> 0;
    PERFORM _test_assert('sh_01_step_keeps_real_outcome',
        (v_step ->> 'reason') || ' ' || (v_step ->> 'result') || ' shadow=' || (v_step ->> 'shadow'), 'gate_denied false shadow=true');
    PERFORM _test_assert('sh_01_decision_reason_is_the_graph', v_explain -> 'decision' ->> 'reason', 'direct_tuple');
    PERFORM _test_assert_true('sh_01_summary_marks_shadow', position('○' in (v_explain ->> 'summary')) > 0, v_explain ->> 'summary');
    PERFORM _test_assert_true('sh_01_describe_marks_shadow',
        position('# gate cooldown (shadow)' in authz.describe_model('test_gates')) > 0);

    -- sh_02: a shadow gate lacking $request context cannot make the decision conditional
    PERFORM authz.add_gate('test_gates', 'account', 'withdraw', 'four_eyes', '{
        "mode": "shadow",
        "all_of": [{"formerly_within": {"window": "1h", "action": "approve_sale", "kind": "response",
                                        "match": {"input.stock": "$request.stock", "output.approved": true},
                                        "recorded_by": ["svc:approvals"]}}]}');
    v_detail := authz.check_access_detailed('test_gates', 'user', 'alice', 'withdraw', 'account', 'acc-1');
    PERFORM _test_assert('sh_02_detailed_state_allow', (v_detail ->> 'decision') || ' ' || (v_detail ->> 'state'), 'true allow');
    PERFORM _test_assert('sh_02_missing_context_excludes_shadow', (v_detail -> 'missing_context')::text, '[]');

    -- sh_03: reserve_event under a shadow gate is allowed and reports the shadowed clause
    r := authz.reserve_event('test_gates', 'user', 'alice', 'peek', 'account', 'acc-1');
    PERFORM _test_assert('sh_03_reserve_allowed_kind_request', (r ->> 'allowed') || ' ' || (r ->> 'kind') || ' ' || (r ->> 'reason'), 'true request allowed');
    PERFORM _test_assert('sh_03_reserve_reports_shadow_outcome',
        (r -> 'gates' -> 0 ->> 'reason') || ' ' || (r -> 'gates' -> 0 ->> 'shadow'), 'gate_denied true');

    -- sh_04: the database-wide switch — shadow allows an ENFORCED gate; off skips evaluation; junk = enforce
    PERFORM _test_assert('sh_04_enforced_quota_denies', pg_temp._g('approve')::text, 'false');
    PERFORM set_config('authz.gates_mode', 'shadow', true);
    PERFORM _test_assert('sh_04_global_shadow_allows', pg_temp._g('approve')::text, 'true');
    PERFORM _test_assert('sh_04_global_shadow_traces_step',
        pg_temp._gsteps('approve') -> 0 ->> 'shadow', 'true');
    PERFORM set_config('authz.gates_mode', 'off', true);
    PERFORM _test_assert('sh_04_off_allows', pg_temp._g('approve')::text, 'true');
    PERFORM _test_assert('sh_04_off_evaluates_nothing', jsonb_array_length(pg_temp._gsteps('approve'))::text, '0');
    PERFORM set_config('authz.gates_mode', 'bogus', true);
    PERFORM _test_assert('sh_04_unknown_value_enforces', pg_temp._g('approve')::text, 'false');
    PERFORM set_config('authz.gates_mode', '', true);

    -- sh_05: enumeration under a shadow gate is unfiltered
    PERFORM authz.add_gate('test_gates', 'doc', 'viewer', 'lockout',
        '{"mode": "shadow", "all_of": [{"count_within": {"window": "1h", "kind": "denied", "max": 0}}]}');
    SELECT string_agg(subject_id, ',' ORDER BY subject_id) INTO v_subjects
      FROM authz.list_subjects('test_gates', 'user', 'viewer', 'doc', 'doc1');
    PERFORM _test_assert('sh_05_list_subjects_unfiltered', v_subjects, 'alice,bob');

    -- sh_06: validation
    v_state := NULL;
    BEGIN PERFORM authz.add_gate('test_gates', 'account', 'audit_note', 'bad',
        '{"mode": "audit", "all_of": [{"count_within": {"window": "1h", "max": 1}}]}');
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('sh_06_bad_mode_rejected', v_state, '23514');

    -- sh_08: mode = off keeps the gate defined but skips it entirely (no steps), and it
    -- still counts toward the retention requirement
    PERFORM authz.add_gate('test_gates', 'account', 'peek', 'cooldown',
        '{"mode": "off", "all_of": [{"count_within": {"window": "10m", "max": 0}}]}');
    PERFORM _test_assert('sh_08_off_allows', pg_temp._g('peek')::text, 'true');
    PERFORM _test_assert('sh_08_off_no_steps', jsonb_array_length(pg_temp._gsteps('peek'))::text, '0');
    PERFORM _test_assert_true('sh_08_describe_marks_off',
        position('# gate cooldown (off)' in authz.describe_model('test_gates')) > 0);
    PERFORM _test_assert('sh_08_off_gate_still_in_windows',
        (SELECT count(*) FROM authz.gate_windows('test_gates') w WHERE w.gate = 'cooldown')::text, '1');
    PERFORM _test_assert('sh_08_still_versioned',
        (SELECT a.action FROM authz.model_gates_audit a WHERE a.name = 'cooldown' AND a.store_id = authz._s('test_gates') ORDER BY a.seq DESC LIMIT 1), 'INSERT');

    -- restore enforcement for the sections below
    PERFORM authz.add_gate('test_gates', 'account', 'peek', 'cooldown', '{"all_of": [{"count_within": {"window": "10m", "max": 0}}]}');
    PERFORM authz.add_gate('test_gates', 'account', 'withdraw', 'four_eyes', '{
        "all_of": [{"formerly_within": {"window": "1h", "action": "approve_sale", "kind": "response",
                                        "match": {"input.stock": "$request.stock", "output.approved": true},
                                        "recorded_by": ["svc:approvals"]}}]}');
    PERFORM authz.add_gate('test_gates', 'doc', 'viewer', 'lockout', '{"all_of": [{"count_within": {"window": "1h", "kind": "denied", "max": 0}}]}');
    PERFORM _test_assert('sh_07_restored_enforces', pg_temp._g('peek')::text, 'false');
END;
$$;

-- ================================================================
-- reserve_event: the strict tier (phase 3)
-- ================================================================
DO $$
DECLARE r jsonb; n int; v_state text;
BEGIN
    PERFORM authz.write_tuple('test_gates', 'user', 'dave', 'peek', 'account', 'acc-1');
    -- the 'peek' cooldown gate (count_within 10m max 0) is still in place
    -- r_01: first reserve is allowed and inserts a `request` event with per-clause outcomes
    r := authz.reserve_event('test_gates', 'user', 'dave', 'peek', 'account', 'acc-1', '{"input": {"n": 1}}');
    PERFORM _test_assert('r_01_allowed', r ->> 'allowed', 'true');
    PERFORM _test_assert('r_01_kind_request', r ->> 'kind', 'request');
    PERFORM _test_assert('r_01_reason', r ->> 'reason', 'allowed');
    PERFORM _test_assert_true('r_01_seq_present', (r ->> 'seq') IS NOT NULL, r::text);
    PERFORM _test_assert('r_01_gate_outcomes', (r -> 'gates' -> 0 ->> 'reason') || ' ' || (r -> 'gates' -> 0 ->> 'observed'), 'gate_passed 0');
    SELECT kind INTO v_state FROM authz.list_events('test_gates', p_subject_type => 'user', p_subject_id => 'dave', p_action => 'peek') ORDER BY seq DESC LIMIT 1;
    PERFORM _test_assert('r_01_request_recorded', v_state, 'request');

    -- r_02: the second reserve is refused by the gate and records a `denied` event
    r := authz.reserve_event('test_gates', 'user', 'dave', 'peek', 'account', 'acc-1');
    PERFORM _test_assert('r_02_refused', r ->> 'allowed', 'false');
    PERFORM _test_assert('r_02_kind_denied', r ->> 'kind', 'denied');
    PERFORM _test_assert('r_02_reason_gate_denied', r ->> 'reason', 'gate_denied');
    PERFORM _test_assert('r_02_gate_outcome_denied', r -> 'gates' -> 0 ->> 'reason', 'gate_denied');
    SELECT count(*) INTO n FROM authz.list_events('test_gates', p_subject_type => 'user', p_subject_id => 'dave', p_action => 'peek', p_kind => 'denied');
    PERFORM _test_assert('r_02_denied_recorded', n::text, '1');
    -- r_03: p_record_denied => false leaves no trace of the refusal
    r := authz.reserve_event('test_gates', 'user', 'dave', 'peek', 'account', 'acc-1', p_record_denied => false);
    PERFORM _test_assert('r_03_refused_unrecorded_kind_null', (r ->> 'allowed') || ' ' || COALESCE(r ->> 'kind', 'null') || ' ' || COALESCE(r ->> 'seq', 'null'), 'false null null');
    SELECT count(*) INTO n FROM authz.list_events('test_gates', p_subject_type => 'user', p_subject_id => 'dave', p_action => 'peek', p_kind => 'denied');
    PERFORM _test_assert('r_03_no_new_denied', n::text, '1');

    -- r_04: a graph deny (no tuple) is refused with reason graph_denied and recorded as denied
    r := authz.reserve_event('test_gates', 'user', 'erin', 'peek', 'account', 'acc-1');
    PERFORM _test_assert('r_04_graph_denied', (r ->> 'allowed') || ' ' || (r ->> 'reason') || ' ' || (r ->> 'kind'), 'false graph_denied denied');
    PERFORM _test_assert('r_04_no_gate_outcomes', jsonb_array_length(r -> 'gates')::text, '0');

    -- r_05: idempotency follows record_event — event_id requires occurred_at; a re-delivered key is seq null
    PERFORM authz.write_tuple('test_gates', 'user', 'dave', 'transfer', 'account', 'acc-9');
    BEGIN
        PERFORM authz.reserve_event('test_gates', 'user', 'dave', 'transfer', 'account', 'acc-9', p_event_id => 'k1');
        PERFORM _test_assert_true('r_05_event_id_requires_occurred_at', false, 'no error');
    EXCEPTION WHEN invalid_parameter_value THEN
        PERFORM _test_assert_true('r_05_event_id_requires_occurred_at', true);
    END;
    r := authz.reserve_event('test_gates', 'user', 'dave', 'transfer', 'account', 'acc-9', p_event_id => 'k1', p_occurred_at => now() - interval '1 minute');
    -- (no gate remains on transfer at this point → the graph decides: allowed)
    PERFORM _test_assert('r_05_first_delivery_allowed_seq', (r ->> 'allowed') || ' ' || ((r ->> 'seq') IS NOT NULL)::text, 'true true');
    r := authz.reserve_event('test_gates', 'user', 'dave', 'transfer', 'account', 'acc-9', p_event_id => 'k1', p_occurred_at => now() - interval '1 minute');
    PERFORM _test_assert('r_05_redelivery_seq_null_decision_kept', (r ->> 'allowed') || ' ' || COALESCE(r ->> 'seq', 'null'), 'true null');

    -- r_06: object type/id are required
    BEGIN
        PERFORM authz.reserve_event('test_gates', 'user', 'dave', 'peek', NULL, NULL);
        PERFORM _test_assert_true('r_06_object_required', false, 'no error');
    EXCEPTION WHEN invalid_parameter_value THEN
        PERFORM _test_assert_true('r_06_object_required', true);
    END;
END;
$$;

SELECT * FROM _test_teardown_gates();

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_gates();
DROP FUNCTION IF EXISTS _test_setup_gates();

SELECT _test_report('temporal gate checks');
