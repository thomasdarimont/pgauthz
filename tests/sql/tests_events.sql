-- Tests for the action log (ADR 0012, phase 1): authz.record_event /
-- record_events_jsonb (ingestion contract: vocabulary, bounds, idempotency,
-- roles, namespace isolation), authz.list_events (filters + keyset cursor),
-- append-only protection, partition maintenance/retention, store erasure.
--
-- Uses its own store 'test_events' and two throwaway NOLOGIN roles.

SELECT _test_reset();

DROP FUNCTION IF EXISTS _test_setup_events();
CREATE FUNCTION _test_setup_events() RETURNS void LANGUAGE plpgsql AS $$
DECLARE s integer;
BEGIN
    BEGIN PERFORM authz.delete_store('test_events'); EXCEPTION WHEN OTHERS THEN NULL; END;
    DROP TABLE IF EXISTS authz.events_2031_01;

    PERFORM authz.create_store('test_events');
    s := authz._s('test_events');
    INSERT INTO authz.types (store_id, name) VALUES (s, 'user'), (s, 'doc'), (s, 'account');
    -- 'doc' lives in the 'docs' namespace; 'account' is unnamespaced.
    UPDATE authz.types SET namespace = 'docs' WHERE store_id = s AND name = 'doc';
    -- The action vocabulary: declared relations (rules are not required).
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'download'), (s, 'approve'), (s, 'transfer');

    -- Per-app identities: a pure recorder and a writer.
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'test_ev_recorder') THEN
        CREATE ROLE test_ev_recorder NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'test_ev_writer') THEN
        CREATE ROLE test_ev_writer NOLOGIN;
    END IF;
    GRANT authz_recorder TO test_ev_recorder;
    GRANT authz_writer   TO test_ev_writer;
    GRANT test_ev_recorder TO authz;
    GRANT test_ev_writer   TO authz;
    -- Only the writer may manage (and therefore record about) the docs namespace.
    PERFORM authz.grant_namespace_access('test_events', 'docs', 'test_ev_writer',
                                         p_can_read := true, p_can_write := true);
END;
$$;

DROP FUNCTION IF EXISTS _test_teardown_events();
CREATE FUNCTION _test_teardown_events() RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    BEGIN PERFORM authz.delete_store('test_events'); EXCEPTION WHEN OTHERS THEN NULL; END;
    DROP TABLE IF EXISTS authz.events_2031_01;
    DROP ROLE IF EXISTS test_ev_recorder;
    DROP ROLE IF EXISTS test_ev_writer;
    RETURN QUERY DELETE FROM _test_results RETURNING *;
END;
$$;

SELECT _test_setup_events();

-- ================================================================
-- Recording: basics, attribution, idempotency
-- ================================================================
DO $$
DECLARE v_seq bigint; v_seq2 bigint; r record; n int;
BEGIN
    -- ev_01: a recorded event returns its seq; occurred_at defaults to the DB clock
    v_seq := authz.record_event('test_events', 'user', 'alice', 'download', 'account', 'acc-1',
                                'request', '{"input": {"bytes": 42}}');
    PERFORM _test_assert_true('ev_01_record_returns_seq', v_seq IS NOT NULL AND v_seq > 0, v_seq::text);

    SELECT * INTO r FROM authz.list_events('test_events') WHERE seq = v_seq;
    PERFORM _test_assert('ev_02_names_resolved',
        r.subject_type || ':' || r.subject_id || ' ' || r.action || ' ' || r.object_type || ':' || r.object_id || ' ' || r.kind,
        'user:alice download account:acc-1 request');
    PERFORM _test_assert('ev_02_occurred_at_defaults_to_recorded_at', (r.occurred_at = r.recorded_at)::text, 'true');
    PERFORM _test_assert('ev_02_payload_as_is', r.payload::text, '{"input": {"bytes": 42}}');
    PERFORM _test_assert('ev_02_recorded_by_falls_back_to_effective_role', r.recorded_by, session_user::text);

    -- ev_03: an explicit recorded_by is stored
    v_seq := authz.record_event('test_events', 'user', 'alice', 'download', p_recorded_by => 'svc:files');
    SELECT recorded_by INTO r FROM authz.list_events('test_events') WHERE seq = v_seq;
    PERFORM _test_assert('ev_03_recorded_by_explicit', r.recorded_by, 'svc:files');

    -- ev_04: idempotency — the same event_id is recorded once; the retry returns NULL
    v_seq  := authz.record_event('test_events', 'user', 'bob', 'download', p_event_id => 'req-1/request', p_occurred_at => now() - interval '1 minute');
    v_seq2 := authz.record_event('test_events', 'user', 'bob', 'download', p_event_id => 'req-1/request', p_occurred_at => now() - interval '1 minute');
    SELECT count(*) INTO n FROM authz.list_events('test_events', p_subject_type => 'user', p_subject_id => 'bob');
    PERFORM _test_assert_true('ev_04_duplicate_returns_null', v_seq IS NOT NULL AND v_seq2 IS NULL,
        format('first=%s second=%s', v_seq, v_seq2));
    PERFORM _test_assert('ev_04_duplicate_not_inserted', n::text, '1');

    -- ev_04b: the kind is part of the key by convention (request/response pairs)
    v_seq2 := authz.record_event('test_events', 'user', 'bob', 'download', p_kind => 'response',
                                 p_event_id => 'req-1/response', p_occurred_at => now() - interval '1 minute');
    PERFORM _test_assert_true('ev_04b_distinct_key_records', v_seq2 IS NOT NULL, v_seq2::text);

    -- ev_04c: an idempotency key without the message timestamp cannot be stable → rejected
    BEGIN
        PERFORM authz.record_event('test_events', 'user', 'bob', 'download', p_event_id => 'req-2/request');
        PERFORM _test_assert_true('ev_04c_event_id_requires_occurred_at', false, 'no error raised');
    EXCEPTION WHEN invalid_parameter_value THEN
        PERFORM _test_assert_true('ev_04c_event_id_requires_occurred_at', true);
    END;
END;
$$;

-- ev_05: batch form — counts, positional seqs, duplicates reported not inflated
DO $$
DECLARE v_out jsonb; n int;
BEGIN
    v_out := authz.record_events_jsonb('test_events', ('[
        {"subject_type": "user", "subject_id": "carol", "action": "transfer", "object_type": "account", "object_id": "acc-9",
         "kind": "request", "payload": {"input": {"amount": 1200}}, "event_id": "tx-1/request", "occurred_at": "' || (now() - interval '30 seconds')::text || '"},
        {"subject_type": "user", "subject_id": "carol", "action": "transfer", "event_id": "tx-1/request", "occurred_at": "' || (now() - interval '30 seconds')::text || '"},
        {"subject_type": "user", "subject_id": "carol", "action": "transfer", "object_type": "account", "object_id": "acc-9",
         "kind": "response", "payload": {"output": {"status": "ok"}}, "event_id": "tx-1/response", "occurred_at": "' || (now() - interval '29 seconds')::text || '"}
    ]')::jsonb, 'svc:bank');
    PERFORM _test_assert('ev_05_batch_recorded',   v_out ->> 'recorded',   '2');
    PERFORM _test_assert('ev_05_batch_duplicates', v_out ->> 'duplicates', '1');
    PERFORM _test_assert('ev_05_batch_seqs_positional',
        (jsonb_array_length(v_out -> 'seqs') = 3
         AND jsonb_typeof(v_out -> 'seqs' -> 0) = 'number'
         AND jsonb_typeof(v_out -> 'seqs' -> 1) = 'null'
         AND jsonb_typeof(v_out -> 'seqs' -> 2) = 'number')::text, 'true');
    SELECT count(*) INTO n FROM authz.list_events('test_events', p_subject_type => 'user', p_subject_id => 'carol', p_recorded_by => 'svc:bank');
    PERFORM _test_assert('ev_05_batch_rows', n::text, '2');
END;
$$;

-- ================================================================
-- Validation: vocabulary, kinds, bounds, payload, shape
-- ================================================================
DO $$
DECLARE v_err text; v_state text; v_seq bigint;
BEGIN
    -- ev_06: an undeclared action fails loud (the model is the action vocabulary)
    v_err := NULL;
    BEGIN
        PERFORM authz.record_event('test_events', 'user', 'alice', 'downlaod');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ev_06_unknown_action_raises', v_err LIKE '%Unknown relation%', coalesce(v_err, 'no error'));

    -- ev_07: an unknown kind is a caller error (invalid_parameter_value)
    v_state := NULL;
    BEGIN
        PERFORM authz.record_event('test_events', 'user', 'alice', 'download', p_kind => 'started');
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('ev_07_unknown_kind_is_22023', v_state, '22023');

    -- ev_08: occurred_at bounded in the future (default skew 5s)
    v_state := NULL;
    BEGIN
        PERFORM authz.record_event('test_events', 'user', 'alice', 'download', p_occurred_at => now() + interval '1 hour');
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('ev_08_future_beyond_skew_rejected', v_state, '22023');
    v_seq := authz.record_event('test_events', 'user', 'alice', 'download', p_occurred_at => now() + interval '2 seconds');
    PERFORM _test_assert_true('ev_08_future_within_skew_ok', v_seq IS NOT NULL);

    -- ev_09: occurred_at bounded in the past (default backdate 24h), GUC-tunable
    v_state := NULL;
    BEGIN
        PERFORM authz.record_event('test_events', 'user', 'alice', 'download', p_occurred_at => now() - interval '2 days');
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('ev_09_backdate_beyond_limit_rejected', v_state, '22023');
    PERFORM set_config('authz.event_max_backdate', '72 hours', true);
    v_seq := authz.record_event('test_events', 'user', 'alice', 'download', p_occurred_at => now() - interval '2 days');
    PERFORM _test_assert_true('ev_09_backdate_within_raised_limit_ok', v_seq IS NOT NULL);
    PERFORM set_config('authz.event_max_backdate', '', true);

    -- ev_10: payload must be an object and is size-bounded (F5)
    v_state := NULL;
    BEGIN
        PERFORM authz.record_event('test_events', 'user', 'alice', 'download', p_payload => '[1,2]'::jsonb);
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('ev_10_payload_array_rejected', v_state, '22023');
    v_state := NULL;
    PERFORM set_config('authz.max_context_bytes', '64', true);
    BEGIN
        PERFORM authz.record_event('test_events', 'user', 'alice', 'download',
            p_payload => jsonb_build_object('blob', repeat('x', 200)));
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM set_config('authz.max_context_bytes', '', true);
    PERFORM _test_assert('ev_10_payload_oversize_is_program_limit', v_state, '54000');

    -- ev_11: concrete principals only; object_id needs object_type
    v_state := NULL;
    BEGIN
        PERFORM authz.record_event('test_events', 'user', '*', 'download');
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('ev_11_wildcard_subject_rejected', v_state, '22023');
    v_state := NULL;
    BEGIN
        PERFORM authz.record_event('test_events', 'user', 'alice', 'download', p_object_id => 'acc-1');
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('ev_11_object_id_without_type_rejected', v_state, '22023');
END;
$$;

-- ev_12: batch shape validation and atomicity
DO $$
DECLARE v_state text; v_err text; n_before int; n_after int;
BEGIN
    v_state := NULL;
    BEGIN PERFORM authz.record_events_jsonb('test_events', '{"not": "an array"}'::jsonb);
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('ev_12_batch_not_array_rejected', v_state, '22023');

    v_err := NULL;
    BEGIN PERFORM authz.record_events_jsonb('test_events', '[{"subject_type": "user", "action": "download"}]'::jsonb);
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ev_12_batch_missing_key_names_it', v_err LIKE '%events[0]%subject_id%', coalesce(v_err, 'no error'));

    v_err := NULL;
    BEGIN PERFORM authz.record_events_jsonb('test_events',
        '[{"subject_type": "user", "subject_id": "a", "action": "download", "kindd": "request"}]'::jsonb);
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ev_12_batch_unknown_key_rejected', v_err LIKE '%unknown key "kindd"%', coalesce(v_err, 'no error'));

    -- Atomic: a bad second element means the good first one is not recorded either.
    SELECT count(*) INTO n_before FROM authz.list_events('test_events', p_subject_type => 'user', p_subject_id => 'atomic');
    BEGIN PERFORM authz.record_events_jsonb('test_events', '[
        {"subject_type": "user", "subject_id": "atomic", "action": "download"},
        {"subject_type": "user", "subject_id": "atomic", "action": "nope"}
    ]'::jsonb);
    EXCEPTION WHEN OTHERS THEN NULL; END;
    SELECT count(*) INTO n_after FROM authz.list_events('test_events', p_subject_type => 'user', p_subject_id => 'atomic');
    PERFORM _test_assert('ev_12_batch_is_atomic', (n_after - n_before)::text, '0');
END;
$$;

-- ================================================================
-- Roles and namespace isolation (per-app identity via SET ROLE)
-- ================================================================
DO $$
DECLARE v_seq bigint; v_err text; r record;
BEGIN
    -- ev_13: a pure recorder can record (unnamespaced object) but cannot write tuples
    PERFORM set_config('role', 'test_ev_recorder', true);
    v_seq := authz.record_event('test_events', 'user', 'alice', 'transfer', 'account', 'acc-1');
    RESET ROLE;
    PERFORM _test_assert_true('ev_13_recorder_can_record', v_seq IS NOT NULL);
    SELECT recorded_by INTO r FROM authz.list_events('test_events') WHERE seq = v_seq;
    PERFORM _test_assert('ev_13_recorded_by_is_effective_role', r.recorded_by, 'test_ev_recorder');

    PERFORM set_config('role', 'test_ev_recorder', true);
    v_err := NULL;
    BEGIN
        PERFORM authz.write_tuple('test_events', 'user', 'alice', 'download', 'account', 'acc-1');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    RESET ROLE;
    PERFORM _test_assert_true('ev_13_recorder_cannot_write_tuples', v_err LIKE '%permission denied%', coalesce(v_err, 'no error'));

    -- ev_13b: a plain reader cannot record
    PERFORM set_config('role', 'authz_reader', true);
    v_err := NULL;
    BEGIN
        PERFORM authz.record_event('test_events', 'user', 'alice', 'transfer');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    RESET ROLE;
    PERFORM _test_assert_true('ev_13b_reader_cannot_record', v_err LIKE '%permission denied%', coalesce(v_err, 'no error'));

    -- ev_13c: a writer inherits the recorder capability
    PERFORM set_config('role', 'test_ev_writer', true);
    v_seq := authz.record_event('test_events', 'user', 'alice', 'transfer', 'account', 'acc-1');
    RESET ROLE;
    PERFORM _test_assert_true('ev_13c_writer_can_record', v_seq IS NOT NULL);

    -- ev_14: namespace isolation — recording ABOUT a namespaced object type needs can_write
    PERFORM set_config('role', 'test_ev_recorder', true);
    v_err := NULL;
    BEGIN
        PERFORM authz.record_event('test_events', 'user', 'alice', 'download', 'doc', 'doc-1');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    RESET ROLE;
    PERFORM _test_assert_true('ev_14_namespace_denied_without_grant',
        v_err LIKE '%Permission denied%namespace%', coalesce(v_err, 'no error'));

    PERFORM set_config('role', 'test_ev_recorder', true);
    v_seq := authz.record_event('test_events', 'user', 'alice', 'download');   -- object-less: no namespace
    RESET ROLE;
    PERFORM _test_assert_true('ev_14_objectless_event_unrestricted', v_seq IS NOT NULL);

    PERFORM set_config('role', 'test_ev_writer', true);
    v_seq := authz.record_event('test_events', 'user', 'alice', 'download', 'doc', 'doc-1');
    RESET ROLE;
    PERFORM _test_assert_true('ev_14_namespace_allowed_with_grant', v_seq IS NOT NULL);
END;
$$;

-- ================================================================
-- Per-recorder action allowlists (migration 0013)
-- ================================================================
DO $$
DECLARE v_seq bigint; v_err text; n int; r jsonb;
BEGIN
    -- ev_20: no allowlist → unrestricted (the recorder records any declared action)
    PERFORM set_config('role', 'test_ev_recorder', true);
    v_seq := authz.record_event('test_events', 'user', 'alice', 'approve');
    RESET ROLE;
    PERFORM _test_assert_true('ev_20_no_allowlist_unrestricted', v_seq IS NOT NULL);

    -- ev_21: grant an allowlist → only listed actions; unknown actions fail loud at grant time
    PERFORM _test_assert('ev_21_grant_returns_rows',
        authz.grant_recorder_actions('test_events', 'test_ev_recorder', ARRAY['download', 'transfer'])::text, '2');
    PERFORM _test_assert('ev_21_grant_idempotent',
        authz.grant_recorder_actions('test_events', 'test_ev_recorder', ARRAY['download'])::text, '0');
    v_err := NULL;
    BEGIN PERFORM authz.grant_recorder_actions('test_events', 'test_ev_recorder', ARRAY['nope']);
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ev_21_grant_unknown_action_raises', v_err LIKE '%Unknown relation%', coalesce(v_err, 'no error'));

    PERFORM set_config('role', 'test_ev_recorder', true);
    v_seq := authz.record_event('test_events', 'user', 'alice', 'download');
    v_err := NULL;
    BEGIN PERFORM authz.record_event('test_events', 'user', 'alice', 'approve');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    RESET ROLE;
    PERFORM _test_assert_true('ev_21_listed_action_allowed', v_seq IS NOT NULL);
    PERFORM _test_assert_true('ev_21_unlisted_action_denied',
        v_err LIKE '%Permission denied%may not record action "approve"%', coalesce(v_err, 'no error'));
    -- the batch form fails atomically on the unlisted element
    PERFORM set_config('role', 'test_ev_recorder', true);
    v_err := NULL;
    BEGIN PERFORM authz.record_events_jsonb('test_events', '[
        {"subject_type": "user", "subject_id": "alice", "action": "download"},
        {"subject_type": "user", "subject_id": "alice", "action": "approve"}]'::jsonb);
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    RESET ROLE;
    PERFORM _test_assert_true('ev_21_batch_denied_atomically', v_err LIKE '%Permission denied%', coalesce(v_err, 'no error'));

    -- ev_22: a role without rows stays unrestricted (the writer)
    PERFORM set_config('role', 'test_ev_writer', true);
    v_seq := authz.record_event('test_events', 'user', 'alice', 'approve');
    RESET ROLE;
    PERFORM _test_assert_true('ev_22_other_role_unrestricted', v_seq IS NOT NULL);

    -- ev_23: reserve_event inherits the allowlist (it records through record_event)
    PERFORM authz.model_add_rule('test_events', 'account', 'approve', 'direct');
    PERFORM authz.write_tuple('test_events', 'user', 'alice', 'approve', 'account', 'acc-1');
    PERFORM set_config('role', 'test_ev_recorder', true);
    v_err := NULL;
    BEGIN PERFORM authz.reserve_event('test_events', 'user', 'alice', 'approve', 'account', 'acc-1');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    RESET ROLE;
    PERFORM _test_assert_true('ev_23_reserve_inherits_allowlist', v_err LIKE '%Permission denied%may not record action%', coalesce(v_err, 'no error'));

    -- ev_24: revoke one action, then the whole list → unrestricted again
    PERFORM _test_assert('ev_24_revoke_one', authz.revoke_recorder_actions('test_events', 'test_ev_recorder', ARRAY['transfer'])::text, '1');
    PERFORM set_config('role', 'test_ev_recorder', true);
    v_err := NULL;
    BEGIN PERFORM authz.record_event('test_events', 'user', 'alice', 'transfer');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    RESET ROLE;
    PERFORM _test_assert_true('ev_24_revoked_action_denied', v_err LIKE '%Permission denied%', coalesce(v_err, 'no error'));
    PERFORM _test_assert('ev_24_revoke_all', authz.revoke_recorder_actions('test_events', 'test_ev_recorder')::text, '1');
    PERFORM set_config('role', 'test_ev_recorder', true);
    v_seq := authz.record_event('test_events', 'user', 'alice', 'approve');
    RESET ROLE;
    PERFORM _test_assert_true('ev_24_unrestricted_after_revoke_all', v_seq IS NOT NULL);
    -- leave a row behind so ev_19 proves delete_store purges it
    PERFORM authz.grant_recorder_actions('test_events', 'test_ev_recorder', ARRAY['download']);
END;
$$;

-- ================================================================
-- Payload schemas (migration 0014): declared shape enforced at record time
-- ================================================================
DO $$
DECLARE v_seq bigint; v_err text; v_state text; v_bad text[]; v_spec text; n int;
BEGIN
    -- own store: the allowlist rows and event counts of test_events stay untouched
    PERFORM authz.create_store('test_events_ps');
    PERFORM authz.model_register_type('test_events_ps', 'user');
    PERFORM authz.model_register_relation('test_events_ps', 'transfer');
    -- ps_01: no schema → any object payload (today's behaviour)
    v_seq := authz.record_event('test_events_ps', 'user', 'alice', 'transfer', p_payload => '{"whatever": 1}');
    PERFORM _test_assert_true('ps_01_no_schema_accepts_anything', v_seq IS NOT NULL);

    -- ps_02: declare a schema on transfer
    PERFORM _test_assert('ps_02_set_schema_changed', authz.model_set_payload_schema('test_events_ps', 'transfer', '{
        "required": {"input.amount": "number", "input.currency": "string"},
        "optional": {"input.memo": "string", "input.meta": "object"},
        "kinds": {"response": {"required": {"output.status": "string"}}}}')::text, 'true');
    PERFORM _test_assert('ps_02_set_same_schema_noop', authz.model_set_payload_schema('test_events_ps', 'transfer', '{
        "required": {"input.amount": "number", "input.currency": "string"},
        "optional": {"input.memo": "string", "input.meta": "object"},
        "kinds": {"response": {"required": {"output.status": "string"}}}}')::text, 'false');

    -- ps_03: conforming payloads record; violations are 22023 naming the field
    v_seq := authz.record_event('test_events_ps', 'user', 'alice', 'transfer', p_payload => '{"input": {"amount": 12.5, "currency": "EUR", "extra": true}}');
    PERFORM _test_assert_true('ps_03_conforming_request_recorded', v_seq IS NOT NULL);
    v_seq := authz.record_event('test_events_ps', 'user', 'alice', 'transfer', p_kind => 'response',
        p_payload => '{"input": {"amount": 12.5, "currency": "EUR"}, "output": {"status": "ok"}}');
    PERFORM _test_assert_true('ps_03_conforming_response_recorded', v_seq IS NOT NULL);
    v_err := NULL; v_state := NULL;
    BEGIN PERFORM authz.record_event('test_events_ps', 'user', 'alice', 'transfer', p_payload => '{"input": {"currency": "EUR"}}');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('ps_03_missing_required_is_22023', v_state, '22023');
    PERFORM _test_assert_true('ps_03_missing_required_named', v_err LIKE '%missing required input.amount (number)%', coalesce(v_err, 'no error'));
    v_err := NULL;
    BEGIN PERFORM authz.record_event('test_events_ps', 'user', 'alice', 'transfer', p_payload => '{"input": {"amount": "12", "currency": "EUR"}}');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ps_03_wrong_type_named', v_err LIKE '%input.amount must be number (got string)%', coalesce(v_err, 'no error'));
    v_err := NULL;
    BEGIN PERFORM authz.record_event('test_events_ps', 'user', 'alice', 'transfer', p_kind => 'response',
        p_payload => '{"input": {"amount": 1, "currency": "EUR"}}');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ps_03_kind_specific_required', v_err LIKE '%missing required output.status%', coalesce(v_err, 'no error'));
    -- the request kind does not need output.status
    v_seq := authz.record_event('test_events_ps', 'user', 'alice', 'transfer', p_payload => '{"input": {"amount": 1, "currency": "EUR", "memo": "x"}}');
    PERFORM _test_assert_true('ps_03_kind_section_scoped', v_seq IS NOT NULL);

    -- ps_04: closed shape (additional: false) — undeclared leaves rejected, declared object subtrees allowed
    PERFORM authz.model_set_payload_schema('test_events_ps', 'transfer', '{
        "required": {"input.amount": "number"}, "optional": {"input.meta": "object"}, "additional": false}');
    v_err := NULL;
    BEGIN PERFORM authz.record_event('test_events_ps', 'user', 'alice', 'transfer', p_payload => '{"input": {"amount": 1, "rogue": 2}}');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ps_04_closed_rejects_undeclared', v_err LIKE '%undeclared field input.rogue%', coalesce(v_err, 'no error'));
    v_seq := authz.record_event('test_events_ps', 'user', 'alice', 'transfer', p_payload => '{"input": {"amount": 1, "meta": {"a": {"b": 1}}}}');
    PERFORM _test_assert_true('ps_04_declared_object_subtree_allowed', v_seq IS NOT NULL);

    -- ps_05: batches stay atomic under schema violations
    SELECT count(*) INTO n FROM authz.list_events('test_events_ps', p_subject_type => 'user', p_subject_id => 'schema_batch');
    BEGIN PERFORM authz.record_events_jsonb('test_events_ps', '[
        {"subject_type": "user", "subject_id": "schema_batch", "action": "transfer", "payload": {"input": {"amount": 1}}},
        {"subject_type": "user", "subject_id": "schema_batch", "action": "transfer", "payload": {"input": {"amount": "x"}}}]'::jsonb);
    EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM _test_assert('ps_05_batch_atomic',
        ((SELECT count(*) FROM authz.list_events('test_events_ps', p_subject_type => 'user', p_subject_id => 'schema_batch')) - n)::text, '0');

    -- ps_06: schema validation
    v_bad := ARRAY[
        '{"required": {"input.amount": "integer"}}',
        '{"required": {"input[0]": "number"}}',
        '{"required": "input.amount"}',
        '{"nope": {}}',
        '{"kinds": {"started": {"required": {"a": "string"}}}}',
        '{"kinds": {"response": {"extra": {}}}}',
        '{"additional": "no"}',
        '[]'
    ];
    n := 0;
    FOREACH v_spec IN ARRAY v_bad LOOP
        v_state := NULL;
        BEGIN PERFORM authz.model_set_payload_schema('test_events_ps', 'transfer', v_spec::jsonb);
        EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
        IF v_state = '22023' THEN n := n + 1; ELSE RAISE NOTICE 'ps_06: % → %', v_spec, coalesce(v_state, 'accepted'); END IF;
    END LOOP;
    PERFORM _test_assert('ps_06_invalid_schemas_rejected', n::text, array_length(v_bad, 1)::text);

    -- ps_07: describe renders it; NULL clears it and anything records again
    PERFORM _test_assert_true('ps_07_describe_renders_schema',
        position('# payload schema transfer: ' in authz.describe_model('test_events_ps')) > 0);
    PERFORM _test_assert('ps_07_clear', authz.model_set_payload_schema('test_events_ps', 'transfer', NULL)::text, 'true');
    v_seq := authz.record_event('test_events_ps', 'user', 'alice', 'transfer', p_payload => '{"anything": "goes"}');
    PERFORM _test_assert_true('ps_07_cleared_accepts_anything', v_seq IS NOT NULL);
    PERFORM authz.delete_store('test_events_ps');
END;
$$;

-- ================================================================
-- list_events: filters and keyset pagination
-- ================================================================
DO $$
DECLARE n int; v_at timestamptz; v_seq bigint; v_first bigint; v_page2_first bigint; v_total int;
BEGIN
    SELECT count(*) INTO n FROM authz.list_events('test_events', p_action => 'transfer', p_kind => 'response');
    PERFORM _test_assert('ev_15_filter_action_kind', n::text, '1');
    SELECT count(*) INTO n FROM authz.list_events('test_events', p_object_type => 'account', p_object_id => 'acc-9');
    PERFORM _test_assert('ev_15_filter_object', n::text, '2');
    SELECT count(*) INTO n FROM authz.list_events('test_events', p_subject_type => 'user', p_subject_id => 'carol');
    PERFORM _test_assert('ev_15_filter_subject', n::text, '2');
    BEGIN
        PERFORM count(*) FROM authz.list_events('test_events', p_subject_id => 'carol');
        PERFORM _test_assert_true('ev_15_subject_id_requires_type', false, 'no error');
    EXCEPTION WHEN invalid_parameter_value THEN
        PERFORM _test_assert_true('ev_15_subject_id_requires_type', true);
    END;
    SELECT count(*) INTO n FROM authz.list_events('test_events', p_action => 'no_such_action');
    PERFORM _test_assert('ev_15_unknown_filter_name_is_empty_not_error', n::text, '0');
    SELECT count(*) INTO n FROM authz.list_events('test_events', p_kind => 'bogus');
    PERFORM _test_assert('ev_15_unknown_kind_filter_is_empty', n::text, '0');
    SELECT count(*) INTO n FROM authz.list_events('test_events', p_since => now() - interval '1 hour');
    SELECT count(*) INTO v_total FROM authz.list_events('test_events');
    PERFORM _test_assert('ev_15_since_excludes_backdated', (n = v_total - 1)::text, 'true');
    SELECT count(*) INTO n FROM authz.list_events('test_events', p_until => now() - interval '1 day');
    PERFORM _test_assert('ev_15_until_selects_backdated_only', n::text, '1');

    -- ev_16: keyset cursor — ascending, no overlap, no gap
    SELECT count(*) INTO v_total FROM authz.list_events('test_events');
    SELECT seq INTO v_first FROM authz.list_events('test_events', p_limit => 1);
    SELECT occurred_at, seq INTO v_at, v_seq
      FROM authz.list_events('test_events', p_limit => 3) ORDER BY occurred_at DESC, seq DESC LIMIT 1;
    SELECT count(*) INTO n FROM authz.list_events('test_events', p_after_at => v_at, p_after_seq => v_seq);
    PERFORM _test_assert('ev_16_cursor_page2_count', n::text, (v_total - 3)::text);
    SELECT seq INTO v_page2_first FROM authz.list_events('test_events', p_after_at => v_at, p_after_seq => v_seq, p_limit => 1);
    PERFORM _test_assert_true('ev_16_cursor_no_overlap',
        v_page2_first NOT IN (SELECT seq FROM authz.list_events('test_events', p_limit => 3)));
    PERFORM _test_assert_true('ev_16_ascending',
        (SELECT bool_and(occurred_at <= lead_at) FROM (
            SELECT occurred_at, lead(occurred_at) OVER (ORDER BY occurred_at, seq) AS lead_at
              FROM authz.list_events('test_events')) x WHERE lead_at IS NOT NULL));
    PERFORM _test_assert('ev_16_limit_zero_is_empty',
        (SELECT count(*) FROM authz.list_events('test_events', p_limit => 0))::text, '0');
END;
$$;

-- ================================================================
-- Append-only, partitions, retention, erasure
-- ================================================================
DO $$
DECLARE v_err text; v_seq bigint; v_rel text; n int;
BEGIN
    -- ev_17: the log is append-only
    v_err := NULL;
    BEGIN UPDATE authz.events SET subject_id = 'mallory' WHERE store_id = authz._s('test_events');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ev_17_update_blocked', v_err LIKE '%append-only%', coalesce(v_err, 'no error'));
    v_err := NULL;
    BEGIN DELETE FROM authz.events WHERE store_id = authz._s('test_events');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('ev_17_delete_blocked', v_err LIKE '%append-only%', coalesce(v_err, 'no error'));

    -- ev_18: a row for a month without a partition lands in the default partition,
    -- _ensure_event_partition moves it (seq preserved), retention drops the month.
    PERFORM set_config('authz.event_max_future_skew', '100 years', true);
    v_seq := authz.record_event('test_events', 'user', 'zed', 'download', p_occurred_at => '2031-01-15 12:00:00+00');
    PERFORM set_config('authz.event_max_future_skew', '', true);
    SELECT c.relname INTO v_rel FROM authz.events e JOIN pg_catalog.pg_class c ON c.oid = e.tableoid WHERE e.seq = v_seq;
    PERFORM _test_assert('ev_18_row_in_default_partition', v_rel, 'events_default');
    PERFORM _test_assert('ev_18_partition_created', authz._ensure_event_partition(2031, 1)::text, 'true');
    PERFORM _test_assert('ev_18_partition_idempotent', authz._ensure_event_partition(2031, 1)::text, 'false');
    SELECT c.relname INTO v_rel FROM authz.events e JOIN pg_catalog.pg_class c ON c.oid = e.tableoid WHERE e.seq = v_seq;
    PERFORM _test_assert('ev_18_row_moved_seq_preserved', v_rel, 'events_2031_01');
    -- A cutoff inside the month keeps it (its rows are not all older); note the
    -- same call legitimately drops the (older, empty) current-month partitions
    -- init created — retention is by age, and ensure_event_partitions below
    -- recreates them.
    -- p_force: the fleet has live gates (the gdrive fixture) whose windows the
    -- future cutoff would truncate — the guard is tested in tests_gates.sql.
    PERFORM authz.drop_event_partitions_before('2031-01-20', p_force => true);
    PERFORM _test_assert('ev_18_retention_keeps_partial_month',
        (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace ns ON ns.oid = c.relnamespace
          WHERE ns.nspname = 'authz' AND c.relname = 'events_2031_01')::text, '1');
    PERFORM _test_assert('ev_18_retention_drops_completed_month', authz.drop_event_partitions_before('2031-02-01', p_force => true)::text, '1');
    PERFORM _test_assert('ev_18_partition_gone',
        (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace ns ON ns.oid = c.relnamespace
          WHERE ns.nspname = 'authz' AND c.relname = 'events_2031_01')::text, '0');
    SELECT count(*) INTO n FROM authz.list_events('test_events', p_subject_type => 'user', p_subject_id => 'zed');
    PERFORM _test_assert('ev_18_dropped_rows_gone', n::text, '0');
    PERFORM _test_assert_true('ev_18_ensure_current_months_recreates', authz.ensure_event_partitions(1) >= 1);
END;
$$;

-- ev_25: per-store retention — purge_events deletes only this store's rows older than p_before
DO $$
DECLARE n_before int; n_after int; n_old int; v_seq bigint; v_state text;
BEGIN
    -- a second store must be untouched by the purge
    BEGIN PERFORM authz.delete_store('test_events_other', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_events_other');
    PERFORM authz.model_register_type('test_events_other', 'user');
    PERFORM authz.model_register_relation('test_events_other', 'download');
    PERFORM set_config('authz.event_max_backdate', '72 hours', true);
    PERFORM authz.record_event('test_events_other', 'user', 'x', 'download', p_occurred_at => now() - interval '2 days');
    PERFORM authz.record_event('test_events', 'user', 'purge_me', 'download', p_occurred_at => now() - interval '2 days');
    PERFORM authz.record_event('test_events', 'user', 'purge_me', 'download', p_occurred_at => now() - interval '40 hours');
    v_seq := authz.record_event('test_events', 'user', 'purge_me', 'download');   -- recent, must survive
    PERFORM set_config('authz.event_max_backdate', '', true);

    SELECT count(*) INTO n_before FROM authz.list_events('test_events');
    PERFORM _test_assert('ev_25_purge_returns_count',
        authz.purge_events('test_events', now() - interval '1 day')::text, '2');   -- (ev_18's partition drop already removed ev_09's backdated row)
    SELECT count(*) INTO n_after FROM authz.list_events('test_events');
    PERFORM _test_assert('ev_25_only_old_rows_gone', (n_before - n_after)::text, '2');
    PERFORM _test_assert('ev_25_recent_row_survives',
        (SELECT count(*) FROM authz.list_events('test_events', p_subject_type => 'user', p_subject_id => 'purge_me'))::text, '1');
    PERFORM _test_assert('ev_25_other_store_untouched',
        (SELECT count(*) FROM authz.list_events('test_events_other'))::text, '1');
    PERFORM _test_assert('ev_25_idempotent', authz.purge_events('test_events', now() - interval '1 day')::text, '0');
    -- append-only protection still holds outside the sanctioned window
    v_state := NULL;
    BEGIN DELETE FROM authz.events WHERE subject_id = 'purge_me';
    EXCEPTION WHEN OTHERS THEN v_state := SQLERRM; END;
    PERFORM _test_assert_true('ev_25_direct_delete_still_blocked', v_state LIKE '%append-only%', coalesce(v_state, 'no error'));
    PERFORM authz.delete_store('test_events_other', p_purge_audit => true);
END;
$$;

-- ev_19: delete_store erases the store's events (FKs would otherwise block it)
DO $$
DECLARE s integer := authz._s('test_events'); n int; v_err text;
BEGIN
    v_err := NULL;
    BEGIN PERFORM authz.delete_store('test_events'); EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('ev_19_delete_store_succeeds', coalesce(v_err, 'ok'), 'ok');
    SELECT count(*) INTO n FROM authz.events WHERE store_id = s;
    PERFORM _test_assert('ev_19_events_purged', n::text, '0');
    SELECT count(*) INTO n FROM authz.recorder_actions WHERE store_id = s;
    PERFORM _test_assert('ev_19_recorder_allowlist_purged', n::text, '0');
END;
$$;

SELECT * FROM _test_teardown_events();

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_events();
DROP FUNCTION IF EXISTS _test_setup_events();

SELECT _test_report('action log (events) checks');
