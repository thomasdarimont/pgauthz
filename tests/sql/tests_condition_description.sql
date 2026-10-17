-- Condition description + timestamps (migration 0021): create_condition takes
-- p_description (NULL keeps, '' clears), a description-only change is a new
-- audit version and bumps updated_at, export carries it, apply propagates it.

SELECT _test_reset();

DO $$
BEGIN
    PERFORM authz.delete_store('test_cdesc', p_purge_audit => true);
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
SELECT authz.create_store('test_cdesc');
SELECT authz.model_register_type('test_cdesc', 'user');
SELECT authz.model_register_type('test_cdesc', 'doc');
SELECT authz.model_register_relation('test_cdesc', 'viewer');
SELECT authz.model_add_rule('test_cdesc', 'doc', 'viewer', 'direct');

DO $$
DECLARE
    v_id      integer;
    v_desc    text;
    v_created timestamptz;
    v_updated timestamptz;
    v_n       integer;
    v_def     jsonb;
BEGIN
    v_id := authz.create_condition('test_cdesc', 'in_hours', '($1->>''hour'')::int < 18', p_description => 'office hours only');
    SELECT description, created_at, updated_at INTO v_desc, v_created, v_updated FROM authz.conditions WHERE id = v_id;
    PERFORM _test_assert('cd_01_description_stored', v_desc, 'office hours only');
    PERFORM _test_assert_true('cd_02_timestamps_set', v_created IS NOT NULL AND v_updated = v_created, 'created/updated');

    -- identical re-run: no new audit version, nothing moves
    SELECT count(*) INTO v_n FROM authz.conditions_audit WHERE condition_id = v_id;
    PERFORM authz.create_condition('test_cdesc', 'in_hours', '($1->>''hour'')::int < 18', p_description => 'office hours only');
    PERFORM _test_assert('cd_03_rerun_is_noop',
        (SELECT count(*) FROM authz.conditions_audit WHERE condition_id = v_id)::text, v_n::text);

    -- NULL keeps the description; a description-only change is a version
    PERFORM authz.create_condition('test_cdesc', 'in_hours', '($1->>''hour'')::int < 18');
    PERFORM _test_assert('cd_04_null_keeps', (SELECT description FROM authz.conditions WHERE id = v_id), 'office hours only');
    PERFORM pg_sleep(0.01);
    PERFORM authz.create_condition('test_cdesc', 'in_hours', '($1->>''hour'')::int < 18', p_description => 'before six');
    PERFORM _test_assert('cd_05_description_change_is_version',
        (SELECT count(*) FROM authz.conditions_audit WHERE condition_id = v_id)::text, (v_n + 2)::text);  -- an UPDATE audits as DELETE + INSERT
    PERFORM _test_assert_true('cd_06_updated_at_bumped',
        (SELECT updated_at > created_at FROM authz.conditions WHERE id = v_id), 'updated_at');
    PERFORM _test_assert('cd_07_audit_carries_description',
        (SELECT description FROM authz.conditions_audit WHERE condition_id = v_id ORDER BY seq DESC LIMIT 1), 'before six');

    -- export carries it only when set; apply propagates it
    v_def := authz.export_model('test_cdesc');
    PERFORM _test_assert('cd_08_export_description',
        (SELECT x->>'description' FROM jsonb_array_elements(v_def->'conditions') x WHERE x->>'name' = 'in_hours'), 'before six');
    PERFORM authz.create_condition('test_cdesc', 'always', 'true');
    v_def := authz.export_model('test_cdesc');
    PERFORM _test_assert_true('cd_09_export_omits_unset',
        NOT ((SELECT x FROM jsonb_array_elements(v_def->'conditions') x WHERE x->>'name' = 'always') ? 'description'), 'no key');
    -- evaluate_condition: the verdict for mocked contexts, no tuple involved
    PERFORM authz.create_condition('test_cdesc', 'same_team', '($1->>''team'') = ($2->>''team'')', p_required_context => '{"request": ["team"], "stored": ["team"]}');
    PERFORM _test_assert('cd_11_evaluate_true',  authz.evaluate_condition('test_cdesc', 'same_team', '{"team": "a"}', '{"team": "a"}')::text, 'true');
    PERFORM _test_assert('cd_12_evaluate_false', authz.evaluate_condition('test_cdesc', 'same_team', '{"team": "a"}', '{"team": "b"}')::text, 'false');
    BEGIN
        PERFORM authz.evaluate_condition('test_cdesc', 'same_team', '{}', '{"team": "b"}');
        v_desc := 'no error';
    EXCEPTION WHEN OTHERS THEN v_desc := SQLERRM; END;
    PERFORM _test_assert_true('cd_13_evaluate_missing_keys', v_desc LIKE '%missing required context keys: request.team%', v_desc);
    -- a server-time condition takes current_time from the clock, as in a check
    PERFORM authz.create_condition('test_cdesc', 'fresh', '($1->>''current_time'')::timestamptz < ($2->>''until'')::timestamptz',
                                   p_required_context => '{"request": ["current_time"], "stored": ["until"]}', p_time_source => 'server');
    PERFORM _test_assert('cd_14_server_time_injected',
        authz.evaluate_condition('test_cdesc', 'fresh', '{}', jsonb_build_object('until', (now() + interval '1 hour')::text))::text, 'true');
    PERFORM _test_assert('cd_15_server_time_wins_over_caller',
        authz.evaluate_condition('test_cdesc', 'fresh', '{"current_time": "2000-01-01T00:00:00Z"}', jsonb_build_object('until', (now() - interval '1 hour')::text))::text, 'false');
    -- '' clears
    PERFORM authz.create_condition('test_cdesc', 'in_hours', '($1->>''hour'')::int < 18', p_description => '');
    PERFORM _test_assert_true('cd_10_empty_clears', (SELECT description IS NULL FROM authz.conditions WHERE id = v_id), 'cleared');
END $$;

SELECT _test_report('condition description');
