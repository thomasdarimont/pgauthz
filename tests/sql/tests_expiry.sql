-- Tests for native relationship expiration (tuples.expires_at).
--
-- Enforcement is STRUCTURAL: row-level security on authz.tuples hides
-- expired rows from every read path (FORCE = also inside the SECURITY
-- DEFINER engine). Server time decides. Time-travel compares expires_at
-- against the asked timestamp, not now().

SELECT _test_reset();

DO $$
BEGIN
    BEGIN PERFORM authz.delete_store('test_exp'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_exp');
    PERFORM authz.model_register_type('test_exp', 'user');
    PERFORM authz.model_register_type('test_exp', 'grp');
    PERFORM authz.model_register_type('test_exp', 'doc');
    PERFORM authz.model_register_relation('test_exp', 'member');
    PERFORM authz.model_register_relation('test_exp', 'viewer');
    PERFORM authz.model_register_relation('test_exp', 'can_read');
    PERFORM authz.model_add_rule('test_exp', 'grp', 'member', 'direct');
    PERFORM authz.model_add_rule('test_exp', 'doc', 'viewer', 'direct');
    PERFORM authz.model_add_rule('test_exp', 'doc', 'can_read', 'computed',
        p_computed_relation => 'viewer');
END;
$$;

-- Helper: backdate a tuple's expiry (superuser bypasses RLS) — simulates
-- time passing without sleeping.
CREATE FUNCTION pg_temp._expire(p_user text) RETURNS void LANGUAGE sql AS $fn$
    UPDATE authz.tuples SET expires_at = now() - interval '1 second'
     WHERE store_id = authz._s('test_exp') AND user_id = p_user;
$fn$;

DO $$
BEGIN
    -- Writing an ALREADY-expired grant is rejected up front (dead on arrival).
    BEGIN
        PERFORM authz.write_tuple('test_exp', 'user', 'zoe', 'viewer', 'doc', 'd1',
                                  p_expires_at := now() - interval '1 second');
        PERFORM _test_assert('exp_0_past_expiry_write_rejected', 'no error', 'error');
    EXCEPTION WHEN invalid_parameter_value THEN
        PERFORM _test_assert('exp_0_past_expiry_write_rejected', 'error', 'error');
    END;

    -- Future expiry grants; once expired (backdated), it does not.
    PERFORM authz.write_tuple('test_exp', 'user', 'alice', 'viewer', 'doc', 'd1',
                              p_expires_at := now() + interval '1 hour');
    PERFORM authz.write_tuple('test_exp', 'user', 'bob', 'viewer', 'doc', 'd1',
                              p_expires_at := now() + interval '1 hour');
    PERFORM pg_temp._expire('bob');

    PERFORM _test_assert('exp_1_future_expiry_grants',
        authz.check_access('test_exp', 'user', 'alice', 'can_read', 'doc', 'd1')::text, 'true');
    PERFORM _test_assert('exp_2_past_expiry_denies',
        authz.check_access('test_exp', 'user', 'bob', 'can_read', 'doc', 'd1')::text, 'false');

    -- Search paths exclude expired rows too (same RLS chokepoint).
    PERFORM _test_assert('exp_3_list_objects_excludes_expired',
        (SELECT count(*)::text FROM authz.list_objects('test_exp', 'user', 'bob', 'can_read', 'doc')), '0');
    PERFORM _test_assert('exp_4_list_subjects_excludes_expired',
        (SELECT string_agg(subject_id, ',') FROM authz.list_subjects('test_exp', 'user', 'viewer', 'doc', 'd1')),
        'alice');

    -- Expired USERSET membership stops granting through the group.
    PERFORM authz.write_tuple('test_exp', 'user', 'carol', 'member', 'grp', 'eng',
                              p_expires_at := now() + interval '1 hour');
    PERFORM pg_temp._expire('carol');
    PERFORM authz.write_tuple('test_exp', 'grp', 'eng', 'viewer', 'doc', 'd2',
                              p_user_relation := 'member');
    PERFORM _test_assert('exp_5_expired_membership_denies_via_userset',
        authz.check_access('test_exp', 'user', 'carol', 'can_read', 'doc', 'd2')::text, 'false');

    -- Re-granting an EXPIRED tuple reactivates it (upsert refreshes expiry).
    PERFORM authz.write_tuple('test_exp', 'user', 'bob', 'viewer', 'doc', 'd1',
                              p_expires_at := now() + interval '1 hour');
    PERFORM _test_assert('exp_6_regrant_reactivates',
        authz.check_access('test_exp', 'user', 'bob', 'can_read', 'doc', 'd1')::text, 'true');

    -- ... and an unconditional typed-batch re-grant over an expired row
    -- reactivates it as permanent (no silent no-op against a hidden corpse).
    PERFORM authz.write_tuple('test_exp', 'user', 'dave', 'viewer', 'doc', 'd1',
                              p_expires_at := now() + interval '1 hour');
    PERFORM pg_temp._expire('dave');
    PERFORM authz.write_tuples('test_exp', ARRAY[
        ('user','dave',NULL,'viewer','doc','d1')
    ]::authz.tuple_input[]);
    PERFORM _test_assert('exp_7_batch_regrant_reactivates',
        authz.check_access('test_exp', 'user', 'dave', 'can_read', 'doc', 'd1')::text, 'true');
    PERFORM _test_assert('exp_8_batch_regrant_now_permanent',
        (SELECT (t.expires_at IS NULL)::text FROM authz.tuples t
          WHERE t.store_id = authz._s('test_exp') AND t.user_id = 'dave'), 'true');

    -- jsonb batch accepts expires_at (routes through write_tuple).
    PERFORM authz.write_tuples_jsonb('test_exp',
        ('[{"user_type":"user","user_id":"erin","relation":"viewer",'
         || '"object_type":"doc","object_id":"d1",'
         || '"expires_at":"' || (now() + interval '1 hour')::text || '"}]')::jsonb);
    PERFORM pg_temp._expire('erin');
    PERFORM _test_assert('exp_9_jsonb_expired_denies',
        authz.check_access('test_exp', 'user', 'erin', 'can_read', 'doc', 'd1')::text, 'false');
END;
$$;

-- Time travel: expiry is judged AS OF the asked time. A grant that expired
-- at T still shows as allowed for p_at < T — even queried after T passed.
DO $$
DECLARE
    v_before  timestamptz;
    v_expires timestamptz := clock_timestamp() + interval '1.5 seconds';
BEGIN
    PERFORM authz.write_tuple('test_exp', 'user', 'tt_user', 'viewer', 'doc', 'd9',
                              p_expires_at := v_expires);
END;
$$;
SELECT set_config('test.exp_t1', clock_timestamp()::text, false);
SELECT pg_sleep(1.6);
DO $$
DECLARE
    v_t1 timestamptz := current_setting('test.exp_t1')::timestamptz;
BEGIN
    -- Live: expired by now.
    PERFORM _test_assert('exp_10_live_expired_now',
        authz.check_access('test_exp', 'user', 'tt_user', 'can_read', 'doc', 'd9')::text, 'false');
    -- Time travel to before the expiry: it granted then.
    PERFORM _test_assert('exp_11_timetravel_before_expiry_allows',
        authz.audit_check_access('test_exp', 'user', 'tt_user', 'can_read', 'doc', 'd9', v_t1)::text, 'true');
    -- Time travel to after the expiry: denied as of that moment too.
    PERFORM _test_assert('exp_12_timetravel_after_expiry_denies',
        authz.audit_check_access('test_exp', 'user', 'tt_user', 'can_read', 'doc', 'd9', clock_timestamp())::text, 'false');
END;
$$;

-- Cleanup function: garbage-collects expired rows (audited), leaves live ones.
DO $$
DECLARE
    v_deleted integer;
BEGIN
    v_deleted := authz.cleanup_expired_tuples('test_exp');
    PERFORM _test_assert('exp_13_cleanup_deletes_expired_only',
        (v_deleted >= 2)::text, 'true');  -- carol + tt_user (+ any other expired)
    PERFORM _test_assert('exp_14_live_grants_survive_cleanup',
        authz.check_access('test_exp', 'user', 'alice', 'can_read', 'doc', 'd1')::text, 'true');
    -- History intact after cleanup: the pre-expiry time-travel still allows.
    PERFORM _test_assert('exp_15_timetravel_survives_cleanup',
        authz.audit_check_access('test_exp', 'user', 'tt_user', 'can_read', 'doc', 'd9',
                                 current_setting('test.exp_t1')::timestamptz)::text, 'true');
END;
$$;

DO $$
BEGIN
    PERFORM authz.delete_store('test_exp');
END;
$$;

SELECT _test_report('expiry');
