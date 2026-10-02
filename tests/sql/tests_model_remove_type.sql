-- Tests for model_remove_type: removing a type from a store's dictionary
-- together with its rules, restrictions and tuple partition, fail-closed
-- against gates / events / tuples, with p_force deleting tuples through the
-- audited path. Uses its own store.

CREATE OR REPLACE FUNCTION _test_setup_remove_type() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    BEGIN PERFORM authz.delete_store('test_rmtype', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_rmtype');
    PERFORM authz.model_register_type('test_rmtype', 'user');
    PERFORM authz.model_register_type('test_rmtype', 'team');
    PERFORM authz.model_register_type('test_rmtype', 'report');
    PERFORM authz.model_register_type('test_rmtype', 'legacy');
    PERFORM authz.model_register_relation('test_rmtype', r) FROM unnest(ARRAY['member','viewer','can_read','download','archive']) r;
    -- team: members
    PERFORM authz.model_add_rule('test_rmtype', 'team', 'member', 'direct');
    PERFORM authz.model_add_type_restriction('test_rmtype', 'team', 'member', 'user');
    -- report: viewers (users or team members), can_read
    PERFORM authz.model_add_rule('test_rmtype', 'report', 'viewer', 'direct');
    PERFORM authz.model_add_type_restriction('test_rmtype', 'report', 'viewer', 'user');
    PERFORM authz.model_add_type_restriction('test_rmtype', 'report', 'viewer', 'team', p_allowed_user_relation => 'member');
    PERFORM authz.model_add_rule('test_rmtype', 'report', 'can_read', 'computed', 'viewer');
    -- legacy: same shape, plus legacy may be a SUBJECT of report.viewer
    PERFORM authz.model_add_rule('test_rmtype', 'legacy', 'viewer', 'direct');
    PERFORM authz.model_add_type_restriction('test_rmtype', 'legacy', 'viewer', 'user');
    PERFORM authz.model_add_rule('test_rmtype', 'legacy', 'can_read', 'computed', 'viewer');
    PERFORM authz.model_add_type_restriction('test_rmtype', 'report', 'viewer', 'legacy');
    PERFORM authz.write_tuple('test_rmtype', 'user', 'alice', 'member', 'team', 'eng');
    PERFORM authz.write_tuple('test_rmtype', 'team', 'eng', 'viewer', 'report', 'r1', p_user_relation => 'member');
END;
$$;

SELECT _test_setup_remove_type();

-- rt_01: refused while tuples reference the type as OBJECT
DO $$
DECLARE v_err text;
BEGIN
    PERFORM authz.write_tuple('test_rmtype', 'user', 'bob', 'viewer', 'legacy', 'l1');
    BEGIN PERFORM authz.model_remove_type('test_rmtype', 'legacy');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('rt_01_refused_object_tuples', v_err LIKE '%referenced by 1 tuple%', coalesce(v_err, 'no error'));
    PERFORM _test_assert('rt_01_type_still_there', (SELECT count(*) FROM authz.types WHERE store_id = authz._s('test_rmtype') AND name = 'legacy')::text, '1');
    PERFORM authz.delete_tuple('test_rmtype', 'user', 'bob', 'viewer', 'legacy', 'l1');
END;
$$;

-- rt_02: refused while tuples reference the type as SUBJECT (other partition)
DO $$
DECLARE v_err text;
BEGIN
    PERFORM authz.write_tuple('test_rmtype', 'legacy', 'l1', 'viewer', 'report', 'r1');
    BEGIN PERFORM authz.model_remove_type('test_rmtype', 'legacy');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('rt_02_refused_subject_tuples', v_err LIKE '%referenced by 1 tuple%', coalesce(v_err, 'no error'));
    PERFORM authz.delete_tuple('test_rmtype', 'legacy', 'l1', 'viewer', 'report', 'r1');
END;
$$;

-- rt_03: refused while a gate sits on the type
DO $$
DECLARE v_err text;
BEGIN
    PERFORM authz.add_gate('test_rmtype', 'legacy', 'download', 'cap', '{"all_of": [{"count_within": {"window": "1h", "max": 3, "plus": 1}}]}');
    BEGIN PERFORM authz.model_remove_type('test_rmtype', 'legacy');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('rt_03_refused_gate', v_err LIKE '%1 temporal gate%', coalesce(v_err, 'no error'));
    PERFORM authz.drop_gate('test_rmtype', 'legacy', 'download', 'cap');
END;
$$;

-- rt_04: refused while recorded events name the type; p_force does not override
DO $$
DECLARE v_err text;
BEGIN
    PERFORM authz.record_event('test_rmtype', 'user', 'alice', 'download', 'legacy', 'l1');
    BEGIN PERFORM authz.model_remove_type('test_rmtype', 'legacy', p_force => true);
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('rt_04_refused_events_even_forced', v_err LIKE '%1 recorded event%', coalesce(v_err, 'no error'));
    PERFORM authz.purge_events('test_rmtype', now() + interval '1 minute');
END;
$$;

-- rt_05: p_force deletes tuples on BOTH sides, incl. expired, through the audited path
DO $$
DECLARE v_res jsonb; n_audit_before bigint; n_audit_after bigint; v_type_id int;
BEGIN
    v_type_id := authz._t(authz._s('test_rmtype'), 'legacy');
    PERFORM authz.write_tuple('test_rmtype', 'user', 'bob', 'viewer', 'legacy', 'l1');
    PERFORM authz.write_tuple('test_rmtype', 'user', 'carol', 'viewer', 'legacy', 'l2', p_expires_at => now() + interval '0.3 seconds');
    PERFORM authz.write_tuple('test_rmtype', 'legacy', 'l1', 'viewer', 'report', 'r1');
    PERFORM pg_sleep(0.4);   -- carol's grant is now expired (hidden from live reads)
    SELECT count(*) INTO n_audit_before FROM authz.tuples_audit WHERE store_id = authz._s('test_rmtype');
    v_res := authz.model_remove_type('test_rmtype', 'legacy', p_force => true, p_performed_by => 'cleanup-job');
    PERFORM _test_assert('rt_05_tuples_deleted_incl_expired', v_res->>'tuples_deleted', '3');
    PERFORM _test_assert('rt_05_rules_removed', v_res->>'rules_removed', '2');          -- legacy.viewer direct, legacy.can_read computed
    PERFORM _test_assert('rt_05_restrictions_removed', v_res->>'restrictions_removed', '2');   -- legacy.viewer←user, report.viewer←legacy
    PERFORM _test_assert('rt_05_partition_dropped', v_res->>'partition_dropped', 'true');
    SELECT count(*) INTO n_audit_after FROM authz.tuples_audit WHERE store_id = authz._s('test_rmtype');
    PERFORM _test_assert('rt_05_audit_rows_written', (n_audit_after - n_audit_before)::text, '4');   -- 3 DELETEs + TYPE_REMOVED
    PERFORM _test_assert('rt_05_deletes_attributed',
        (SELECT count(*) FROM authz.tuples_audit WHERE store_id = authz._s('test_rmtype') AND action = 'DELETE' AND performed_by = 'cleanup-job')::text, '3');
    PERFORM _test_assert('rt_05_marker_names_type',
        (SELECT object_id FROM authz.tuples_audit WHERE store_id = authz._s('test_rmtype') AND action = 'TYPE_REMOVED'), 'legacy');
    PERFORM _test_assert('rt_05_type_gone', (SELECT count(*) FROM authz.types WHERE store_id = authz._s('test_rmtype') AND name = 'legacy')::text, '0');
    PERFORM _test_assert('rt_05_partition_gone',
        (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'authz' AND c.relname = 'tuples_test_rmtype_legacy')::text, '0');
    PERFORM _test_assert('rt_05_no_orphan_tuples',
        (SELECT count(*) FROM authz.tuples WHERE store_id = authz._s('test_rmtype') AND (object_type = v_type_id OR user_type = v_type_id))::text, '0');
END;
$$;

-- rt_06: the rest of the model is intact and still decides; relations stay registered
DO $$
BEGIN
    PERFORM _test_assert('rt_06_other_type_still_decides', authz.check_access('test_rmtype', 'user', 'alice', 'can_read', 'report', 'r1')::text, 'true');
    PERFORM _test_assert('rt_06_report_restrictions_kept',
        (SELECT count(*) FROM authz.type_restrictions WHERE store_id = authz._s('test_rmtype') AND object_type = authz._t(authz._s('test_rmtype'), 'report'))::text, '2');
    PERFORM _test_assert('rt_06_relations_kept', (SELECT count(*) FROM authz.relations WHERE store_id = authz._s('test_rmtype') AND name IN ('viewer','can_read'))::text, '2');
    PERFORM _test_assert_true('rt_06_describe_omits_type', position('legacy' in authz.describe_model('test_rmtype')) = 0, 'describe still mentions legacy');
END;
$$;

-- rt_07: the changefeed surfaces TYPE_REMOVED to every watcher, filters or not
DO $$
DECLARE n int;
BEGIN
    SELECT count(*) INTO n FROM authz.watch_changes('test_rmtype', p_lag => interval '0') w WHERE w.action = 'TYPE_REMOVED' AND w.object_id = 'legacy';
    PERFORM _test_assert('rt_07_watch_unfiltered', n::text, '1');
    SELECT count(*) INTO n FROM authz.watch_changes('test_rmtype', p_lag => interval '0', p_object_types => ARRAY['report']) w WHERE w.action = 'TYPE_REMOVED';
    PERFORM _test_assert('rt_07_watch_filtered_still_sees_it', n::text, '1');
END;
$$;

-- rt_08: unknown type / removed type raise; re-registering the name works again
DO $$
DECLARE v_err text; v_id int;
BEGIN
    BEGIN PERFORM authz.model_remove_type('test_rmtype', 'legacy');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('rt_08_removed_type_unknown', v_err LIKE '%Unknown type%', coalesce(v_err, 'no error'));
    v_id := authz.model_register_type('test_rmtype', 'legacy');
    PERFORM _test_assert_true('rt_08_name_reusable', v_id > 0, '');
    PERFORM _test_assert('rt_08_fresh_partition',
        (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'authz' AND c.relname = 'tuples_test_rmtype_legacy')::text, '1');
END;
$$;

-- rt_09: a type with no tuples / rules / restrictions removes cleanly without p_force
DO $$
DECLARE v_res jsonb;
BEGIN
    v_res := authz.model_remove_type('test_rmtype', 'legacy');
    PERFORM _test_assert('rt_09_clean_removal', v_res->>'tuples_deleted' || '/' || (v_res->>'rules_removed') || '/' || (v_res->>'partition_dropped'), '0/0/true');
END;
$$;

DROP FUNCTION IF EXISTS _test_setup_remove_type();

SELECT _test_report('model_remove_type checks');
