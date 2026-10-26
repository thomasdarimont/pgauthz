-- Store groups (ADR 0017, migration 0028): the default group holds the
-- migrated stores, a group is created / described / deleted, a store is
-- attached and detached, the empty-only deletion rule, the audit trail,
-- and list_stores naming the group.
SELECT _test_reset();

DO $$
DECLARE v_err text; v_state text; v_n bigint; r record; v_seq0 bigint := COALESCE((SELECT max(seq) FROM authz.store_group_audit), 0);
BEGIN
    PERFORM authz.delete_store('sg_test_a', p_purge_audit => true) FROM (SELECT 1) x WHERE EXISTS (SELECT 1 FROM authz.stores WHERE name = 'sg_test_a');
    PERFORM authz.delete_store('sg_test_b', p_purge_audit => true) FROM (SELECT 1) x WHERE EXISTS (SELECT 1 FROM authz.stores WHERE name = 'sg_test_b');
    DELETE FROM authz.stores WHERE name IN ('sg_test_a', 'sg_test_b');
    DELETE FROM authz.store_groups WHERE name IN ('sg_tenant', 'sg_other');

    -- the default group exists and holds the stores that predate it
    PERFORM _test_assert('sg_default_exists', (SELECT count(*) FROM authz.store_groups WHERE name = 'default')::text, '1');
    PERFORM _test_assert('sg_default_in_list_first', (SELECT name FROM authz.list_store_groups() LIMIT 1), 'default');

    -- a new store is ungrouped (its own group of one); the console places it
    PERFORM authz.create_store('sg_test_a', 'group test a');
    PERFORM authz.create_store('sg_test_b', 'group test b');
    PERFORM _test_assert('sg_new_store_ungrouped', coalesce((SELECT store_group FROM authz.list_stores() WHERE name = 'sg_test_a'), '<null>'), '<null>');

    -- create / describe / attach
    PERFORM set_config('authz.performed_by', 'user:tester', false);
    PERFORM authz.create_store_group('sg_tenant', 'tenant A');
    PERFORM _test_assert('sg_created', (SELECT description FROM authz.list_store_groups() WHERE name = 'sg_tenant'), 'tenant A');
    PERFORM authz.update_store_group('sg_tenant', 'Tenant A (renamed)');
    PERFORM _test_assert('sg_updated', (SELECT description FROM authz.list_store_groups() WHERE name = 'sg_tenant'), 'Tenant A (renamed)');
    PERFORM authz.set_store_group('sg_test_a', 'sg_tenant');
    PERFORM authz.set_store_group('sg_test_b', 'sg_tenant');
    PERFORM _test_assert('sg_attached', (SELECT store_group FROM authz.list_stores() WHERE name = 'sg_test_a'), 'sg_tenant');
    PERFORM _test_assert('sg_store_count', (SELECT store_count FROM authz.list_store_groups() WHERE name = 'sg_tenant')::text, '2');
    -- attaching again records nothing
    SELECT count(*) INTO v_n FROM authz.store_group_audit WHERE group_name = 'sg_tenant' AND seq > v_seq0;
    PERFORM authz.set_store_group('sg_test_a', 'sg_tenant');
    PERFORM _test_assert('sg_attach_idempotent', (SELECT count(*) FROM authz.store_group_audit WHERE group_name = 'sg_tenant' AND seq > v_seq0)::text, v_n::text);

    -- names follow the store rule; an unknown group raises; the default group stays
    v_state := NULL;
    BEGIN PERFORM authz.create_store_group('bad-name'); EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('sg_bad_name', v_state, '22023');
    v_err := NULL;
    BEGIN PERFORM authz.set_store_group('sg_test_a', 'sg_nope'); EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('sg_unknown_group', v_err, 'Unknown store group: sg_nope');
    v_err := NULL;
    BEGIN PERFORM authz.delete_store_group('default'); EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('sg_default_undeletable', v_err, 'the default store group cannot be deleted');

    -- a group with stores cannot be deleted; detach / move first
    v_err := NULL;
    BEGIN PERFORM authz.delete_store_group('sg_tenant'); EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('sg_delete_nonempty', v_err, 'store group sg_tenant still holds 2 store(s): move or detach them first');
    PERFORM authz.create_store_group('sg_other');
    PERFORM authz.set_store_group('sg_test_a', 'sg_other');   -- a move: DETACH from one, ATTACH to the other
    PERFORM authz.set_store_group('sg_test_b', NULL);         -- detached: its own group of one
    PERFORM _test_assert('sg_detached', coalesce((SELECT store_group FROM authz.list_stores() WHERE name = 'sg_test_b'), '<null>'), '<null>');
    PERFORM _test_assert('sg_delete_empty', authz.delete_store_group('sg_tenant')::text, 'true');
    PERFORM _test_assert('sg_delete_missing', authz.delete_store_group('sg_tenant')::text, 'false');

    -- the trail: who did what, newest first
    SELECT * INTO r FROM authz.list_store_group_audit('sg_other', 1);
    PERFORM _test_assert('sg_audit_last', r.action || ' ' || r.store || ' by ' || r.performed_by, 'ATTACH sg_test_a by user:tester');
    PERFORM _test_assert('sg_audit_actions',
        (SELECT string_agg(action, ',' ORDER BY seq) FROM authz.store_group_audit WHERE group_name = 'sg_tenant' AND seq > v_seq0),
        'CREATE,UPDATE,ATTACH,ATTACH,DETACH,DETACH,DELETE');

    -- a retired store keeps its group
    PERFORM authz.retire_store('sg_test_a');
    PERFORM _test_assert('sg_retired_keeps_group', (SELECT store_group FROM authz.list_stores() WHERE name = 'sg_test_a'), 'sg_other');

    PERFORM set_config('authz.performed_by', '', false);
    PERFORM authz.delete_store('sg_test_a', p_purge_audit => true);
    PERFORM authz.delete_store('sg_test_b', p_purge_audit => true);
    PERFORM authz.delete_store_group('sg_other');
END;
$$;

SELECT _test_report('store group checks');
