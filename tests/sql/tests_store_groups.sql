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

-- Model ownership and sharing (ADR 0017 phase 3, migration 0030): a model
-- belongs to the publishing store's group (or the store itself when
-- ungrouped); a store applies its own group's and the platform's models,
-- another group's only with a model_consumer grant; the plan says why.
DO $$
DECLARE v_err text; v_state text; v_plan jsonb; o record; s text;
BEGIN
    FOR s IN SELECT unnest(ARRAY['mo_a_src', 'mo_b_tgt', 'mo_solo']) LOOP
        BEGIN PERFORM authz.delete_store(s, p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END;
    END LOOP;
    DELETE FROM authz.model_registry WHERE name IN ('mo_model', 'mo_solo_model', 'mo_platform_model');
    DELETE FROM authz.model_owners WHERE name IN ('mo_model', 'mo_solo_model', 'mo_platform_model');
    DELETE FROM authz.store_groups WHERE name IN ('mo_a', 'mo_b');
    PERFORM authz.create_store_group('mo_a'); PERFORM authz.create_store_group('mo_b');
    PERFORM authz.create_store('mo_a_src'); PERFORM authz.set_store_group('mo_a_src', 'mo_a');
    PERFORM authz.create_store('mo_b_tgt'); PERFORM authz.set_store_group('mo_b_tgt', 'mo_b');
    PERFORM authz.create_store('mo_solo');
    PERFORM authz.model_register_type('mo_a_src', 'doc'); PERFORM authz.model_register_relation('mo_a_src', 'viewer');
    PERFORM authz.model_add_rule('mo_a_src', 'doc', 'viewer', 'direct');
    PERFORM authz.model_register_type('mo_solo', 'doc'); PERFORM authz.model_register_relation('mo_solo', 'viewer');
    PERFORM authz.model_add_rule('mo_solo', 'doc', 'viewer', 'direct');

    -- publishing from a grouped store: the group owns the name; from an ungrouped store: the store does
    PERFORM authz.publish_model('mo_model', 'mo_a_src', 'A''s model');
    SELECT * INTO o FROM authz.model_owner('mo_model');
    PERFORM _test_assert('mo_01_group_owns', o.owner_group || '/' || coalesce(o.owner_store, '-'), 'mo_a/-');
    PERFORM authz.publish_model('mo_solo_model', 'mo_solo');
    SELECT * INTO o FROM authz.model_owner('mo_solo_model');
    PERFORM _test_assert('mo_02_store_owns', coalesce(o.owner_group, '-') || '/' || o.owner_store, '-/mo_solo');
    PERFORM _test_assert('mo_03_listed', (SELECT owner_group FROM authz.list_model_versions('mo_model') LIMIT 1), 'mo_a');
    -- a definition published without a store is the platform's
    PERFORM authz.publish_model_definition('mo_platform_model', authz.export_model('mo_a_src'));
    SELECT * INTO o FROM authz.model_owner('mo_platform_model');
    PERFORM _test_assert('mo_04_platform_owns', o.owner_group, 'default');

    -- B may not apply A's model: apply raises, the plan reports the blocker
    v_err := NULL; v_state := NULL;
    BEGIN PERFORM authz.apply_model('mo_b_tgt', 'mo_model'); EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('mo_05_apply_refused', v_state || ' ' || v_err, '42501 apply_model: model mo_model belongs to group mo_a; store mo_b_tgt (group mo_b) may apply it only with a model_consumer grant from mo_a');
    v_plan := authz.plan_model_apply('mo_b_tgt', 'mo_model');
    PERFORM _test_assert('mo_06_plan_blocker', (v_plan->>'can_apply') || ' ' || (v_plan->'blockers'->0->>'kind'), 'false model_not_shared');
    -- the platform's model: everyone's; A's own store: its own
    PERFORM authz.apply_model('mo_b_tgt', 'mo_platform_model');
    PERFORM _test_assert('mo_07_platform_model_applies', (SELECT model_name FROM authz.model_status('mo_b_tgt')), 'mo_platform_model');
    PERFORM authz.apply_model('mo_a_src', 'mo_model');
    -- A grants B: now it applies; the grant is audited; revoke ends it
    PERFORM set_config('authz.performed_by', 'user:a_admin', false);
    PERFORM authz.grant_model_consumer('mo_a', 'mo_b');
    PERFORM _test_assert('mo_08_consumers', (SELECT string_agg(consumer_group, ',') FROM authz.list_model_consumers('mo_a')), 'mo_b');
    PERFORM authz.apply_model('mo_b_tgt', 'mo_model');
    PERFORM _test_assert('mo_09_shared_applies', (SELECT model_name FROM authz.model_status('mo_b_tgt')), 'mo_model');
    PERFORM _test_assert('mo_10_audit', (SELECT action || ' ' || description || ' by ' || performed_by FROM authz.list_store_group_audit('mo_a', 1)), 'RELATE model_consumer mo_b by user:a_admin');
    PERFORM _test_assert('mo_11_revoke', authz.revoke_model_consumer('mo_a', 'mo_b')::text || authz.revoke_model_consumer('mo_a', 'mo_b')::text, 'truefalse');
    v_plan := authz.plan_model_apply('mo_b_tgt', 'mo_model');
    PERFORM _test_assert('mo_12_blocked_again', (v_plan->>'can_apply'), 'false');
    PERFORM set_config('authz.performed_by', '', false);
    -- an ungrouped store's model is open like the platform's (isolation is a group's property)
    PERFORM authz.apply_model('mo_b_tgt', 'mo_solo_model');
    PERFORM _test_assert('mo_13_store_model_open', (SELECT model_name FROM authz.model_status('mo_b_tgt')), 'mo_solo_model');
    PERFORM authz.model_register_type('mo_b_tgt', 'folder');   -- B's store drifts from A's model …
    v_err := NULL;
    BEGIN PERFORM authz.publish_model('mo_model', 'mo_b_tgt'); EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('mo_14_publish_other_group_refused', v_err, 'model mo_model belongs to group mo_a — a new version is published from that group (set_model_owner moves it)');
    -- the platform moves ownership
    PERFORM authz.set_model_owner('mo_solo_model', 'mo_a');
    SELECT * INTO o FROM authz.model_owner('mo_solo_model');
    PERFORM _test_assert('mo_15_owner_moved', o.owner_group, 'mo_a');
    v_err := NULL; BEGIN PERFORM authz.grant_model_consumer('mo_a', 'mo_a'); EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert('mo_16_self_relation', v_err, 'a group always applies its own models: no relationship with itself');

    FOR s IN SELECT unnest(ARRAY['mo_a_src', 'mo_b_tgt', 'mo_solo']) LOOP PERFORM authz.delete_store(s, p_purge_audit => true); END LOOP;
    DELETE FROM authz.model_registry WHERE name IN ('mo_model', 'mo_solo_model', 'mo_platform_model');
    DELETE FROM authz.model_owners WHERE name IN ('mo_model', 'mo_solo_model', 'mo_platform_model');
    PERFORM authz.delete_store_group('mo_a'); PERFORM authz.delete_store_group('mo_b');
END;
$$;

SELECT _test_report('store group checks');
