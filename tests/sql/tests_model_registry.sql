-- Tests for the model registry: publish_model / apply_model / model_status /
-- model_rollout_status — the shared-model-across-tenant-stores workflow.
--
-- Scenario: test_reg_src is the "authoring" store; its model is published as
-- named versions and rolled out to tenant stores (test_reg_tgt, test_reg_t2).

SELECT _test_reset();

-- Setup: authoring store with types, relations, rules, a restriction and a
-- condition; publish v1 (and prove republish is idempotent).
DO $$
DECLARE
    v int;
BEGIN
    BEGIN PERFORM authz.delete_store('test_reg_src'); EXCEPTION WHEN OTHERS THEN NULL; END;
    BEGIN PERFORM authz.delete_store('test_reg_tgt'); EXCEPTION WHEN OTHERS THEN NULL; END;
    BEGIN PERFORM authz.delete_store('test_reg_t2');  EXCEPTION WHEN OTHERS THEN NULL; END;
    DELETE FROM authz.model_registry WHERE name = 'test_reg_model';

    PERFORM authz.create_store('test_reg_src');
    PERFORM authz.model_register_type('test_reg_src', 'user');
    PERFORM authz.model_register_type('test_reg_src', 'doc', 0, NULL, NULL, ARRAY['group:test']);
    PERFORM authz.model_register_relation('test_reg_src', 'viewer');
    PERFORM authz.model_register_relation('test_reg_src', 'can_read');
    PERFORM authz.model_add_rule('test_reg_src', 'doc', 'viewer', 'direct');
    PERFORM authz.model_add_rule('test_reg_src', 'doc', 'can_read', 'computed',
        p_computed_relation => 'viewer');
    PERFORM authz.model_add_type_restriction('test_reg_src', 'doc', 'viewer', 'user');
    PERFORM authz.create_condition_sql('test_reg_src', 'always', 'true');

    v := authz.publish_model('test_reg_model', 'test_reg_src', 'registry test model');
    PERFORM _test_assert('reg_1_publish_v1', v::text, '1');

    v := authz.publish_model('test_reg_model', 'test_reg_src');
    PERFORM _test_assert('reg_2_republish_unchanged_stays_v1', v::text, '1');
END;
$$;

-- Apply v1 to a fresh tenant store: model works, state is in sync.
DO $$
DECLARE
    v int;
    s record;
BEGIN
    PERFORM authz.create_store('test_reg_tgt');
    v := authz.apply_model('test_reg_tgt', 'test_reg_model');
    PERFORM _test_assert('reg_3_apply_latest_is_v1', v::text, '1');

    PERFORM authz.write_tuple('test_reg_tgt', 'user', 'alice', 'viewer', 'doc', 'doc1');
    PERFORM _test_assert('reg_4_applied_model_grants',
        authz.check_access('test_reg_tgt', 'user', 'alice', 'can_read', 'doc', 'doc1')::text,
        'true');

    SELECT * INTO s FROM authz.model_status('test_reg_tgt');
    PERFORM _test_assert('reg_5_status_version', s.model_version::text, '1');
    PERFORM _test_assert('reg_6_status_in_sync', s.in_sync::text, 'true');

    PERFORM _test_assert('reg_7_condition_applied',
        (SELECT count(*)::text FROM authz.conditions c
          WHERE c.store_id = authz._s('test_reg_tgt') AND c.name = 'always'), '1');
END;
$$;

-- Evolve the source model, publish v2, roll it out.
DO $$
DECLARE
    v int;
    s record;
BEGIN
    PERFORM authz.model_register_relation('test_reg_src', 'editor');
    PERFORM authz.model_add_rule('test_reg_src', 'doc', 'editor', 'direct');
    PERFORM authz.delete_condition('test_reg_src', 'always');

    v := authz.publish_model('test_reg_model', 'test_reg_src');
    PERFORM _test_assert('reg_8_publish_v2', v::text, '2');

    -- Fleet view before the rollout: target still on v1, latest is 2.
    SELECT * INTO s FROM authz.model_rollout_status('test_reg_model');
    PERFORM _test_assert('reg_9_rollout_store_version', s.model_version::text, '1');
    PERFORM _test_assert('reg_10_rollout_latest', s.latest_version::text, '2');
    PERFORM _test_assert('reg_11_rollout_in_sync', s.in_sync::text, 'true');

    v := authz.apply_model('test_reg_tgt', 'test_reg_model');
    PERFORM _test_assert('reg_12_apply_v2', v::text, '2');
    SELECT * INTO s FROM authz.model_status('test_reg_tgt');
    PERFORM _test_assert('reg_13_status_v2_in_sync',
        s.model_version::text || '/' || s.in_sync::text, '2/true');

    -- v2 removed the condition — apply must remove it from the target too.
    PERFORM _test_assert('reg_14_condition_removed',
        (SELECT count(*)::text FROM authz.conditions c
          WHERE c.store_id = authz._s('test_reg_tgt') AND c.name = 'always'), '0');
END;
$$;

-- Drift detection and repair: hand-edit the target, see in_sync flip, then
-- re-apply. A stale relation still referenced by tuples must BLOCK the
-- repair (tuples have no FK on relations — silent deletion would orphan
-- them); after the tuples are gone, re-apply removes rule and relation.
DO $$
DECLARE
    s record;
    v_err boolean := false;
BEGIN
    PERFORM authz.model_register_relation('test_reg_tgt', 'owner');
    PERFORM authz.model_add_rule('test_reg_tgt', 'doc', 'owner', 'direct');
    PERFORM authz.write_tuple('test_reg_tgt', 'user', 'bob', 'owner', 'doc', 'doc1');

    SELECT * INTO s FROM authz.model_status('test_reg_tgt');
    PERFORM _test_assert('reg_15_drift_detected', s.in_sync::text, 'false');

    BEGIN
        PERFORM authz.apply_model('test_reg_tgt', 'test_reg_model', 2);
    EXCEPTION WHEN OTHERS THEN
        v_err := true;
    END;
    PERFORM _test_assert('reg_16_reapply_blocked_by_referencing_tuples', v_err::text, 'true');

    PERFORM authz.delete_tuple('test_reg_tgt', 'user', 'bob', 'owner', 'doc', 'doc1');
    PERFORM authz.apply_model('test_reg_tgt', 'test_reg_model', 2);
    SELECT * INTO s FROM authz.model_status('test_reg_tgt');
    PERFORM _test_assert('reg_17_reapply_repairs_drift', s.in_sync::text, 'true');
    PERFORM _test_assert('reg_18_stale_relation_removed',
        (SELECT count(*)::text FROM authz.relations r
          WHERE r.store_id = authz._s('test_reg_tgt') AND r.name = 'owner'), '0');
END;
$$;

-- Fleet apply + the strict no-type-removal guard.
DO $$
DECLARE
    v_count int;
    v_err   boolean := false;
BEGIN
    PERFORM authz.create_store('test_reg_t2');
    SELECT count(*) INTO v_count
      FROM authz.apply_model(ARRAY['test_reg_tgt', 'test_reg_t2'], 'test_reg_model') a
     WHERE a.version = 2;
    PERFORM _test_assert('reg_19_fleet_apply_both_v2', v_count::text, '2');

    -- An extra type in the target is never removed automatically: error.
    PERFORM authz.model_register_type('test_reg_t2', 'rogue');
    BEGIN
        PERFORM authz.apply_model('test_reg_t2', 'test_reg_model', 2);
    EXCEPTION WHEN OTHERS THEN
        v_err := true;
    END;
    PERFORM _test_assert('reg_20_extra_type_blocks_apply', v_err::text, 'true');
END;
$$;

-- Registry listing + unmanaged-store status.
DO $$
DECLARE
    v_count int;
    s record;
BEGIN
    SELECT count(*) INTO v_count FROM authz.list_model_versions('test_reg_model');
    PERFORM _test_assert('reg_21_two_versions_listed', v_count::text, '2');

    SELECT * INTO s FROM authz.model_status('test_reg_src');  -- never applied to
    PERFORM _test_assert('reg_22_unmanaged_store_null_model',
        (s.model_name IS NULL)::text || '/' || (s.live_checksum IS NOT NULL)::text,
        'true/true');
END;
$$;

-- plan_model_apply: dry-run report (no_op, changes, blockers, rollback).
DO $$
DECLARE
    p jsonb;
BEGIN
    -- In-sync store, latest version → a no-op plan with no blockers.
    p := authz.plan_model_apply('test_reg_tgt', 'test_reg_model');
    PERFORM _test_assert('reg_23_plan_noop',
        (p->>'no_op') || '/' || (p->>'can_apply') || '/' || (p->'blockers')::text,
        'true/true/[]');

    -- Planning the DOWNGRADE to v1: the condition comes back, the editor
    -- relation goes away (no tuples reference it → no blocker), and rolling
    -- back afterwards (re-applying v2) is feasible (v1 adds no types).
    p := authz.plan_model_apply('test_reg_tgt', 'test_reg_model', 1);
    PERFORM _test_assert('reg_24_plan_downgrade',
        (p->>'no_op') || '/' || (p->>'can_apply')
            || '/' || (p->'changes'->'conditions'->'add')::text
            || '/' || (p->'changes'->'relations'->'remove')::text
            || '/' || (p->'rollback'->>'possible'),
        'false/true/["always"]/["editor"]/true');

    -- Extra type in the store → extra_type blocker, can_apply=false.
    p := authz.plan_model_apply('test_reg_t2', 'test_reg_model');
    PERFORM _test_assert('reg_25_plan_extra_type_blocks',
        (p->>'can_apply') || '/' || (p->'blockers'->0->>'kind')
            || '/' || (p->'blockers'->0->>'name'),
        'false/extra_type/rogue');

    -- Relation slated for removal but still referenced by tuples → blocker
    -- with the tuple count; deleting the tuples clears it.
    PERFORM authz.model_register_relation('test_reg_tgt', 'ghost');
    PERFORM authz.model_add_rule('test_reg_tgt', 'doc', 'ghost', 'direct');
    PERFORM authz.write_tuple('test_reg_tgt', 'user', 'bob', 'ghost', 'doc', 'doc1');
    p := authz.plan_model_apply('test_reg_tgt', 'test_reg_model');
    PERFORM _test_assert('reg_26_plan_tuple_blocker',
        (p->>'can_apply') || '/' || (p->'blockers'->0->>'kind')
            || '/' || (p->'blockers'->0->>'name') || '/' || (p->'blockers'->0->>'tuples'),
        'false/relation_referenced_by_tuples/ghost/1');

    PERFORM authz.delete_tuple('test_reg_tgt', 'user', 'bob', 'ghost', 'doc', 'doc1');
    p := authz.plan_model_apply('test_reg_tgt', 'test_reg_model');
    PERFORM _test_assert('reg_27_plan_unblocked_after_tuple_delete',
        (p->>'can_apply') || '/' || (p->'changes'->'relations'->'remove')::text,
        'true/["ghost"]');
    PERFORM authz.apply_model('test_reg_tgt', 'test_reg_model', 2);  -- restore

    -- A version that ADDS a type makes rollback infeasible (apply never
    -- removes types), and the plan says so up front.
    PERFORM authz.model_register_type('test_reg_src', 'folder');
    PERFORM _test_assert('reg_28_publish_v3',
        authz.publish_model('test_reg_model', 'test_reg_src')::text, '3');
    p := authz.plan_model_apply('test_reg_tgt', 'test_reg_model', 3);
    PERFORM _test_assert('reg_29_plan_rollback_infeasible',
        (p->>'can_apply') || '/' || (p->'changes'->'types'->'add')::text
            || '/' || (p->'rollback'->>'to_version') || '/' || (p->'rollback'->>'possible')
            || '/' || (p->'rollback'->'type_removals_required')::text,
        'true/["folder"]/2/false/["folder"]');
END;
$$;

-- Cleanup (store_model_state rows cascade with the stores).
DO $$
BEGIN
    PERFORM authz.delete_store('test_reg_src');
    PERFORM authz.delete_store('test_reg_tgt');
    PERFORM authz.delete_store('test_reg_t2');
    DELETE FROM authz.model_registry WHERE name = 'test_reg_model';
END;
$$;

SELECT _test_report('model registry');
