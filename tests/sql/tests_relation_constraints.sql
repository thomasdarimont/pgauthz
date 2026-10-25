-- Tests for relation constraints (migration 0025): max_direct enforced on
-- every write path through the tuple cap guard, max_effective advisory
-- through relation_usage; carried by describe_model, export, the registry.
-- Own store.

SELECT _test_reset();

CREATE OR REPLACE FUNCTION _test_setup_rc() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    BEGIN PERFORM authz.delete_store('test_rc', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END;
    BEGIN PERFORM authz.delete_store('test_rc2', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_rc');
    PERFORM authz.model_register_type('test_rc', 'user');
    PERFORM authz.model_register_type('test_rc', 'team');
    PERFORM authz.model_register_type('test_rc', 'doc');
    PERFORM authz.model_register_relation('test_rc', r)
       FROM unnest(ARRAY['member','owner','viewer','editor','can_view','can_share']) r;
    PERFORM authz.model_add_rule('test_rc', 'team', 'member', 'direct');
    PERFORM authz.model_add_rule('test_rc', 'doc', r, 'direct') FROM unnest(ARRAY['owner','viewer','editor']) r;
    PERFORM authz.model_add_type_restriction('test_rc', 'doc', 'viewer', 'user');
    PERFORM authz.model_add_type_restriction('test_rc', 'doc', 'viewer', 'team', p_allowed_user_relation => 'member');
    PERFORM authz.model_add_rule('test_rc', 'doc', 'can_view', 'computed', r) FROM unnest(ARRAY['viewer','editor','owner']) r;
    PERFORM authz.model_add_rule('test_rc', 'doc', 'can_share', 'computed', 'owner');
    PERFORM authz.model_add_grant_rule('test_rc', 'doc', 'viewer', 'can_share');
    PERFORM authz.write_tuple('test_rc', 'user', 'alice', 'owner', 'doc', 'plan');
    PERFORM authz.write_tuple('test_rc', 'user', 'alice', 'owner', 'doc', 'memo');
    PERFORM authz.write_tuple('test_rc', 'user', u, 'member', 'team', 'eng') FROM unnest(ARRAY['ann','ben','cid']) u;
END;
$$;

SELECT _test_setup_rc();

-- rc_01: declare, list, validate
DO $$
DECLARE v_err text; v_state text; v_id integer;
BEGIN
    v_id := authz.model_set_relation_constraint('test_rc', 'doc', 'viewer', p_max_direct => 3);
    PERFORM _test_assert_true('rc_01_set_returns_id', v_id > 0, v_id::text);
    PERFORM _test_assert('rc_01_set_is_idempotent', authz.model_set_relation_constraint('test_rc', 'doc', 'viewer', p_max_direct => 3)::text, v_id::text);
    PERFORM _test_assert('rc_01_listed',
        (SELECT string_agg(object_type || '.' || relation || ':' || coalesce(max_direct::text, '-') || '/' || coalesce(max_effective::text, '-'), ',')
           FROM authz.list_relation_constraints('test_rc')), 'doc.viewer:3/-');
    BEGIN PERFORM authz.model_set_relation_constraint('test_rc', 'doc', 'editor');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert_true('rc_01_both_null_refused', v_err LIKE '%needs max_direct or max_effective%', coalesce(v_err, 'no error'));
    PERFORM _test_assert('rc_01_both_null_sqlstate', v_state, '22023');
    v_err := NULL;
    BEGIN PERFORM authz.model_set_relation_constraint('test_rc', 'doc', 'editor', 0);
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('rc_01_zero_refused', v_err LIKE '%at least 1%', coalesce(v_err, 'no error'));
    -- max_direct needs a direct rule (can_view is derived) and no wildcard facet (owner gets one here, briefly)
    v_err := NULL;
    BEGIN PERFORM authz.model_set_relation_constraint('test_rc', 'doc', 'can_view', 5);
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('rc_01_no_direct_rule_refused', v_err LIKE '%has no direct rule%', coalesce(v_err, 'no error'));
    PERFORM _test_assert_true('rc_01_effective_on_permission_ok', authz.model_set_relation_constraint('test_rc', 'doc', 'can_view', p_max_effective => 100) > 0, 'id');
    PERFORM authz.model_drop_relation_constraint('test_rc', 'doc', 'can_view');
    PERFORM authz.model_add_type_restriction('test_rc', 'doc', 'owner', 'user', p_allow_wildcard => true);
    v_err := NULL;
    BEGIN PERFORM authz.model_set_relation_constraint('test_rc', 'doc', 'owner', 1);
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('rc_01_wildcard_facet_refused', v_err LIKE '%allows wildcard grants%', coalesce(v_err, 'no error'));
    PERFORM authz.model_remove_type_restrictions('test_rc', 'doc', 'owner');
    -- audit: one INSERT row for the declaration (the idempotent re-set stays quiet)
    PERFORM _test_assert('rc_01_audited',
        (SELECT string_agg(a.action, ',' ORDER BY a.seq) FROM authz.relation_constraints_audit a WHERE a.store_id = authz._s('test_rc')), 'INSERT,INSERT,DELETE');
END;
$$;

-- rc_02: the cap on write_tuple — the (N+1)th is refused with ZA001, nothing written
DO $$
DECLARE v_err text; v_state text; v_detail text;
BEGIN
    PERFORM _test_assert('rc_02_first',  authz.write_tuple('test_rc', 'user', 'bob',   'viewer', 'doc', 'plan')::text, 'true');
    PERFORM _test_assert('rc_02_second', authz.write_tuple('test_rc', 'user', 'carol', 'viewer', 'doc', 'plan')::text, 'true');
    PERFORM _test_assert('rc_02_third',  authz.write_tuple('test_rc', 'user', 'dave',  'viewer', 'doc', 'plan')::text, 'true');
    BEGIN PERFORM authz.write_tuple('test_rc', 'user', 'erin', 'viewer', 'doc', 'plan');
    EXCEPTION WHEN OTHERS THEN GET STACKED DIAGNOSTICS v_detail = PG_EXCEPTION_DETAIL; v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('rc_02_fourth_refused', v_err, 'relation viewer on doc:plan is full: 3 of 3 active direct assignments (max_direct)');
    PERFORM _test_assert('rc_02_sqlstate_ZA001', v_state, 'ZA001');
    PERFORM _test_assert('rc_02_detail_json', (v_detail::jsonb)->>'code' || ' ' || ((v_detail::jsonb)->>'max_direct') || ' ' || ((v_detail::jsonb)->>'direct_count'), 'relation_full 3 3');
    PERFORM _test_assert('rc_02_nothing_written', authz.check_access('test_rc', 'user', 'erin', 'can_view', 'doc', 'plan')::text, 'false');
    -- another object has its own count
    PERFORM _test_assert('rc_02_other_object_unaffected', authz.write_tuple('test_rc', 'user', 'erin', 'viewer', 'doc', 'memo')::text, 'true');
    -- an uncapped relation on the same object is unaffected
    PERFORM _test_assert('rc_02_other_relation_unaffected', authz.write_tuple('test_rc', 'user', 'erin', 'editor', 'doc', 'plan')::text, 'true');
END;
$$;

-- rc_03: a re-grant of a holder does not consume a slot; a condition change on a holder is an upsert, not a new slot
DO $$
DECLARE v_err text;
BEGIN
    PERFORM _test_assert('rc_03_regrant_noop', authz.write_tuple('test_rc', 'user', 'bob', 'viewer', 'doc', 'plan')::text, 'false');
    PERFORM _test_assert('rc_03_regrant_with_expiry_is_update',
        authz.write_tuple('test_rc', 'user', 'bob', 'viewer', 'doc', 'plan', p_expires_at => now() + interval '1 day')::text, 'true');
    PERFORM _test_assert('rc_03_still_three',
        (SELECT count(*)::text FROM authz.tuples t WHERE t.store_id = authz._s('test_rc') AND t.object_id = 'plan' AND t.relation = authz._r(authz._s('test_rc'), 'viewer')), '3');
END;
$$;

-- rc_04: an expired holder does not count; its slot is free
DO $$
BEGIN
    -- superuser: RLS is not forced on superusers, so the row can be aged directly
    UPDATE authz.tuples t SET expires_at = now() - interval '1 minute'
     WHERE t.store_id = authz._s('test_rc') AND t.object_id = 'plan' AND t.user_id = 'bob'
       AND t.relation = authz._r(authz._s('test_rc'), 'viewer');
    PERFORM _test_assert('rc_04_expired_frees_slot', authz.write_tuple('test_rc', 'user', 'erin', 'viewer', 'doc', 'plan')::text, 'true');
    -- re-granting the expired holder would now be the 4th live one
    DECLARE v_err text; v_state text;
    BEGIN
        BEGIN PERFORM authz.write_tuple('test_rc', 'user', 'bob', 'viewer', 'doc', 'plan');
        EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
        PERFORM _test_assert('rc_04_reactivation_counts_live_others', v_state, 'ZA001');
    END;
    PERFORM authz.delete_tuple('test_rc', 'user', 'erin', 'viewer', 'doc', 'plan');
    PERFORM authz.cleanup_expired_tuples('test_rc', '0 seconds');
END;
$$;

-- rc_05: wildcards are refused on a capped relation (check_violation, not ZA001)
DO $$
DECLARE v_err text; v_state text;
BEGIN
    PERFORM authz.model_set_relation_constraint('test_rc', 'doc', 'editor', 2);
    BEGIN PERFORM authz.write_tuple('test_rc', 'user', '*', 'editor', 'doc', 'memo');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert_true('rc_05_user_wildcard_refused', v_err LIKE 'relation editor on doc is capped (max_direct 2): a wildcard tuple is unbounded%', coalesce(v_err, 'no error'));
    PERFORM _test_assert('rc_05_sqlstate_check_violation', v_state, '23514');
    PERFORM _test_assert('rc_05_nothing_written', authz.check_access('test_rc', 'user', 'zoe', 'can_view', 'doc', 'memo')::text, 'false');
    PERFORM authz.model_drop_relation_constraint('test_rc', 'doc', 'editor');
END;
$$;

-- rc_06: a userset subject is one assignment; the batch writers hit the same guard atomically
DO $$
DECLARE v_err text; v_state text; v_n integer;
BEGIN
    PERFORM _test_assert('rc_06_userset_is_one', authz.write_tuple('test_rc', 'team', 'eng', 'viewer', 'doc', 'plan', p_user_relation => 'member')::text, 'true');
    -- plan: carol, dave, team:eng#member = 3 → a batch of two more fails as a whole
    BEGIN
        PERFORM authz.write_tuples('test_rc', ARRAY[
            ('user','fay',NULL,'viewer','doc','memo'),     -- memo has room (erin only)
            ('user','gus',NULL,'viewer','doc','plan')]::authz.tuple_input[]);
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('rc_06_batch_refused_sqlstate', v_state, 'ZA001');
    PERFORM _test_assert('rc_06_batch_is_atomic',
        (SELECT count(*)::text FROM authz.tuples t WHERE t.store_id = authz._s('test_rc') AND t.user_id IN ('fay', 'gus')), '0');
    -- a batch that overshoots within itself fails on the first row over the cap
    v_err := NULL; v_state := NULL;
    BEGIN
        PERFORM authz.write_tuples('test_rc', ARRAY[
            ('user','h1',NULL,'viewer','doc','memo'),
            ('user','h2',NULL,'viewer','doc','memo'),
            ('user','h3',NULL,'viewer','doc','memo')]::authz.tuple_input[]);   -- memo: erin + 3 = 4
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('rc_06_batch_overshoot_refused', v_state, 'ZA001');
    PERFORM _test_assert('rc_06_batch_overshoot_atomic',
        (SELECT count(*)::text FROM authz.tuples t WHERE t.store_id = authz._s('test_rc') AND t.object_id = 'memo' AND t.relation = authz._r(authz._s('test_rc'), 'viewer')), '1');
    -- exactly up to the cap is fine
    v_n := authz.write_tuples('test_rc', ARRAY[
            ('user','h1',NULL,'viewer','doc','memo'),
            ('user','h2',NULL,'viewer','doc','memo')]::authz.tuple_input[]);
    PERFORM _test_assert('rc_06_batch_to_the_cap_ok', v_n::text, '2');
    -- the jsonb path (conditional / expiring elements go through write_tuple)
    v_err := NULL; v_state := NULL;
    BEGIN
        PERFORM authz.write_tuples_jsonb('test_rc', '[{"user_type":"user","user_id":"ivy","relation":"viewer","object_type":"doc","object_id":"memo","expires_at":"2099-01-01T00:00:00Z"}]');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('rc_06_jsonb_path_refused', v_state, 'ZA001');
END;
$$;

-- rc_07: grant / apply_grants — the owner may share, but not past the cap; the SQLSTATE survives apply_grants
DO $$
DECLARE v_err text; v_state text;
BEGIN
    BEGIN PERFORM authz.grant('test_rc', 'user', 'alice', 'user', 'jon', 'viewer', 'doc', 'plan');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('rc_07_grant_refused', v_state, 'ZA001');
    v_err := NULL; v_state := NULL;
    BEGIN PERFORM authz.apply_grants('test_rc', 'user', 'alice',
        p_grants => '[{"user_type":"user","user_id":"jon","relation":"viewer","object_type":"doc","object_id":"plan"}]');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('rc_07_apply_grants_keeps_sqlstate', v_state, 'ZA001');
    PERFORM _test_assert_true('rc_07_apply_grants_message', v_err LIKE 'apply_grants: grant entry 1: relation viewer on doc:plan is full: 3 of 3 active%', coalesce(v_err, 'no error'));
    -- a checked write too (the same trigger)
    v_err := NULL; v_state := NULL;
    BEGIN PERFORM authz.write_tuples_checked('test_rc',
        p_writes => '[{"user_type":"user","user_id":"jon","relation":"viewer","object_type":"doc","object_id":"plan"}]');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('rc_07_checked_write_refused', v_state, 'ZA001');
END;
$$;

-- rc_08: relation_usage — direct vs effective, headroom, the budget, unbounded
DO $$
DECLARE u record;
BEGIN
    -- plan: direct = carol, dave, team:eng#member (3 of 3); effective = carol, dave, ann, ben, cid (5)
    SELECT * INTO u FROM authz.relation_usage('test_rc', 'doc', 'plan', 'viewer');
    PERFORM _test_assert('rc_08_direct_count', u.direct_count::text, '3');
    PERFORM _test_assert('rc_08_direct_headroom', u.direct_headroom::text, '0');
    PERFORM _test_assert('rc_08_effective_exhaustive', u.effective_count::text, '5');
    PERFORM _test_assert('rc_08_no_effective_cap', coalesce(u.max_effective::text, 'null') || ' ' || coalesce(u.effective_headroom::text, 'null'), 'null null');
    PERFORM _test_assert('rc_08_not_limited', u.limit_reached::text || ' ' || u.unbounded::text, 'false false');
    -- one subject type only
    SELECT * INTO u FROM authz.relation_usage('test_rc', 'doc', 'plan', 'viewer', p_subject_type => 'user');
    PERFORM _test_assert('rc_08_one_type', u.effective_count::text, '5');
    -- an explicit budget stops the resolution: a lower bound
    SELECT * INTO u FROM authz.relation_usage('test_rc', 'doc', 'plan', 'viewer', p_limit => 2);
    PERFORM _test_assert('rc_08_budget_stops', u.effective_count::text || ' ' || u.limit_reached::text, '2 true');
    -- an advisory effective cap sets the default budget
    PERFORM authz.model_set_relation_constraint('test_rc', 'doc', 'viewer', 3, 4);
    SELECT * INTO u FROM authz.relation_usage('test_rc', 'doc', 'plan', 'viewer');
    PERFORM _test_assert('rc_08_effective_cap_budget', u.effective_count::text || ' ' || u.max_effective::text || ' ' || u.effective_headroom::text || ' ' || u.limit_reached::text, '4 4 0 true');
    PERFORM authz.model_set_relation_constraint('test_rc', 'doc', 'viewer', 3, 10);
    SELECT * INTO u FROM authz.relation_usage('test_rc', 'doc', 'plan', 'viewer');
    PERFORM _test_assert('rc_08_effective_headroom', u.effective_count::text || ' ' || u.effective_headroom::text || ' ' || u.limit_reached::text, '5 5 false');
    -- "room for k more": budget max_effective - k + 1 → limit_reached means "would exceed"
    SELECT * INTO u FROM authz.relation_usage('test_rc', 'doc', 'plan', 'viewer', p_limit => 10 - 6 + 1);
    PERFORM _test_assert('rc_08_room_for_six', u.limit_reached::text, 'true');
    SELECT * INTO u FROM authz.relation_usage('test_rc', 'doc', 'plan', 'viewer', p_limit => 10 - 5 + 1);
    PERFORM _test_assert('rc_08_room_for_five', u.limit_reached::text, 'false');
    -- an object with no tuples at all
    SELECT * INTO u FROM authz.relation_usage('test_rc', 'doc', 'nothing', 'viewer');
    PERFORM _test_assert('rc_08_empty_object', u.direct_count::text || ' ' || u.direct_headroom::text || ' ' || u.effective_count::text, '0 3 0');
    -- a wildcard on an uncapped relation: unbounded, counts are null
    PERFORM authz.model_add_type_restriction('test_rc', 'doc', 'editor', 'user', p_allow_wildcard => true);
    PERFORM authz.write_tuple('test_rc', 'user', '*', 'editor', 'doc', 'memo');
    SELECT * INTO u FROM authz.relation_usage('test_rc', 'doc', 'memo', 'editor');
    PERFORM _test_assert('rc_08_unbounded', u.unbounded::text || ' ' || coalesce(u.effective_count::text, 'null') || ' ' || u.direct_count::text, 'true null 1');  -- the wildcard row is a direct tuple on the object
    -- the uncapped, unbudgeted direct count is exhaustive
    SELECT * INTO u FROM authz.relation_usage('test_rc', 'doc', 'plan', 'editor');
    PERFORM _test_assert('rc_08_uncapped_direct', u.direct_count::text || ' ' || coalesce(u.max_direct::text, 'null') || ' ' || coalesce(u.direct_headroom::text, 'null'), '1 null null');
END;
$$;

-- rc_09: describe_model renders the constraint; export carries it; the checksum sees it; apply propagates and removes
DO $$
DECLARE v_txt text; v_def jsonb; v_sum1 text; v_sum2 text;
BEGIN
    v_txt := authz.describe_model('test_rc');
    PERFORM _test_assert_true('rc_09_describe_comment', v_txt LIKE E'%    define viewer: [team#member, user]\n    # grant requires can_share\n    # constraint: max_direct 3, max_effective 10\n%', v_txt);
    v_def := authz.export_model('test_rc');
    PERFORM _test_assert('rc_09_export', (v_def->'relation_constraints')::text, '[{"relation": "viewer", "max_direct": 3, "object_type": "doc", "max_effective": 10}]');
    v_sum1 := authz._model_checksum(v_def);
    v_sum2 := authz._model_checksum(v_def - 'relation_constraints');
    PERFORM _test_assert_true('rc_09_checksum_moves', v_sum1 <> v_sum2, 'same checksum with and without the constraint');
    PERFORM _test_assert('rc_09_empty_is_pre_0025_checksum',
        authz._model_checksum(jsonb_set(v_def, '{relation_constraints}', '[]'::jsonb)), v_sum2);

    -- registry round trip into a second store
    PERFORM authz.publish_model('rc_model', 'test_rc');
    PERFORM authz.create_store('test_rc2');
    PERFORM authz.apply_model('test_rc2', 'rc_model');
    PERFORM _test_assert('rc_09_apply_propagates',
        (SELECT string_agg(object_type || '.' || relation || ':' || max_direct || '/' || max_effective, ',') FROM authz.list_relation_constraints('test_rc2')), 'doc.viewer:3/10');
    -- a constraint-free version removes it again
    PERFORM authz.model_drop_relation_constraint('test_rc', 'doc', 'viewer');
    PERFORM authz.publish_model('rc_model', 'test_rc');
    PERFORM authz.apply_model('test_rc2', 'rc_model');
    PERFORM _test_assert('rc_09_apply_removes_stale', (SELECT count(*)::text FROM authz.list_relation_constraints('test_rc2')), '0');
    -- plan reports the section
    PERFORM authz.model_set_relation_constraint('test_rc', 'doc', 'viewer', 3, 10);
    PERFORM authz.publish_model('rc_model', 'test_rc');
    PERFORM _test_assert('rc_09_plan_lists_add',
        (authz.plan_model_apply('test_rc2', 'rc_model')->'changes'->'relation_constraints'->'add'->0->>'max_direct'), '3');
END;
$$;

-- rc_10: dropping the cap frees the relation; removing the type removes the constraint; delete_store purges
DO $$
DECLARE v_err text; v_state text;
BEGIN
    PERFORM _test_assert('rc_10_drop', authz.model_drop_relation_constraint('test_rc', 'doc', 'viewer')::text, 'true');
    PERFORM _test_assert('rc_10_drop_again_false', authz.model_drop_relation_constraint('test_rc', 'doc', 'viewer')::text, 'false');
    PERFORM _test_assert('rc_10_uncapped_again', authz.write_tuple('test_rc', 'user', 'jon', 'viewer', 'doc', 'plan')::text, 'true');
    PERFORM authz.model_add_type_restriction('test_rc', 'doc', 'viewer', 'user', p_allow_wildcard => true);
    PERFORM _test_assert('rc_10_wildcard_ok_again', authz.write_tuple('test_rc', 'user', '*', 'viewer', 'doc', 'plan')::text, 'true');
    PERFORM authz.delete_tuple('test_rc', 'user', '*', 'viewer', 'doc', 'plan');
    PERFORM authz.model_remove_type_restrictions('test_rc', 'doc', 'viewer');
    PERFORM authz.model_set_relation_constraint('test_rc', 'doc', 'viewer', 5);
    PERFORM authz.model_remove_type('test_rc', 'doc', true);
    PERFORM _test_assert('rc_10_remove_type_drops_constraint', (SELECT count(*)::text FROM authz.list_relation_constraints('test_rc')), '0');
    PERFORM _test_assert_true('rc_10_audit_has_history',
        (SELECT count(*) FROM authz.relation_constraints_audit a WHERE a.store_id = authz._s('test_rc')) >= 6, 'audit rows');
    PERFORM authz.delete_store('test_rc2', p_purge_audit => true);
    PERFORM _test_assert('rc_10_delete_store_purges_audit',
        (SELECT count(*)::text FROM authz.relation_constraints_audit a WHERE a.store_id NOT IN (SELECT id FROM authz.stores)), '0');
END;
$$;

-- rc_11 (review db28333): the cap and the model stay consistent in both orders, the direct
-- count is exact above a lowered cap, and a capped write needs READ COMMITTED
SELECT _test_setup_rc();
DO $$
DECLARE v_err text; v_state text; u record;
BEGIN
    PERFORM authz.write_tuple('test_rc', 'user', x.n, 'viewer', 'doc', 'plan') FROM unnest(ARRAY['b1','b2','b3','b4','b5']) AS x(n);
    -- a cap below the current count is accepted (existing data is not re-checked) and reported, not hidden
    PERFORM authz.model_set_relation_constraint('test_rc', 'doc', 'viewer', 2);
    SELECT * INTO u FROM authz.relation_usage('test_rc', 'doc', 'plan', 'viewer');
    PERFORM _test_assert('rc_11_overfull_reported', u.direct_count::text || ' ' || u.max_direct::text || ' ' || u.direct_headroom::text, '5 2 0');
    BEGIN PERFORM authz.write_tuple('test_rc', 'user', 'b6', 'viewer', 'doc', 'plan');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('rc_11_overfull_refuses_more', v_state || ' ' || v_err, 'ZA001 relation viewer on doc:plan is full: 5 of 2 active direct assignments (max_direct)');
    -- a budget never bounds the direct count
    SELECT * INTO u FROM authz.relation_usage('test_rc', 'doc', 'plan', 'viewer', p_limit => 1);
    PERFORM _test_assert('rc_11_budget_leaves_direct_exact', u.direct_count::text || ' ' || u.effective_count::text || ' ' || u.limit_reached::text, '5 1 true');
    -- the reverse order: a wildcard facet / object-wildcard rule on a capped relation is refused
    v_err := NULL;
    BEGIN PERFORM authz.model_add_type_restriction('test_rc', 'doc', 'viewer', 'user', p_allow_wildcard => true);
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('rc_11_facet_on_capped_refused', v_err LIKE 'model_add_type_restriction: viewer on doc is capped%', coalesce(v_err, 'no error'));
    v_err := NULL;
    BEGIN PERFORM authz.model_add_rule('test_rc', 'doc', 'viewer', 'direct', p_allow_object_wildcard => true);
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('rc_11_object_wildcard_rule_on_capped_refused', v_err LIKE 'model_add_rule: viewer on doc is capped%', coalesce(v_err, 'no error'));
    PERFORM _test_assert('rc_11_facet_not_added',
        (SELECT count(*)::text FROM authz.type_restrictions tr WHERE tr.store_id = authz._s('test_rc') AND tr.allow_wildcard), '0');
    -- a stored wildcard tuple that outlived its facet blocks a new cap
    PERFORM authz.model_drop_relation_constraint('test_rc', 'doc', 'viewer');
    PERFORM authz.model_add_type_restriction('test_rc', 'doc', 'viewer', 'user', p_allow_wildcard => true);
    PERFORM authz.write_tuple('test_rc', 'user', '*', 'viewer', 'doc', 'memo');
    PERFORM authz.model_remove_type_restrictions('test_rc', 'doc', 'viewer');
    v_err := NULL;
    BEGIN PERFORM authz.model_set_relation_constraint('test_rc', 'doc', 'viewer', 50);
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('rc_11_stored_wildcard_blocks_cap', v_err LIKE 'model_set_relation_constraint: 1 active wildcard tuple(s) exist for viewer on doc%', coalesce(v_err, 'no error'));
    PERFORM authz.delete_tuple('test_rc', 'user', '*', 'viewer', 'doc', 'memo');
    PERFORM _test_assert_true('rc_11_cap_after_wildcard_deleted', authz.model_set_relation_constraint('test_rc', 'doc', 'viewer', 50) > 0, 'id');
END;
$$;

-- rc_12: a capped write under REPEATABLE READ is refused (25000); uncapped writes are not
BEGIN ISOLATION LEVEL REPEATABLE READ;
DO $$
DECLARE v_err text; v_state text;
BEGIN
    BEGIN PERFORM authz.write_tuple('test_rc', 'user', 'rr', 'viewer', 'doc', 'memo');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('rc_12_repeatable_read_refused', v_state, '25000');
    PERFORM _test_assert_true('rc_12_message', v_err LIKE 'writing to a capped relation (max_direct) requires READ COMMITTED isolation (current: repeatable read)%', coalesce(v_err, 'no error'));
    PERFORM _test_assert('rc_12_uncapped_write_ok', authz.write_tuple('test_rc', 'user', 'rr', 'editor', 'doc', 'memo')::text, 'true');
END;
$$;
COMMIT;

-- rc_13: apply_model where the definition replaces a live cap by a wildcard facet (stale cap goes first)
DO $$
DECLARE v_def jsonb;
BEGIN
    PERFORM authz.create_store('test_rc2');
    PERFORM authz.publish_model('rc_model2', 'test_rc');            -- viewer capped at 50
    PERFORM authz.apply_model('test_rc2', 'rc_model2');
    PERFORM _test_assert('rc_13_cap_applied', (SELECT count(*)::text FROM authz.list_relation_constraints('test_rc2')), '1');
    PERFORM authz.model_drop_relation_constraint('test_rc', 'doc', 'viewer');
    PERFORM authz.model_add_type_restriction('test_rc', 'doc', 'viewer', 'user', p_allow_wildcard => true);
    PERFORM authz.publish_model('rc_model2', 'test_rc');            -- no cap, a user:* facet
    PERFORM authz.apply_model('test_rc2', 'rc_model2');
    PERFORM _test_assert('rc_13_cap_removed_facet_added',
        (SELECT count(*)::text FROM authz.list_relation_constraints('test_rc2')) || ' ' ||
        (SELECT count(*)::text FROM authz.type_restrictions tr WHERE tr.store_id = authz._s('test_rc2') AND tr.allow_wildcard), '0 1');
    PERFORM authz.delete_store('test_rc2', p_purge_audit => true);
    PERFORM authz.delete_store('test_rc', p_purge_audit => true);
END;
$$;

DROP FUNCTION IF EXISTS _test_setup_rc();

SELECT _test_report('relation constraint checks');
