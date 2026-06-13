-- Tests for recursion behavior: cycle detection (cyclic relationships
-- must terminate without granting access) and the resolution depth
-- limit (exceeding it raises instead of silently denying).

SELECT _test_reset();

-- Model:
--   type team    { member: [user, team#member] }
--   type folder  { viewer: [user] or viewer from parent; parent: [folder] }
--   type doc     { viewer: [user, team#member] }
-- Data:
--   team a <-> team b membership cycle; alice direct member of team a
--   doc1 viewer: team:a#member
--   ok-chain:   f1 <- f2 <- ... <- f10  (alice viewer on f10)
--   mid-chain:  m1 <- m2 <- ... <- m25  (alice viewer on m25; within
--               the default limit of 32, beyond the old limit of 15)
--   deep-chain: g1 <- g2 <- ... <- g40  (alice viewer on g40; beyond
--               the default limit)
DROP FUNCTION IF EXISTS _test_setup_rec();
CREATE OR REPLACE FUNCTION _test_setup_rec() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    s smallint;
    i int;
BEGIN
    BEGIN PERFORM authz.delete_store('test_rec'); EXCEPTION WHEN OTHERS THEN NULL; END;

    s := authz.create_store('test_rec');
    INSERT INTO authz.types (store_id, name) VALUES (s, 'user'), (s, 'team'), (s, 'folder'), (s, 'doc');
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'member'), (s, 'viewer'), (s, 'parent');
    PERFORM authz._ensure_tuple_partition(s, 'folder');
    PERFORM authz._ensure_tuple_partition(s, 'doc');

    INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                              computed_relation, tupleset_relation, tupleset_computed)
    VALUES
        (s, authz._t(s, 'team'),   authz._r(s, 'member'), authz._rel_direct(), NULL, NULL, NULL),
        (s, authz._t(s, 'doc'),    authz._r(s, 'viewer'), authz._rel_direct(), NULL, NULL, NULL),
        (s, authz._t(s, 'folder'), authz._r(s, 'viewer'), authz._rel_direct(), NULL, NULL, NULL),
        (s, authz._t(s, 'folder'), authz._r(s, 'viewer'), authz._rel_ttu(),
            NULL, authz._r(s, 'parent'), authz._r(s, 'viewer'));

    -- Membership cycle: each team's members include the other team's members
    PERFORM authz.write_tuple('test_rec', 'team', 'b', 'member', 'team', 'a', p_user_relation => 'member');
    PERFORM authz.write_tuple('test_rec', 'team', 'a', 'member', 'team', 'b', p_user_relation => 'member');
    PERFORM authz.write_tuple('test_rec', 'user', 'alice', 'member', 'team', 'a');

    -- doc1 readable by team a members
    PERFORM authz.write_tuple('test_rec', 'team', 'a', 'viewer', 'doc', 'doc1', p_user_relation => 'member');

    -- ok-chain: 9 TTU hops, within the depth limit
    FOR i IN 1..9 LOOP
        PERFORM authz.write_tuple('test_rec', 'folder', 'f' || (i + 1), 'parent', 'folder', 'f' || i);
    END LOOP;
    PERFORM authz.write_tuple('test_rec', 'user', 'alice', 'viewer', 'folder', 'f10');

    -- mid-chain: 24 TTU hops, within the default depth limit
    FOR i IN 1..24 LOOP
        PERFORM authz.write_tuple('test_rec', 'folder', 'm' || (i + 1), 'parent', 'folder', 'm' || i);
    END LOOP;
    PERFORM authz.write_tuple('test_rec', 'user', 'alice', 'viewer', 'folder', 'm25');

    -- deep-chain: 39 TTU hops, beyond the default depth limit
    FOR i IN 1..39 LOOP
        PERFORM authz.write_tuple('test_rec', 'folder', 'g' || (i + 1), 'parent', 'folder', 'g' || i);
    END LOOP;
    PERFORM authz.write_tuple('test_rec', 'user', 'alice', 'viewer', 'folder', 'g40');

    RETURN true;
END;
$$;

DROP FUNCTION IF EXISTS _test_teardown_rec();
CREATE OR REPLACE FUNCTION _test_teardown_rec()
RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    PERFORM authz.delete_store('test_rec');
    RETURN QUERY DELETE FROM _test_results RETURNING *;
END;
$$;

-- rec_01..03: cycles terminate with correct results
DO $$
BEGIN
    PERFORM _test_setup_rec();

    -- alice is granted through team a despite the a<->b cycle
    PERFORM _test_assert('rec_01_member_in_cyclic_team_allowed',
        authz.check_access('test_rec', 'user', 'alice', 'viewer', 'doc', 'doc1')::text, 'true');

    -- bob is in neither team: the cycle is pruned and the check denies
    PERFORM _test_assert('rec_02_nonmember_cyclic_team_denied',
        authz.check_access('test_rec', 'user', 'bob', 'viewer', 'doc', 'doc1')::text, 'false');

    -- membership through the cycle itself does not grant
    PERFORM _test_assert('rec_03_cycle_itself_grants_nothing',
        authz.check_access('test_rec', 'user', 'bob', 'member', 'team', 'a')::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_rec();

-- rec_04/04a/05: hierarchies within the limit resolve; beyond it raise
SELECT _test_setup_rec();
DO $$
BEGIN
    PERFORM _test_assert('rec_04_deep_chain_within_limit_allowed',
        authz.check_access('test_rec', 'user', 'alice', 'viewer', 'folder', 'f1')::text, 'true');

    -- 24 hops: within the default limit of 32
    PERFORM _test_assert('rec_04a_mid_chain_within_default_limit_allowed',
        authz.check_access('test_rec', 'user', 'alice', 'viewer', 'folder', 'm1')::text, 'true');
END;
$$;
DO $$
BEGIN
    PERFORM authz.check_access('test_rec', 'user', 'alice', 'viewer', 'folder', 'g1');
    PERFORM _test_assert_true('rec_05_beyond_depth_limit_raises', false,
        'expected exception, got silent result');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('rec_05_beyond_depth_limit_raises',
        SQLERRM LIKE '%depth%', SQLERRM);
END;
$$;
-- rec_05a: the limit is configurable via the authz.max_depth GUC
DO $$
BEGIN
    PERFORM set_config('authz.max_depth', '5', true);
    BEGIN
        PERFORM authz.check_access('test_rec', 'user', 'alice', 'viewer', 'folder', 'f1');
        PERFORM set_config('authz.max_depth', '', true);
        PERFORM _test_assert_true('rec_05a_guc_lowers_depth_limit', false,
            'expected exception with authz.max_depth = 5');
    EXCEPTION WHEN raise_exception THEN
        PERFORM set_config('authz.max_depth', '', true);
        PERFORM _test_assert_true('rec_05a_guc_lowers_depth_limit',
            SQLERRM LIKE '%depth (5)%', SQLERRM);
    END;
END;
$$;
SELECT * FROM _test_teardown_rec();

-- rec_06/07: the time-travel snapshot evaluator behaves the same
SELECT _test_setup_rec();
DO $$
BEGIN
    PERFORM _test_assert('rec_06_audit_cycle_denied',
        authz.audit_check_access('test_rec', 'user', 'bob', 'viewer', 'doc', 'doc1',
            clock_timestamp())::text, 'false');
END;
$$;
DO $$
BEGIN
    PERFORM authz.audit_check_access('test_rec', 'user', 'alice', 'viewer', 'folder', 'g1',
        clock_timestamp());
    PERFORM _test_assert_true('rec_07_audit_beyond_depth_limit_raises', false,
        'expected exception, got silent result');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('rec_07_audit_beyond_depth_limit_raises',
        SQLERRM LIKE '%depth%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_rec();

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_rec();
DROP FUNCTION IF EXISTS _test_setup_rec();

SELECT _test_report('recursion checks');
