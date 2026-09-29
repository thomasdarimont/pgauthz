-- Resolver regression shapes — graph structures that broke OpenFGA's v2
-- ("weighted graph") check resolver during 2026 (release notes v1.16.1 →
-- v1.20.0), pinned here as fixed-answer fixtures for pgauthz's recursive walk
-- and its memoization wrapper:
--
--   S1  #3244  relations crossing two distinct recursive TTUs that share one
--              tupleset relation (viewer-from-parent AND editor-from-parent)
--   S2  #3239  multi-branch recursion on the same relation (viewer from parent
--              OR viewer from linked), with a cycle and a diamond
--   S3  #3195  independently-recursive relations joined by a union
--   S4  #3224  deep nesting: resolves up to the depth limit, fails CLOSED with
--              an error beyond it (never a silent false)
--   S5  #3145  contextual (ephemeral) tuples mixed with stored ones inside a
--              userset + intersection, in any order
--   S6  #3284  wide union / intersection operand sets, incl. enumeration
--   (nested exclusion on a wildcard base — GHSA-h7w8 — lives in
--    tests_list_subjects ls_04b; condition-facet binding — #3218 — in
--    tests_type_restrictions tr_16/17)
--
-- Every check is asserted THREE ways: the expected answer with the memo on,
-- memo off == memo on, and check == membership in list_objects / list_subjects
-- (the enumerations must never disagree with the decision).

SELECT _test_reset();

-- ── helpers ───────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION pg_temp._rs(p_name text, p_store text, p_user text, p_rel text,
                                       p_ot text, p_oid text, p_expected boolean)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE r_on boolean; r_off boolean;
BEGIN
    PERFORM set_config('authz.memoize', 'off', true);
    r_off := authz.check_access(p_store, 'user', p_user, p_rel, p_ot, p_oid);
    PERFORM set_config('authz.memoize', 'on', true);
    r_on  := authz.check_access(p_store, 'user', p_user, p_rel, p_ot, p_oid);
    PERFORM _test_assert(p_name, r_on::text, p_expected::text);
    PERFORM _test_assert(p_name || '__memo_agrees', r_off::text, r_on::text);
END $$;

-- check == list_objects membership == list_subjects membership, for every pair
CREATE OR REPLACE FUNCTION pg_temp._rs_lists(p_name text, p_store text, p_users text[],
                                             p_rel text, p_ot text, p_objects text[])
RETURNS void LANGUAGE plpgsql AS $$
DECLARE u text; o text; c boolean; in_lo boolean; in_ls boolean; mism int := 0; first text := '';
BEGIN
    FOREACH u IN ARRAY p_users LOOP
        FOREACH o IN ARRAY p_objects LOOP
            c     := authz.check_access(p_store, 'user', u, p_rel, p_ot, o);
            in_lo := EXISTS (SELECT 1 FROM authz.list_objects(p_store, 'user', u, p_rel, p_ot, p_limit => 1000) l WHERE l.object_id = o);
            in_ls := EXISTS (SELECT 1 FROM authz.list_subjects(p_store, 'user', p_rel, p_ot, o, p_limit => 1000) l WHERE l.subject_id = u);
            IF c IS DISTINCT FROM in_lo OR c IS DISTINCT FROM in_ls THEN
                mism := mism + 1;
                IF first = '' THEN first := format('%s %s %s:%s check=%s list_objects=%s list_subjects=%s', u, p_rel, p_ot, o, c, in_lo, in_ls); END IF;
            END IF;
        END LOOP;
    END LOOP;
    PERFORM _test_assert(p_name, mism::text, '0');
    IF mism > 0 THEN RAISE WARNING '% first disagreement: %', p_name, first; END IF;
END $$;

-- ── S1: two recursive TTUs sharing the tupleset relation `parent` ─────────────
DO $$
BEGIN
    BEGIN PERFORM authz.delete_store('rs1'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('rs1');
    PERFORM authz.model_register_type('rs1', 'user');
    PERFORM authz.model_register_type('rs1', 'folder');
    PERFORM authz.model_register_type('rs1', 'doc');
    PERFORM authz.model_register_relation('rs1', 'parent');
    PERFORM authz.model_register_relation('rs1', 'viewer');
    PERFORM authz.model_register_relation('rs1', 'editor');
    PERFORM authz.model_register_relation('rs1', 'can_view');
    PERFORM authz.model_add_rule('rs1', 'folder', 'parent', 'direct');
    PERFORM authz.model_add_rule('rs1', 'folder', 'viewer', 'direct');
    PERFORM authz.model_add_rule('rs1', 'folder', 'viewer', 'ttu', p_tupleset_relation => 'parent', p_tupleset_computed => 'viewer');
    PERFORM authz.model_add_rule('rs1', 'folder', 'editor', 'direct');
    PERFORM authz.model_add_rule('rs1', 'folder', 'editor', 'ttu', p_tupleset_relation => 'parent', p_tupleset_computed => 'editor');
    -- can_view crosses BOTH recursive TTUs (same tupleset relation) + recurses itself
    PERFORM authz.model_add_rule('rs1', 'folder', 'can_view', 'computed', p_computed_relation => 'viewer');
    PERFORM authz.model_add_rule('rs1', 'folder', 'can_view', 'computed', p_computed_relation => 'editor');
    PERFORM authz.model_add_rule('rs1', 'folder', 'can_view', 'ttu', p_tupleset_relation => 'parent', p_tupleset_computed => 'can_view');
    PERFORM authz.model_add_rule('rs1', 'doc', 'parent', 'direct');
    PERFORM authz.model_add_rule('rs1', 'doc', 'can_view', 'ttu', p_tupleset_relation => 'parent', p_tupleset_computed => 'can_view');

    -- chain f1 <- f2 <- f3 <- f4 <- d1  (X parent Y == Y's parent is X)
    PERFORM authz.write_tuple('rs1', 'folder', 'f1', 'parent', 'folder', 'f2');
    PERFORM authz.write_tuple('rs1', 'folder', 'f2', 'parent', 'folder', 'f3');
    PERFORM authz.write_tuple('rs1', 'folder', 'f3', 'parent', 'folder', 'f4');
    PERFORM authz.write_tuple('rs1', 'folder', 'f4', 'parent', 'doc', 'd1');
    PERFORM authz.write_tuple('rs1', 'user', 'alice', 'viewer', 'folder', 'f1');
    PERFORM authz.write_tuple('rs1', 'user', 'bob',   'editor', 'folder', 'f2');
    PERFORM authz.write_tuple('rs1', 'user', 'erin',  'viewer', 'folder', 'f4');

    PERFORM pg_temp._rs('rs1_01_viewer_chain_reaches_doc',  'rs1', 'alice', 'can_view', 'doc', 'd1', true);
    PERFORM pg_temp._rs('rs1_02_editor_chain_reaches_doc',  'rs1', 'bob',   'can_view', 'doc', 'd1', true);
    PERFORM pg_temp._rs('rs1_03_leaf_grant_reaches_doc',    'rs1', 'erin',  'can_view', 'doc', 'd1', true);
    PERFORM pg_temp._rs('rs1_04_ungranted_denied',          'rs1', 'carol', 'can_view', 'doc', 'd1', false);
    PERFORM pg_temp._rs('rs1_05_viewer_recurses_alone',     'rs1', 'alice', 'viewer',   'folder', 'f4', true);
    PERFORM pg_temp._rs('rs1_06_viewer_does_not_leak_into_editor', 'rs1', 'alice', 'editor', 'folder', 'f4', false);
    PERFORM pg_temp._rs('rs1_07_editor_recurses_alone',     'rs1', 'bob',   'editor',   'folder', 'f4', true);
    PERFORM pg_temp._rs('rs1_08_editor_does_not_leak_into_viewer', 'rs1', 'bob', 'viewer', 'folder', 'f4', false);
    PERFORM pg_temp._rs('rs1_09_no_upward_leak',            'rs1', 'erin',  'can_view', 'folder', 'f1', false);
    PERFORM pg_temp._rs_lists('rs1_10_lists_agree_can_view', 'rs1', ARRAY['alice','bob','carol','erin'], 'can_view', 'folder', ARRAY['f1','f2','f3','f4']);
    PERFORM pg_temp._rs_lists('rs1_11_lists_agree_doc',      'rs1', ARRAY['alice','bob','carol','erin'], 'can_view', 'doc', ARRAY['d1']);
    PERFORM authz.delete_store('rs1');
END $$;

-- ── S2: multi-branch recursion on ONE relation (parent OR linked), cycle, diamond
DO $$
BEGIN
    BEGIN PERFORM authz.delete_store('rs2'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('rs2');
    PERFORM authz.model_register_type('rs2', 'user');
    PERFORM authz.model_register_type('rs2', 'folder');
    PERFORM authz.model_register_relation('rs2', 'parent');
    PERFORM authz.model_register_relation('rs2', 'linked');
    PERFORM authz.model_register_relation('rs2', 'viewer');
    PERFORM authz.model_add_rule('rs2', 'folder', 'parent', 'direct');
    PERFORM authz.model_add_rule('rs2', 'folder', 'linked', 'direct');
    PERFORM authz.model_add_rule('rs2', 'folder', 'viewer', 'direct');
    PERFORM authz.model_add_rule('rs2', 'folder', 'viewer', 'ttu', p_tupleset_relation => 'parent', p_tupleset_computed => 'viewer');
    PERFORM authz.model_add_rule('rs2', 'folder', 'viewer', 'ttu', p_tupleset_relation => 'linked', p_tupleset_computed => 'viewer');

    -- fa -linked-> fb -parent-> fc -linked-> fd -parent-> fa   (a cycle through both branches)
    PERFORM authz.write_tuple('rs2', 'folder', 'fb', 'linked', 'folder', 'fa');
    PERFORM authz.write_tuple('rs2', 'folder', 'fc', 'parent', 'folder', 'fb');
    PERFORM authz.write_tuple('rs2', 'folder', 'fd', 'linked', 'folder', 'fc');
    PERFORM authz.write_tuple('rs2', 'folder', 'fa', 'parent', 'folder', 'fd');
    PERFORM authz.write_tuple('rs2', 'user', 'dan', 'viewer', 'folder', 'fd');
    -- diamond: fx reaches fy through BOTH branches
    PERFORM authz.write_tuple('rs2', 'folder', 'fy', 'parent', 'folder', 'fx');
    PERFORM authz.write_tuple('rs2', 'folder', 'fy', 'linked', 'folder', 'fx');
    PERFORM authz.write_tuple('rs2', 'user', 'grace', 'viewer', 'folder', 'fy');

    PERFORM pg_temp._rs('rs2_01_mixed_branch_chain',   'rs2', 'dan',   'viewer', 'folder', 'fa', true);
    PERFORM pg_temp._rs('rs2_02_mixed_branch_chain_b', 'rs2', 'dan',   'viewer', 'folder', 'fb', true);
    PERFORM pg_temp._rs('rs2_03_mixed_branch_chain_c', 'rs2', 'dan',   'viewer', 'folder', 'fc', true);
    PERFORM pg_temp._rs('rs2_04_cycle_terminates_deny', 'rs2', 'eve',  'viewer', 'folder', 'fa', false);
    PERFORM pg_temp._rs('rs2_05_diamond_allows',        'rs2', 'grace', 'viewer', 'folder', 'fx', true);
    PERFORM pg_temp._rs('rs2_06_diamond_no_leak',       'rs2', 'grace', 'viewer', 'folder', 'fa', false);
    PERFORM pg_temp._rs_lists('rs2_07_lists_agree', 'rs2', ARRAY['dan','eve','grace'], 'viewer', 'folder', ARRAY['fa','fb','fc','fd','fx','fy']);
    PERFORM authz.delete_store('rs2');
END $$;

-- ── S3: independently-recursive relations joined by a union ───────────────────
DO $$
BEGIN
    BEGIN PERFORM authz.delete_store('rs3'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('rs3');
    PERFORM authz.model_register_type('rs3', 'user');
    PERFORM authz.model_register_type('rs3', 'node');
    PERFORM authz.model_register_relation('rs3', 'parent');
    PERFORM authz.model_register_relation('rs3', 'container');
    PERFORM authz.model_register_relation('rs3', 'viewer');
    PERFORM authz.model_register_relation('rs3', 'editor');
    PERFORM authz.model_register_relation('rs3', 'can_read');
    PERFORM authz.model_add_rule('rs3', 'node', 'parent', 'direct');
    PERFORM authz.model_add_rule('rs3', 'node', 'container', 'direct');
    PERFORM authz.model_add_rule('rs3', 'node', 'viewer', 'direct');
    PERFORM authz.model_add_rule('rs3', 'node', 'viewer', 'ttu', p_tupleset_relation => 'parent',    p_tupleset_computed => 'viewer');
    PERFORM authz.model_add_rule('rs3', 'node', 'editor', 'direct');
    PERFORM authz.model_add_rule('rs3', 'node', 'editor', 'ttu', p_tupleset_relation => 'container', p_tupleset_computed => 'editor');
    PERFORM authz.model_add_rule('rs3', 'node', 'can_read', 'computed', p_computed_relation => 'viewer');
    PERFORM authz.model_add_rule('rs3', 'node', 'can_read', 'computed', p_computed_relation => 'editor');

    -- parent chain p1 <- p2 <- p3 <- leaf ; container chain c1 <- c2 <- c3 <- leaf
    PERFORM authz.write_tuple('rs3', 'node', 'p1', 'parent', 'node', 'p2');
    PERFORM authz.write_tuple('rs3', 'node', 'p2', 'parent', 'node', 'p3');
    PERFORM authz.write_tuple('rs3', 'node', 'p3', 'parent', 'node', 'leaf');
    PERFORM authz.write_tuple('rs3', 'node', 'c1', 'container', 'node', 'c2');
    PERFORM authz.write_tuple('rs3', 'node', 'c2', 'container', 'node', 'c3');
    PERFORM authz.write_tuple('rs3', 'node', 'c3', 'container', 'node', 'leaf');
    -- cross-wiring that must NOT create a path: a container link on the parent chain
    PERFORM authz.write_tuple('rs3', 'node', 'p1', 'container', 'node', 'p2');
    PERFORM authz.write_tuple('rs3', 'user', 'hank', 'viewer', 'node', 'p1');
    PERFORM authz.write_tuple('rs3', 'user', 'ivy',  'editor', 'node', 'c1');

    PERFORM pg_temp._rs('rs3_01_parent_chain_can_read',    'rs3', 'hank', 'can_read', 'node', 'leaf', true);
    PERFORM pg_temp._rs('rs3_02_container_chain_can_read', 'rs3', 'ivy',  'can_read', 'node', 'leaf', true);
    PERFORM pg_temp._rs('rs3_03_viewer_not_via_container', 'rs3', 'hank', 'editor',   'node', 'leaf', false);
    PERFORM pg_temp._rs('rs3_04_editor_not_via_parent',    'rs3', 'ivy',  'viewer',   'node', 'leaf', false);
    PERFORM pg_temp._rs('rs3_05_cross_wired_link_no_path', 'rs3', 'hank', 'editor',   'node', 'p2',   false);
    PERFORM pg_temp._rs_lists('rs3_06_lists_agree', 'rs3', ARRAY['hank','ivy','nobody'], 'can_read', 'node', ARRAY['p1','p2','p3','c1','c2','c3','leaf']);
    PERFORM authz.delete_store('rs3');
END $$;

-- ── S4: deep nesting — resolves to the limit, fails CLOSED with an error past it
DO $$
DECLARE i int; v_msg text; v_msg_off text;
BEGIN
    BEGIN PERFORM authz.delete_store('rs4'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('rs4');
    PERFORM authz.model_register_type('rs4', 'user');
    PERFORM authz.model_register_type('rs4', 'folder');
    PERFORM authz.model_register_relation('rs4', 'parent');
    PERFORM authz.model_register_relation('rs4', 'viewer');
    PERFORM authz.model_add_rule('rs4', 'folder', 'parent', 'direct');
    PERFORM authz.model_add_rule('rs4', 'folder', 'viewer', 'direct');
    PERFORM authz.model_add_rule('rs4', 'folder', 'viewer', 'ttu', p_tupleset_relation => 'parent', p_tupleset_computed => 'viewer');
    -- n0 <- n1 <- ... <- n30 (within the limit) and, separately, m0 <- ... <- m40
    -- (past it — its own chain, so list_objects on jack never has to verify a
    -- folder the engine refuses to resolve)
    FOR i IN 1..30 LOOP
        PERFORM authz.write_tuple('rs4', 'folder', 'n' || (i - 1), 'parent', 'folder', 'n' || i);
    END LOOP;
    FOR i IN 1..40 LOOP
        PERFORM authz.write_tuple('rs4', 'folder', 'm' || (i - 1), 'parent', 'folder', 'm' || i);
    END LOOP;
    PERFORM authz.write_tuple('rs4', 'user', 'jack', 'viewer', 'folder', 'n0');
    PERFORM authz.write_tuple('rs4', 'user', 'jill', 'viewer', 'folder', 'm0');

    -- within the limit (default authz.max_depth = 32): a 30-hop chain resolves
    PERFORM pg_temp._rs('rs4_01_depth30_allows', 'rs4', 'jack', 'viewer', 'folder', 'n30', true);
    PERFORM pg_temp._rs('rs4_02_depth30_other_user_denies', 'rs4', 'kate', 'viewer', 'folder', 'n30', false);
    PERFORM _test_assert('rs4_03_list_objects_walks_depth',
        (SELECT count(*)::text FROM authz.list_objects('rs4', 'user', 'jack', 'viewer', 'folder', p_limit => 100)), '31');

    -- beyond the limit: an ERROR in both modes — never a silent false
    BEGIN
        PERFORM set_config('authz.memoize', 'on', true);
        PERFORM authz.check_access('rs4', 'user', 'jill', 'viewer', 'folder', 'm40');
        v_msg := 'no error';
    EXCEPTION WHEN OTHERS THEN v_msg := SQLERRM; END;
    BEGIN
        PERFORM set_config('authz.memoize', 'off', true);
        PERFORM authz.check_access('rs4', 'user', 'jill', 'viewer', 'folder', 'm40');
        v_msg_off := 'no error';
    EXCEPTION WHEN OTHERS THEN v_msg_off := SQLERRM; END;
    PERFORM set_config('authz.memoize', 'on', true);
    PERFORM _test_assert_true('rs4_04_past_limit_fails_closed_memo_on',  v_msg     LIKE '%maximum resolution depth%', v_msg);
    PERFORM _test_assert_true('rs4_05_past_limit_fails_closed_memo_off', v_msg_off LIKE '%maximum resolution depth%', v_msg_off);
    PERFORM authz.delete_store('rs4');
END $$;

-- ── S5: contextual tuples mixed with stored ones (userset + intersection) ────
DO $$
DECLARE r1 boolean; r2 boolean; r3 boolean; r_off boolean;
BEGIN
    BEGIN PERFORM authz.delete_store('rs5'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('rs5');
    PERFORM authz.model_register_type('rs5', 'user');
    PERFORM authz.model_register_type('rs5', 'group');
    PERFORM authz.model_register_type('rs5', 'doc');
    PERFORM authz.model_register_relation('rs5', 'member');
    PERFORM authz.model_register_relation('rs5', 'viewer');
    PERFORM authz.model_register_relation('rs5', 'owner');
    PERFORM authz.model_register_relation('rs5', 'can_edit');
    PERFORM authz.model_add_rule('rs5', 'group', 'member', 'direct');
    PERFORM authz.model_add_rule('rs5', 'doc', 'viewer', 'direct');
    PERFORM authz.model_add_rule('rs5', 'doc', 'owner', 'direct');
    PERFORM authz.model_add_rule('rs5', 'doc', 'can_edit', 'computed', p_computed_relation => 'viewer', p_group_id => 1, p_group_op => 'intersection');
    PERFORM authz.model_add_rule('rs5', 'doc', 'can_edit', 'computed', p_computed_relation => 'owner',  p_group_id => 1, p_group_op => 'intersection');

    -- stored: g1#member are viewers of d1; kim owns d1. Membership arrives contextually.
    PERFORM authz.write_tuple('rs5', 'group', 'g1', 'viewer', 'doc', 'd1', p_user_relation => 'member');
    PERFORM authz.write_tuple('rs5', 'user', 'kim', 'owner', 'doc', 'd1');

    PERFORM _test_assert('rs5_01_without_context_denied',
        authz.check_access('rs5', 'user', 'kim', 'can_edit', 'doc', 'd1')::text, 'false');
    -- one contextual tuple completes the userset leg of the intersection
    r1 := authz.check_access_with_contextual_tuples('rs5', 'user', 'kim', 'can_edit', 'doc', 'd1', NULL,
              ARRAY[ROW('user', 'kim', NULL, 'member', 'group', 'g1')::authz.tuple_input]);
    PERFORM _test_assert('rs5_02_contextual_membership_allows', r1::text, 'true');
    -- nested membership supplied out of order (inner link listed after the outer one)
    r2 := authz.check_access_with_contextual_tuples('rs5', 'user', 'lee', 'can_edit', 'doc', 'd1', NULL,
              ARRAY[ROW('user',  'lee', NULL,     'member', 'group', 'g2')::authz.tuple_input,
                    ROW('user',  'lee', NULL,     'owner',  'doc',   'd1')::authz.tuple_input,
                    ROW('group', 'g2',  'member', 'member', 'group', 'g1')::authz.tuple_input]);
    PERFORM _test_assert('rs5_03_nested_contextual_any_order_allows', r2::text, 'true');
    -- the same facts stored instead of injected give the same answer
    PERFORM authz.write_tuple('rs5', 'user', 'kim', 'member', 'group', 'g1');
    r3 := authz.check_access('rs5', 'user', 'kim', 'can_edit', 'doc', 'd1');
    PERFORM _test_assert('rs5_04_stored_equals_contextual', r3::text, r1::text);
    -- memo off agrees for the contextual evaluation
    PERFORM set_config('authz.memoize', 'off', true);
    r_off := authz.check_access_with_contextual_tuples('rs5', 'user', 'lee', 'can_edit', 'doc', 'd1', NULL,
              ARRAY[ROW('user',  'lee', NULL,     'member', 'group', 'g2')::authz.tuple_input,
                    ROW('user',  'lee', NULL,     'owner',  'doc',   'd1')::authz.tuple_input,
                    ROW('group', 'g2',  'member', 'member', 'group', 'g1')::authz.tuple_input]);
    PERFORM set_config('authz.memoize', 'on', true);
    PERFORM _test_assert('rs5_05_memo_off_agrees_contextual', r_off::text, r2::text);
    -- a contextual tuple must not satisfy a leg it does not name
    PERFORM _test_assert('rs5_06_contextual_does_not_leak_legs',
        authz.check_access_with_contextual_tuples('rs5', 'user', 'max', 'can_edit', 'doc', 'd1', NULL,
            ARRAY[ROW('user', 'max', NULL, 'member', 'group', 'g1')::authz.tuple_input])::text, 'false');
    PERFORM authz.delete_store('rs5');
END $$;

-- ── S6: wide union / intersection operand sets + enumeration ─────────────────
DO $$
DECLARE i int; j int;
BEGIN
    BEGIN PERFORM authz.delete_store('rs6'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('rs6');
    PERFORM authz.model_register_type('rs6', 'user');
    PERFORM authz.model_register_type('rs6', 'doc');
    PERFORM authz.model_register_relation('rs6', 'can_read');
    PERFORM authz.model_register_relation('rs6', 'all_of');
    FOR i IN 1..12 LOOP
        PERFORM authz.model_register_relation('rs6', 'r' || i);
        PERFORM authz.model_add_rule('rs6', 'doc', 'r' || i, 'direct');
        PERFORM authz.model_add_rule('rs6', 'doc', 'can_read', 'computed', p_computed_relation => 'r' || i);   -- 12-way union
    END LOOP;
    FOR i IN 1..6 LOOP
        PERFORM authz.model_register_relation('rs6', 'a' || i);
        PERFORM authz.model_add_rule('rs6', 'doc', 'a' || i, 'direct');
        PERFORM authz.model_add_rule('rs6', 'doc', 'all_of', 'computed', p_computed_relation => 'a' || i,
                                     p_group_id => 1, p_group_op => 'intersection');                       -- 6-way intersection
    END LOOP;
    -- 40 users spread over the 12 union operands; users 1..6 hold all six
    -- intersection operands, 7..12 hold only five
    FOR i IN 1..40 LOOP
        PERFORM authz.write_tuple('rs6', 'user', 'u' || i, 'r' || (1 + (i % 12)), 'doc', 'd1');
    END LOOP;
    FOR i IN 1..12 LOOP
        FOR j IN 1..(CASE WHEN i <= 6 THEN 6 ELSE 5 END) LOOP
            PERFORM authz.write_tuple('rs6', 'user', 'u' || i, 'a' || j, 'doc', 'd1');
        END LOOP;
    END LOOP;

    PERFORM pg_temp._rs('rs6_01_union_last_operand',   'rs6', 'u12', 'can_read', 'doc', 'd1', true);
    PERFORM pg_temp._rs('rs6_02_union_first_operand',  'rs6', 'u1',  'can_read', 'doc', 'd1', true);
    PERFORM pg_temp._rs('rs6_03_union_ungranted',      'rs6', 'u99', 'can_read', 'doc', 'd1', false);
    PERFORM pg_temp._rs('rs6_04_intersection_full',    'rs6', 'u3',  'all_of',   'doc', 'd1', true);
    PERFORM pg_temp._rs('rs6_05_intersection_missing_one', 'rs6', 'u9', 'all_of', 'doc', 'd1', false);
    PERFORM _test_assert('rs6_06_list_subjects_union_count',
        (SELECT count(*)::text FROM authz.list_subjects('rs6', 'user', 'can_read', 'doc', 'd1', p_limit => 1000)), '40');
    PERFORM _test_assert('rs6_07_list_subjects_intersection_count',
        (SELECT count(*)::text FROM authz.list_subjects('rs6', 'user', 'all_of', 'doc', 'd1', p_limit => 1000)), '6');
    PERFORM pg_temp._rs_lists('rs6_08_lists_agree_all_of', 'rs6', ARRAY['u1','u6','u7','u12','u13','u99'], 'all_of', 'doc', ARRAY['d1']);
    PERFORM authz.delete_store('rs6');
END $$;

DROP FUNCTION IF EXISTS pg_temp._rs(text, text, text, text, text, text, boolean);
DROP FUNCTION IF EXISTS pg_temp._rs_lists(text, text, text[], text, text, text[]);

SELECT _test_report('resolver regression shapes (OpenFGA v2-resolver bug classes)');
