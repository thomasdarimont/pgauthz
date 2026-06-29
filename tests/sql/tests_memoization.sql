-- Correctness tests for the check_access memoization wrapper.
--
-- The memo caches a (relation, object) sub-result within one root check to
-- collapse diamond/converging graphs from O(2^depth) to ~linear. It is only
-- sound if it produces the SAME decision as the un-memoized, path-based
-- evaluator on EVERY input — including cyclic graphs, where a naive cache would
-- be unsound (a node's result can depend on which ancestors are on the path).
--
-- We prove equivalence DIFFERENTIALLY: toggle authz.memoize and compare on vs
-- off across a graph deliberately rich in cycles AND convergence. A single
-- mismatch fails the suite.

SELECT _test_reset();

DO $$
DECLARE
    n_nodes int := 10;
    s    int;
    u    text;
    n    text;
    r_on  boolean;
    r_off boolean;
    mism  int := 0;
BEGIN
    BEGIN PERFORM authz.delete_store('memotest'); EXCEPTION WHEN OTHERS THEN NULL; END;
    s := authz.create_store('memotest');
    INSERT INTO authz.types (store_id, name) VALUES (s, 'user'), (s, 'node');
    INSERT INTO authz.relations (store_id, name)
        VALUES (s, 'parent_a'), (s, 'parent_b'), (s, 'viewer'), (s, 'can_view');

    -- viewer is a direct relation; can_view = viewer OR parent_a->can_view OR parent_b->can_view
    PERFORM authz.model_add_rule('memotest','node','viewer','direct');
    PERFORM authz.model_add_rule('memotest','node','can_view','computed', p_computed_relation=>'viewer');
    PERFORM authz.model_add_rule('memotest','node','can_view','ttu', p_tupleset_relation=>'parent_a', p_tupleset_computed=>'can_view');
    PERFORM authz.model_add_rule('memotest','node','can_view','ttu', p_tupleset_relation=>'parent_b', p_tupleset_computed=>'can_view');

    -- A graph rich in cycles AND converging paths:
    --   parent_a forms a RING (n_i's parent_a = n_{i+1}, n_N's = n_1) → cycles.
    --   parent_b adds skip edges (n_i's parent_b = n_{i+2}) → many nodes are
    --   reachable via multiple distinct paths (diamonds). Both relations feed
    --   can_view, so resolution explores the whole tangled graph.
    PERFORM authz.write_tuple('memotest', 'node', 'n'||(i % n_nodes + 1), 'parent_a', 'node', 'n'||i)
       FROM generate_series(1, n_nodes) i;
    PERFORM authz.write_tuple('memotest', 'node', 'n'||((i + 1) % n_nodes + 1), 'parent_b', 'node', 'n'||i)
       FROM generate_series(1, n_nodes) i;

    -- viewer grants are the only sources of access.
    PERFORM authz.write_tuple('memotest', 'user', 'alice', 'viewer', 'node', 'n3');
    PERFORM authz.write_tuple('memotest', 'user', 'bob',   'viewer', 'node', 'n7');

    -- Anchor: results are non-trivial (not everything false).
    PERFORM _test_assert('memo_00_anchor_direct_grant',
        authz.check_access('memotest','user','alice','can_view','node','n3')::text, 'true');
    PERFORM _test_assert('memo_00b_anchor_via_parent',
        authz.check_access('memotest','user','alice','can_view','node','n2')::text, 'true');  -- n2.parent_a = n3

    -- Differential: memo ON must equal memo OFF for every (user, node), incl.
    -- users with no grant (full cyclic DENY traversal).
    FOREACH u IN ARRAY ARRAY['alice','bob','carol'] LOOP
        FOR n IN SELECT 'n'||g FROM generate_series(1, n_nodes) g LOOP
            PERFORM set_config('authz.memoize', 'off', true);
            r_off := authz.check_access('memotest','user',u,'can_view','node',n);
            PERFORM set_config('authz.memoize', 'on', true);
            r_on  := authz.check_access('memotest','user',u,'can_view','node',n);
            IF r_on IS DISTINCT FROM r_off THEN
                mism := mism + 1;
            END IF;
        END LOOP;
    END LOOP;
    PERFORM set_config('authz.memoize', 'on', true);

    PERFORM _test_assert('memo_01_memo_equals_nomemo_on_cyclic_graph', mism::text, '0');

    -- Same differential for the TIME-TRAVEL evaluator (audit_check_access),
    -- which resolves against the replayed audit snapshot through its own
    -- memoizing wrapper. p_at is set just past these writes so the whole
    -- graph is in the snapshot. The live and snapshot paths share the
    -- authz.memoize kill-switch but use independent memo state.
    mism := 0;
    FOREACH u IN ARRAY ARRAY['alice','bob','carol'] LOOP
        FOR n IN SELECT 'n'||g FROM generate_series(1, n_nodes) g LOOP
            PERFORM set_config('authz.memoize', 'off', true);
            r_off := authz.audit_check_access('memotest','user',u,'can_view','node',n, now() + interval '1 hour');
            PERFORM set_config('authz.memoize', 'on', true);
            r_on  := authz.audit_check_access('memotest','user',u,'can_view','node',n, now() + interval '1 hour');
            IF r_on IS DISTINCT FROM r_off THEN
                mism := mism + 1;
            END IF;
        END LOOP;
    END LOOP;
    PERFORM set_config('authz.memoize', 'on', true);

    PERFORM _test_assert('memo_02_audit_memo_equals_nomemo_on_cyclic_graph', mism::text, '0');

    -- And the time-travel result must equal the live result on this graph
    -- (no edits between the writes and p_at, so the snapshot == current).
    mism := 0;
    FOREACH u IN ARRAY ARRAY['alice','bob','carol'] LOOP
        FOR n IN SELECT 'n'||g FROM generate_series(1, n_nodes) g LOOP
            IF authz.audit_check_access('memotest','user',u,'can_view','node',n, now() + interval '1 hour')
               IS DISTINCT FROM authz.check_access('memotest','user',u,'can_view','node',n) THEN
                mism := mism + 1;
            END IF;
        END LOOP;
    END LOOP;
    PERFORM _test_assert('memo_03_audit_equals_live_on_cyclic_graph', mism::text, '0');

    PERFORM authz.delete_store('memotest');
END $$;

SELECT _test_report('checks');
