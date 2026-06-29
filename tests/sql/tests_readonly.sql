-- check_access must resolve in a READ ONLY transaction (a hot standby / read
-- replica) AND stay protected against converging/diamond graphs there.
--
-- The memo wrapper normally uses a session temp table, which cannot be created
-- in a read-only transaction. On the read-only path it switches to a session-GUC
-- jsonb backend (authz._memo_mode = 'guc') — slower than the temp table but still
-- polynomial, so the read path is both correct and protected. This reproduces
-- the read-only path with SET TRANSACTION READ ONLY (no replica needed);
-- set_config is allowed read-only, so we stash results in GUCs and assert after.

SELECT _test_reset();

-- ── Fixture 1: a small computed chain (writable / autocommit) ────────────────
DO $$
DECLARE s int;
BEGIN
    BEGIN PERFORM authz.delete_store('rotest'); EXCEPTION WHEN OTHERS THEN NULL; END;
    s := authz.create_store('rotest');
    INSERT INTO authz.types (store_id, name) VALUES (s, 'user'), (s, 'doc');
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'viewer'), (s, 'editor'), (s, 'can_view');
    PERFORM authz.model_add_rule('rotest','doc','viewer','direct');
    PERFORM authz.model_add_rule('rotest','doc','editor','direct');
    PERFORM authz.model_add_rule('rotest','doc','can_view','computed', p_computed_relation=>'viewer');
    PERFORM authz.model_add_rule('rotest','doc','can_view','computed', p_computed_relation=>'editor');
    PERFORM authz.write_tuple('rotest','user','alice','viewer','doc','d1');
END $$;

-- ── Fixture 2: an acyclic CONVERGING diamond (the pathological case) ──────────
-- node n_i has parent_a = n_{i+1} and parent_b = n_{i+2}; can_view propagates up
-- through parents to the anchor n_N where alice is a viewer. Reaching n_N from
-- n_1 via +1/+2 steps is Fibonacci-many PATHS over only N nodes — O(2^depth)
-- without the memo, ~linear with it. Acyclic, so every sub-result is cacheable.
DO $$
DECLARE s int; n_nodes int := 18;
BEGIN
    BEGIN PERFORM authz.delete_store('rodiamond'); EXCEPTION WHEN OTHERS THEN NULL; END;
    s := authz.create_store('rodiamond');
    INSERT INTO authz.types (store_id, name) VALUES (s,'user'), (s,'node');
    INSERT INTO authz.relations (store_id, name) VALUES (s,'parent_a'),(s,'parent_b'),(s,'viewer'),(s,'can_view');
    PERFORM authz.model_add_rule('rodiamond','node','viewer','direct');
    PERFORM authz.model_add_rule('rodiamond','node','parent_a','direct');
    PERFORM authz.model_add_rule('rodiamond','node','parent_b','direct');
    PERFORM authz.model_add_rule('rodiamond','node','can_view','computed', p_computed_relation=>'viewer');
    PERFORM authz.model_add_rule('rodiamond','node','can_view','ttu', p_tupleset_relation=>'parent_a', p_tupleset_computed=>'can_view');
    PERFORM authz.model_add_rule('rodiamond','node','can_view','ttu', p_tupleset_relation=>'parent_b', p_tupleset_computed=>'can_view');
    -- n_i.parent_a = n_{i+1}
    PERFORM authz.write_tuple('rodiamond','node','n'||(i+1),'parent_a','node','n'||i) FROM generate_series(1, n_nodes-1) i;
    -- n_i.parent_b = n_{i+2}
    PERFORM authz.write_tuple('rodiamond','node','n'||(i+2),'parent_b','node','n'||i) FROM generate_series(1, n_nodes-2) i;
    -- alice is a viewer of the anchor n_N
    PERFORM authz.write_tuple('rodiamond','user','alice','viewer','node','n'||n_nodes);
END $$;

-- ── Resolve inside a read-only transaction (mirrors a standby) ────────────────
BEGIN;
SET TRANSACTION READ ONLY;
-- Fixture 1: a check resolves at all (no "CREATE TABLE in a read-only txn").
SELECT set_config('authz._ro_grant',
    authz.check_access('rotest','user','alice','can_view','doc','d1')::text, false);
SELECT set_config('authz._ro_deny',
    authz.check_access('rotest','user','bob','can_view','doc','d1')::text, false);

-- Fixture 2: the converging diamond resolves with the memo ON (GUC backend).
SELECT set_config('authz._ro_diamond',
    authz.check_access('rodiamond','user','alice','can_view','node','n1')::text, false);
-- The GUC backend was selected, and it actually accumulated cached sub-results.
SELECT set_config('authz._ro_mode', COALESCE(current_setting('authz._memo_mode', true), '?'), false);
SELECT set_config('authz._ro_memo_keys',
    (SELECT count(*) FROM jsonb_object_keys(COALESCE(current_setting('authz._memo_data', true), '{}')::jsonb))::text,
    false);
-- Differential: with the memo OFF the answer is identical (just slower).
SET LOCAL authz.memoize = 'off';
SELECT set_config('authz._ro_diamond_off',
    authz.check_access('rodiamond','user','alice','can_view','node','n1')::text, false);
COMMIT;

DO $$
BEGIN
    PERFORM _test_assert('ro_01_granted_check_resolves_in_ro_txn',
        current_setting('authz._ro_grant', true), 'true');
    PERFORM _test_assert('ro_02_denied_check_resolves_in_ro_txn',
        current_setting('authz._ro_deny', true), 'false');
    PERFORM _test_assert('ro_03_diamond_resolves_in_ro_txn',
        current_setting('authz._ro_diamond', true), 'true');
    PERFORM _test_assert('ro_04_guc_backend_selected_when_read_only',
        current_setting('authz._ro_mode', true), 'guc');
    PERFORM _test_assert('ro_05_guc_memo_populated',
        (current_setting('authz._ro_memo_keys', true)::int > 0)::text, 'true');
    PERFORM _test_assert('ro_06_memo_on_equals_memo_off',
        current_setting('authz._ro_diamond_off', true),
        current_setting('authz._ro_diamond', true));
    PERFORM authz.delete_store('rotest');
    PERFORM authz.delete_store('rodiamond');
END $$;

SELECT _test_report('read-only (replica) check resolution + protection');
