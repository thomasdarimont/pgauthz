-- Tests for write_tuples_checked (optimistic-concurrency / conditional writes).
--
-- write_tuples_checked(store, preconditions, deletes, writes, performed_by)
-- checks each precondition (exists / absent, partial filters) and applies the
-- deletes + writes atomically in one transaction; any failed precondition
-- aborts the whole thing. See db/engine/tuples.sql.

SELECT _test_reset();

DROP FUNCTION IF EXISTS _test_setup_pc();
CREATE FUNCTION _test_setup_pc() RETURNS void LANGUAGE plpgsql AS $$
DECLARE s smallint;
BEGIN
    BEGIN PERFORM authz.delete_store('test_pc'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.create_store('test_pc');
    s := authz._s('test_pc');
    INSERT INTO authz.types (store_id, name) VALUES (s, 'user'), (s, 'doc');
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'owner'), (s, 'viewer');
    PERFORM authz._ensure_tuple_partition(s, 'doc');
    INSERT INTO authz.models (store_id, object_type, relation, rule_type,
                              computed_relation, tupleset_relation, tupleset_computed)
    VALUES (s, authz._t(s, 'doc'), authz._r(s, 'owner'),  authz._rel_direct(), NULL, NULL, NULL),
           (s, authz._t(s, 'doc'), authz._r(s, 'viewer'), authz._rel_direct(), NULL, NULL, NULL);
END;
$$;

-- helper: does a (user, relation, doc) tuple exist in test_pc?
DROP FUNCTION IF EXISTS _pc_has(text, text, text, text);
CREATE FUNCTION _pc_has(p_user text, p_rel text, p_ot text, p_oid text)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (SELECT 1 FROM authz.tuples t
                    WHERE t.store_id    = authz._s('test_pc')
                      AND t.user_id     = p_user
                      AND t.relation    = authz._r(authz._s('test_pc'), p_rel)
                      AND t.object_type = authz._t(authz._s('test_pc'), p_ot)
                      AND t.object_id   = p_oid);
$$;

SELECT _test_setup_pc();
SELECT authz.write_tuple('test_pc', 'user', 'alice', 'owner', 'doc', 'd1');

-- pc_01: satisfied "exists" precondition → writes applied.
DO $$
DECLARE r jsonb;
BEGIN
    r := authz.write_tuples_checked('test_pc',
        p_preconditions := '[{"match":"exists","user_type":"user","user_id":"alice","relation":"owner","object_type":"doc","object_id":"d1"}]',
        p_writes        := '[{"user_type":"user","user_id":"bob","relation":"viewer","object_type":"doc","object_id":"d1"}]');
    PERFORM _test_assert_true('pc_01_exists_pass_writes',
        _pc_has('bob', 'viewer', 'doc', 'd1') AND (r->>'written') = '1', coalesce(r::text, 'null'));
END $$;

-- pc_02: failed "exists" precondition → exception, nothing written.
DO $$
DECLARE v_err text;
BEGIN
    BEGIN
        PERFORM authz.write_tuples_checked('test_pc',
            p_preconditions := '[{"match":"exists","user_type":"user","user_id":"zoe","relation":"owner","object_type":"doc","object_id":"d1"}]',
            p_writes        := '[{"user_type":"user","user_id":"eve","relation":"viewer","object_type":"doc","object_id":"d1"}]');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM;
    END;
    PERFORM _test_assert_true('pc_02_exists_fail_no_write',
        v_err LIKE '%precondition failed%' AND NOT _pc_has('eve', 'viewer', 'doc', 'd1'),
        coalesce(v_err, 'no error'));
END $$;

-- pc_03: satisfied "absent" precondition (no owner on d2) → write applied.
DO $$
DECLARE r jsonb;
BEGIN
    r := authz.write_tuples_checked('test_pc',
        p_preconditions := '[{"match":"absent","relation":"owner","object_type":"doc","object_id":"d2"}]',
        p_writes        := '[{"user_type":"user","user_id":"carol","relation":"owner","object_type":"doc","object_id":"d2"}]');
    PERFORM _test_assert_true('pc_03_absent_pass_writes',
        _pc_has('carol', 'owner', 'doc', 'd2') AND (r->>'written') = '1', coalesce(r::text, 'null'));
END $$;

-- pc_04: failed "absent" precondition (owner already exists on d1) → no write.
DO $$
DECLARE v_err text;
BEGIN
    BEGIN
        PERFORM authz.write_tuples_checked('test_pc',
            p_preconditions := '[{"match":"absent","relation":"owner","object_type":"doc","object_id":"d1"}]',
            p_writes        := '[{"user_type":"user","user_id":"dave","relation":"owner","object_type":"doc","object_id":"d1"}]');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM;
    END;
    PERFORM _test_assert_true('pc_04_absent_fail_no_write',
        v_err LIKE '%precondition failed%' AND NOT _pc_has('dave', 'owner', 'doc', 'd1'),
        coalesce(v_err, 'no error'));
END $$;

-- pc_05: atomic ownership transfer — require alice owner, delete alice, add bob.
DO $$
DECLARE r jsonb;
BEGIN
    r := authz.write_tuples_checked('test_pc',
        p_preconditions := '[{"match":"exists","user_type":"user","user_id":"alice","relation":"owner","object_type":"doc","object_id":"d1"}]',
        p_deletes       := '[{"user_type":"user","user_id":"alice","relation":"owner","object_type":"doc","object_id":"d1"}]',
        p_writes        := '[{"user_type":"user","user_id":"bob","relation":"owner","object_type":"doc","object_id":"d1"}]');
    PERFORM _test_assert_true('pc_05_transfer_atomic',
        (NOT _pc_has('alice', 'owner', 'doc', 'd1')) AND _pc_has('bob', 'owner', 'doc', 'd1')
        AND (r->>'deleted') = '1' AND (r->>'written') = '1', coalesce(r::text, 'null'));
END $$;

-- pc_06: a failed precondition rolls back the deletes too (full atomicity).
-- bob now owns d1; attempt a transfer that requires a non-existent owner.
DO $$
DECLARE v_err text;
BEGIN
    BEGIN
        PERFORM authz.write_tuples_checked('test_pc',
            p_preconditions := '[{"match":"exists","user_type":"user","user_id":"ghost","relation":"owner","object_type":"doc","object_id":"d1"}]',
            p_deletes       := '[{"user_type":"user","user_id":"bob","relation":"owner","object_type":"doc","object_id":"d1"}]',
            p_writes        := '[{"user_type":"user","user_id":"carol","relation":"owner","object_type":"doc","object_id":"d1"}]');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM;
    END;
    PERFORM _test_assert_true('pc_06_fail_rolls_back_deletes',
        _pc_has('bob', 'owner', 'doc', 'd1') AND NOT _pc_has('carol', 'owner', 'doc', 'd1'),
        coalesce(v_err, 'no error'));
END $$;

-- pc_08..pc_12: "allowed" / "denied" preconditions run a full access check
-- (computed relations, conditions with context, gates) — "grant only if the
-- granter may". bob owns d1 (after pc_05); can_share = owner (computed).
DO $$
DECLARE s smallint := authz._s('test_pc'); v_err text; v_state text;
BEGIN
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'can_share');
    INSERT INTO authz.models (store_id, object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed)
    VALUES (s, authz._t(s, 'doc'), authz._r(s, 'can_share'), authz._rel_computed(), authz._r(s, 'owner'), NULL, NULL);

    -- pc_08: bob may share d1 (computed through owner) → carol becomes viewer
    PERFORM authz.write_tuples_checked('test_pc',
        p_preconditions := '[{"match":"allowed","user_type":"user","user_id":"bob","relation":"can_share","object_type":"doc","object_id":"d1"}]',
        p_writes        := '[{"user_type":"user","user_id":"carol","relation":"viewer","object_type":"doc","object_id":"d1"}]');
    PERFORM _test_assert_true('pc_08_allowed_computed_pass', _pc_has('carol', 'viewer', 'doc', 'd1'));

    -- pc_09: alice no longer owns d1 → her share is refused, nothing written, check_violation
    v_err := NULL; v_state := NULL;
    BEGIN
        PERFORM authz.write_tuples_checked('test_pc',
            p_preconditions := '[{"match":"allowed","user_type":"user","user_id":"alice","relation":"can_share","object_type":"doc","object_id":"d1"}]',
            p_writes        := '[{"user_type":"user","user_id":"dave","relation":"viewer","object_type":"doc","object_id":"d1"}]');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; v_state := SQLSTATE; END;
    PERFORM _test_assert('pc_09_allowed_fail_state', v_state, '23514');
    PERFORM _test_assert_true('pc_09_allowed_fail_message', v_err LIKE 'Write precondition failed: allowed %', coalesce(v_err, 'no error'));
    PERFORM _test_assert_true('pc_09_allowed_fail_no_write', NOT _pc_has('dave', 'viewer', 'doc', 'd1'));

    -- pc_10: "denied" — grant only if the target does NOT already have access
    PERFORM authz.write_tuples_checked('test_pc',
        p_preconditions := '[{"match":"denied","user_type":"user","user_id":"erin","relation":"viewer","object_type":"doc","object_id":"d1"}]',
        p_writes        := '[{"user_type":"user","user_id":"erin","relation":"viewer","object_type":"doc","object_id":"d1"}]');
    PERFORM _test_assert_true('pc_10_denied_pass', _pc_has('erin', 'viewer', 'doc', 'd1'));
    v_state := NULL;
    BEGIN
        PERFORM authz.write_tuples_checked('test_pc',
            p_preconditions := '[{"match":"denied","user_type":"user","user_id":"erin","relation":"viewer","object_type":"doc","object_id":"d1"}]',
            p_writes        := '[{"user_type":"user","user_id":"erin","relation":"owner","object_type":"doc","object_id":"d1"}]');
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('pc_10_denied_fail_state', v_state, '23514');
    PERFORM _test_assert_true('pc_10_denied_fail_no_write', NOT _pc_has('erin', 'owner', 'doc', 'd1'));

    -- pc_11: the check honours request context (a conditional grant)
    PERFORM authz.create_condition_sql('test_pc', 'pc_clearance', $c$ ($1->>'clearance') = 'high' $c$, '{"request": ["clearance"]}');
    PERFORM authz.write_tuple('test_pc', 'user', 'frank', 'owner', 'doc', 'd3', p_condition => 'pc_clearance');
    v_state := NULL;
    BEGIN
        PERFORM authz.write_tuples_checked('test_pc',
            p_preconditions := '[{"match":"allowed","user_type":"user","user_id":"frank","relation":"can_share","object_type":"doc","object_id":"d3"}]',
            p_writes        := '[{"user_type":"user","user_id":"gina","relation":"viewer","object_type":"doc","object_id":"d3"}]');
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('pc_11_allowed_without_context_fails', v_state, '23514');
    PERFORM authz.write_tuples_checked('test_pc',
        p_preconditions := '[{"match":"allowed","user_type":"user","user_id":"frank","relation":"can_share","object_type":"doc","object_id":"d3","context":{"clearance":"high"}}]',
        p_writes        := '[{"user_type":"user","user_id":"gina","relation":"viewer","object_type":"doc","object_id":"d3"}]');
    PERFORM _test_assert_true('pc_11_allowed_with_context_passes', _pc_has('gina', 'viewer', 'doc', 'd3'));

    -- pc_12: shape errors are 22023, unknown match names all four kinds
    v_state := NULL; v_err := NULL;
    BEGIN
        PERFORM authz.write_tuples_checked('test_pc',
            p_preconditions := '[{"match":"allowed","user_type":"user","user_id":"bob","relation":"can_share","object_type":"doc"}]');
    EXCEPTION WHEN OTHERS THEN v_state := SQLSTATE; END;
    PERFORM _test_assert('pc_12_allowed_missing_fields', v_state, '22023');
    BEGIN
        PERFORM authz.write_tuples_checked('test_pc', p_preconditions := '[{"match":"maybe"}]');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM; END;
    PERFORM _test_assert_true('pc_12_unknown_match_lists_kinds', v_err LIKE '%"allowed" or "denied"%', coalesce(v_err, 'no error'));
END;
$$;

-- pc_07: partial "absent" filter (no owner at all on d1) fails because bob owns it.
DO $$
DECLARE v_err text;
BEGIN
    BEGIN
        PERFORM authz.write_tuples_checked('test_pc',
            p_preconditions := '[{"match":"absent","object_type":"doc","object_id":"d1","relation":"owner"}]',
            p_writes        := '[{"user_type":"user","user_id":"newowner","relation":"owner","object_type":"doc","object_id":"d1"}]');
    EXCEPTION WHEN OTHERS THEN v_err := SQLERRM;
    END;
    PERFORM _test_assert_true('pc_07_partial_absent_blocks',
        v_err LIKE '%precondition failed%' AND NOT _pc_has('newowner', 'owner', 'doc', 'd1'),
        coalesce(v_err, 'no error'));
END $$;

SELECT authz.delete_store('test_pc');
DROP FUNCTION IF EXISTS _pc_has(text, text, text, text);
DROP FUNCTION IF EXISTS _test_setup_pc();

SELECT _test_report('precondition checks');
