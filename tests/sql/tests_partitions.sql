-- Tests for partition management: _ensure_tuple_partition and
-- _ensure_audit_partition (creation, idempotency, row placement,
-- hash sub-partitioning, default-partition row migration).
--
-- Uses its own store 'test_part' with throwaway types. Created
-- partitions are dropped in teardown so the suite can be re-run.

SELECT _test_reset();

DROP FUNCTION IF EXISTS _test_setup_part();
CREATE OR REPLACE FUNCTION _test_setup_part() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    s integer;
BEGIN
    BEGIN PERFORM authz.delete_store('test_part'); EXCEPTION WHEN OTHERS THEN NULL; END;
    -- Leftover partitions from a previous (aborted) run would make
    -- _ensure_*_partition return false and skew the assertions.
    DROP TABLE IF EXISTS authz.tuples_test_part_widget;
    DROP TABLE IF EXISTS authz.tuples_test_part_gadget;
    DROP TABLE IF EXISTS authz.tuples_audit_2031_01;

    PERFORM authz.create_store('test_part');
    s := authz._s('test_part');
    INSERT INTO authz.types (store_id, name) VALUES
        (s, 'user'), (s, 'widget'), (s, 'gadget'), (s, 'plain');
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'viewer');
    RETURN true;
END;
$$;

DROP FUNCTION IF EXISTS _test_teardown_part();
CREATE OR REPLACE FUNCTION _test_teardown_part()
RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    PERFORM authz.delete_store('test_part');
    DROP TABLE IF EXISTS authz.tuples_test_part_widget;
    DROP TABLE IF EXISTS authz.tuples_test_part_gadget;
    DROP TABLE IF EXISTS authz.tuples_audit_2031_01;
    RETURN QUERY DELETE FROM _test_results RETURNING *;
END;
$$;

-- ================================================================
-- tuple partitions
-- ================================================================
DO $$
DECLARE
    s integer;
    v_oid text;
BEGIN
    PERFORM _test_setup_part();
    s := authz._s('test_part');

    -- part_01: creating a dedicated partition reports creation
    PERFORM _test_assert('part_01_tuple_partition_created',
        authz._ensure_tuple_partition(s, 'widget')::text, 'true');

    -- part_02: second call is an idempotent no-op
    PERFORM _test_assert('part_02_tuple_partition_idempotent',
        authz._ensure_tuple_partition(s, 'widget')::text, 'false');

    -- part_03: tuples for the type land in the dedicated partition
    PERFORM authz.write_tuple('test_part', 'user', 'u1', 'viewer', 'widget', 'w1');
    SELECT c.relname INTO v_oid
      FROM authz.tuples t
      JOIN pg_catalog.pg_class c ON c.oid = t.tableoid
     WHERE t.store_id = s AND t.object_type = authz._t(s, 'widget');
    PERFORM _test_assert('part_03_tuple_in_dedicated_partition',
        v_oid, 'tuples_test_part_widget');

    -- part_04: tuples for types without a partition land in the default
    PERFORM authz.write_tuple('test_part', 'user', 'u1', 'viewer', 'plain', 'p1');
    SELECT c.relname INTO v_oid
      FROM authz.tuples t
      JOIN pg_catalog.pg_class c ON c.oid = t.tableoid
     WHERE t.store_id = s AND t.object_type = authz._t(s, 'plain');
    PERFORM _test_assert('part_04_tuple_in_default_partition',
        v_oid, 'tuples_default');

    -- part_05: hash sub-partitioning creates the requested buckets
    PERFORM authz._ensure_tuple_partition(s, 'gadget', 2);
    PERFORM _test_assert('part_05_hash_subpartitions_created',
        (SELECT count(*) FROM pg_catalog.pg_class c
           JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'authz'
            AND c.relname IN ('tuples_test_part_gadget_0', 'tuples_test_part_gadget_1')
            AND c.relispartition)::text, '2');
END;
$$;
SELECT * FROM _test_teardown_part();

-- ================================================================
-- audit partitions
-- ================================================================
DO $$
DECLARE
    s integer;
    v_oid text;
BEGIN
    PERFORM _test_setup_part();
    s := authz._s('test_part');

    -- Synthetic audit row in a month that has no dedicated partition yet:
    -- it must be caught by the default partition.
    INSERT INTO authz.tuples_audit (action, performed_at, performed_by,
        store_id, user_type, user_id, relation, object_type, object_id)
    VALUES ('INSERT', '2031-01-15T12:00:00Z', '_test_partition_probe',
        s, authz._t(s, 'user'), 'u1', authz._r(s, 'viewer'), authz._t(s, 'widget'), 'w1');

    SELECT c.relname INTO v_oid
      FROM authz.tuples_audit a
      JOIN pg_catalog.pg_class c ON c.oid = a.tableoid
     WHERE a.performed_by = '_test_partition_probe';
    PERFORM _test_assert('part_06_audit_row_in_default_partition',
        v_oid, 'tuples_audit_default');

    -- part_07: creating the monthly partition reports creation
    PERFORM _test_assert('part_07_audit_partition_created',
        authz._ensure_audit_partition(2031, 1)::text, 'true');

    -- part_08: existing rows are migrated out of the default partition
    SELECT c.relname INTO v_oid
      FROM authz.tuples_audit a
      JOIN pg_catalog.pg_class c ON c.oid = a.tableoid
     WHERE a.performed_by = '_test_partition_probe';
    PERFORM _test_assert('part_08_audit_row_migrated_to_monthly_partition',
        v_oid, 'tuples_audit_2031_01');

    -- part_09: second call is an idempotent no-op
    PERFORM _test_assert('part_09_audit_partition_idempotent',
        authz._ensure_audit_partition(2031, 1)::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_part();

-- ================================================================
-- ensure_audit_partitions: scheduled/automatic monthly partitions
-- ================================================================
-- The created partitions (current + next month) are intentionally
-- left in place — that is the desired operational state.
DO $$
DECLARE
    v_cur  text := 'tuples_audit_' || to_char(now(), 'YYYY_MM');
    v_next text := 'tuples_audit_' || to_char(date_trunc('month', now()) + interval '1 month', 'YYYY_MM');
BEGIN
    PERFORM authz.ensure_audit_partitions();

    -- part_10: partitions for the current and next month exist
    PERFORM _test_assert('part_10_current_and_next_month_partitions_exist',
        (SELECT count(*) FROM pg_catalog.pg_class c
           JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'authz'
            AND c.relname IN (v_cur, v_next)
            AND c.relispartition)::text, '2');

    -- part_11: second call is an idempotent no-op
    PERFORM _test_assert('part_11_ensure_audit_partitions_idempotent',
        authz.ensure_audit_partitions()::text, '0');

    -- part_12: new audit rows land in the monthly partition, not the default
    PERFORM _test_setup_part();
    PERFORM authz.write_tuple('test_part', 'user', 'u9', 'viewer', 'plain', 'p9');
    PERFORM _test_assert('part_12_audit_row_in_monthly_partition',
        (SELECT c.relname FROM authz.tuples_audit a
           JOIN pg_catalog.pg_class c ON c.oid = a.tableoid
          WHERE a.store_id = authz._s('test_part')
            AND a.user_id = 'u9'), v_cur);
END;
$$;
SELECT * FROM _test_teardown_part();

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_part();
DROP FUNCTION IF EXISTS _test_setup_part();

SELECT _test_report('partition checks');


-- ---------------------------------------------------------------------
-- authz.ephemeral_store: a type registered under the GUC gets no dedicated
-- partition (no DDL on the parent, no ACCESS EXCLUSIVE lock), its tuples
-- live in tuples_default, and delete_store cleans up without a partition.
-- ---------------------------------------------------------------------
BEGIN;
SELECT set_config('authz.ephemeral_store', 'on', true);
SELECT authz.create_store('test_ephem', 'ephemeral');
SELECT authz.model_register_type('test_ephem', 'user');
SELECT authz.model_register_type('test_ephem', 'thing');
SELECT authz.model_register_relation('test_ephem', 'viewer');
SELECT authz.model_add_rule('test_ephem', 'thing', 'viewer', 'direct');
SELECT authz.write_tuple('test_ephem', 'user', 'eve', 'viewer', 'thing', 't1');
SELECT _test_assert_true('ephemeral: no partition for the type',
    NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class WHERE relname = 'tuples_test_ephem_thing'));
SELECT _test_assert_true('ephemeral: the tuple lives in tuples_default',
    EXISTS (SELECT 1 FROM authz.tuples_default t JOIN authz.stores s ON s.id = t.store_id WHERE s.name = 'test_ephem'));
SELECT _test_assert('ephemeral: the check decides from the default partition',
    authz.check_access('test_ephem', 'user', 'eve', 'viewer', 'thing', 't1')::text, 'true');
SELECT _test_assert_true('ephemeral: no ACCESS EXCLUSIVE lock on the parent',
    NOT EXISTS (SELECT 1 FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
                 WHERE c.relname = 'tuples' AND c.relnamespace = 'authz'::regnamespace
                   AND l.pid = pg_backend_pid() AND l.mode = 'AccessExclusiveLock'));
SELECT authz.delete_store('test_ephem', p_purge_audit => true);
SELECT _test_assert_true('ephemeral: delete_store removed the rows',
    NOT EXISTS (SELECT 1 FROM authz.tuples_default t JOIN authz.stores s ON s.id = t.store_id WHERE s.name = 'test_ephem'));
COMMIT;
