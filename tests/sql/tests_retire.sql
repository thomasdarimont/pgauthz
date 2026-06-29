-- Tests for retire_store (soft-delete) and the audit-after-deletion contract.
--
-- The gap retire_store closes: delete_store physically removes a store's
-- dictionary (stores/types/relations), so even when audit rows are preserved
-- the audit_* API can no longer resolve them by name ("Unknown store").
-- retire_store keeps the dictionary + audit and only drops the live tuples,
-- so the time-travel API stays usable, while live APIs reject the store.
--
-- Timestamps: the audit log stamps events with transaction_timestamp(), and
-- each top-level statement here runs in its own transaction, so a watermark
-- captured between the seed and the retire sits strictly between the write
-- events and the retire-time tuple deletions.

SELECT _test_reset();

-- Seed (txn 1): a store with a granted permission.
DO $$
DECLARE s int;
BEGIN
    BEGIN PERFORM authz.delete_store('retiretest'); EXCEPTION WHEN OTHERS THEN NULL; END;
    s := authz.create_store('retiretest');
    INSERT INTO authz.types (store_id, name) VALUES (s, 'user'), (s, 'doc');
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'viewer'), (s, 'can_view');
    PERFORM authz.model_add_rule('retiretest','doc','viewer','direct');
    PERFORM authz.model_add_rule('retiretest','doc','can_view','computed', p_computed_relation=>'viewer');
    PERFORM authz.write_tuple('retiretest','user','alice','viewer','doc','doc1');

    -- Sanity: access is granted while the store is live.
    PERFORM _test_assert('retire_00_live_access_granted',
        authz.check_access('retiretest','user','alice','can_view','doc','doc1')::text, 'true');
END $$;

-- Watermark (txn 2): an instant after seeding, before retirement.
CREATE TEMP TABLE _retire_t AS SELECT clock_timestamp() AS t_before;
SELECT pg_sleep(0.05);

-- Retire (txn 3): soft-delete. Drops live tuples, keeps dictionary + audit.
SELECT authz.retire_store('retiretest');

-- Assertions against the retired store.
DO $$
DECLARE
    v_before timestamptz;
    v_raised boolean;
BEGIN
    SELECT t_before INTO v_before FROM _retire_t;

    -- Live APIs reject a retired store (authz._s resolves live-only).
    BEGIN
        PERFORM authz.check_access('retiretest','user','alice','can_view','doc','doc1');
        v_raised := false;
    EXCEPTION WHEN OTHERS THEN v_raised := true;
    END;
    PERFORM _test_assert_true('retire_01_live_check_rejected', v_raised,
        'check_access on a retired store must raise');

    -- THE FIX: the audit_* API still resolves the retired store BY NAME and
    -- can answer "could alice view doc1 before it was retired?" -> yes.
    PERFORM _test_assert('retire_02_audit_history_queryable_after_retire',
        authz.audit_check_access('retiretest','user','alice','can_view','doc','doc1', v_before)::text,
        'true');

    -- As of after retirement the live tuples are gone -> no access.
    PERFORM _test_assert('retire_03_access_revoked_as_of_after_retire',
        authz.audit_check_access('retiretest','user','alice','can_view','doc','doc1', now() + interval '1 hour')::text,
        'false');

    -- A retired store's name stays reserved (no by-name ambiguity with the
    -- preserved history).
    BEGIN
        PERFORM authz.create_store('retiretest');
        v_raised := false;
    EXCEPTION WHEN OTHERS THEN v_raised := true;
    END;
    PERFORM _test_assert_true('retire_04_name_reserved', v_raised,
        'create_store must reject a retired store name');

    -- Retiring twice is rejected (already not live).
    BEGIN
        PERFORM authz.retire_store('retiretest');
        v_raised := false;
    EXCEPTION WHEN OTHERS THEN v_raised := true;
    END;
    PERFORM _test_assert_true('retire_05_double_retire_rejected', v_raised,
        'retire_store on an already-retired store must raise');
END $$;

-- Hard purge (txn): delete_store resolves the retired store and removes it
-- physically. Afterward even the audit_* API can no longer resolve it.
SELECT authz.delete_store('retiretest', true);

DO $$
DECLARE
    v_before timestamptz;
    v_raised boolean;
BEGIN
    SELECT t_before INTO v_before FROM _retire_t;
    BEGIN
        PERFORM authz.audit_check_access('retiretest','user','alice','can_view','doc','doc1', v_before);
        v_raised := false;
    EXCEPTION WHEN OTHERS THEN v_raised := true;
    END;
    PERFORM _test_assert_true('retire_06_purged_store_unresolvable', v_raised,
        'after physical delete_store the store name no longer resolves');
END $$;

DROP TABLE _retire_t;

SELECT _test_report('retire / soft-delete checks');
