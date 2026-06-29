-- Regression: check_access must resolve in a READ ONLY transaction.
--
-- A hot standby / read replica runs every transaction read-only, where a
-- temp table cannot be created. The memoization wrapper builds a session temp
-- table (_check_memo) at the root of a check, so it must DISABLE the memo when
-- the transaction is read-only — otherwise check_access fails on replicas with
-- 'cannot execute CREATE TABLE in a read-only transaction'. This reproduces
-- that path with SET TRANSACTION READ ONLY (no replica needed); set_config is
-- allowed read-only, so we stash the results in GUCs and assert afterwards.

SELECT _test_reset();

-- Fixture (writable / autocommit).
DO $$
DECLARE s int;
BEGIN
    BEGIN PERFORM authz.delete_store('rotest'); EXCEPTION WHEN OTHERS THEN NULL; END;
    s := authz.create_store('rotest');
    INSERT INTO authz.types (store_id, name) VALUES (s, 'user'), (s, 'doc');
    INSERT INTO authz.relations (store_id, name) VALUES (s, 'viewer'), (s, 'editor'), (s, 'can_view');
    -- A small computed chain so the check recurses (exercises the memo gate too).
    PERFORM authz.model_add_rule('rotest','doc','viewer','direct');
    PERFORM authz.model_add_rule('rotest','doc','editor','direct');
    PERFORM authz.model_add_rule('rotest','doc','can_view','computed', p_computed_relation=>'viewer');
    PERFORM authz.model_add_rule('rotest','doc','can_view','computed', p_computed_relation=>'editor');
    PERFORM authz.write_tuple('rotest','user','alice','viewer','doc','d1');
END $$;

-- Resolve checks inside a read-only transaction (mirrors a standby).
BEGIN;
SET TRANSACTION READ ONLY;
SELECT set_config('authz._ro_grant',
    authz.check_access('rotest','user','alice','can_view','doc','d1')::text, false);
SELECT set_config('authz._ro_deny',
    authz.check_access('rotest','user','bob','can_view','doc','d1')::text, false);
COMMIT;

DO $$
BEGIN
    PERFORM _test_assert('ro_01_granted_check_resolves_in_ro_txn',
        current_setting('authz._ro_grant', true), 'true');
    PERFORM _test_assert('ro_02_denied_check_resolves_in_ro_txn',
        current_setting('authz._ro_deny', true), 'false');
    PERFORM authz.delete_store('rotest');
END $$;

SELECT _test_report('read-only (replica) check');
