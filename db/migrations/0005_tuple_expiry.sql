-- 0005_tuple_expiry.sql
--
-- Native relationship expiration: tuples.expires_at.
--
-- A tuple with expires_at in the past must not grant ANYTHING, on any read
-- path. Rather than adding an expiry filter to every one of the ~37 tuple
-- scan sites (miss one = an expired tuple still grants — a fail-OPEN bug
-- class), enforcement is STRUCTURAL: row-level security on authz.tuples
-- hides expired rows from every SELECT — including inside the
-- SECURITY DEFINER engine functions (FORCE applies RLS to the table owner).
-- Server time (now()) decides; caller-supplied context has no say.
--
-- Write/delete policies stay permissive: re-granting an expired tuple is an
-- ordinary upsert (write_tuple refreshes expires_at), and cleanup /
-- delete_store can remove expired rows (audited as usual). Time-travel
-- stays correct: tuples_audit records expires_at, and the replay compares
-- it against p_at, not now() (engine code).
--
-- The hot-path covering indexes gain expires_at in INCLUDE so the policy
-- predicate is evaluable from the index tuple (preserving index-only scans).

ALTER TABLE authz.tuples       ADD COLUMN expires_at timestamptz;
ALTER TABLE authz.tuples_audit ADD COLUMN expires_at timestamptz;

COMMENT ON COLUMN authz.tuples.expires_at IS
    'Optional expiry (server time). Expired rows are hidden by row-level '
    'security from every read path — they grant nothing — and can be '
    'removed by cleanup_expired_tuples (audited). NULL = never expires. '
    'For complex time windows keep using conditions; this is the simple case.';

-- Recreate the hot-path indexes with expires_at in INCLUDE (index-only scans
-- must be able to evaluate the RLS predicate without heap fetches).
DROP INDEX authz.idx_tuples_direct;
CREATE INDEX idx_tuples_direct
    ON authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    INCLUDE (expires_at)
    WHERE user_relation IS NULL;

DROP INDEX authz.idx_tuples_userset;
CREATE INDEX idx_tuples_userset
    ON authz.tuples (store_id, object_type, object_id, relation)
    INCLUDE (user_type, user_id, user_relation, expires_at)
    WHERE user_relation IS NOT NULL;

DROP INDEX authz.idx_tuples_user;
CREATE INDEX idx_tuples_user
    ON authz.tuples (store_id, user_type, user_id)
    INCLUDE (relation, object_type, object_id, expires_at);

-- Cleanup scans: only rows that can expire, ordered by when.
CREATE INDEX idx_tuples_expiring
    ON authz.tuples (expires_at)
    WHERE expires_at IS NOT NULL;

-- Structural enforcement. FORCE extends the policies to the table owner
-- (authz_owner), which is what the SECURITY DEFINER engine runs as.
ALTER TABLE authz.tuples ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz.tuples FORCE  ROW LEVEL SECURITY;

-- Reads: expired rows do not exist. The escape hatch mirrors the audit
-- tables' authz.audit_maintenance pattern: sanctioned engine internals
-- (upsert-reactivation, deletes/offboarding, cleanup) set the transaction-
-- local GUC authz.tuples_include_expired and reset it immediately — needed
-- because ANY DML whose WHERE/SET reads existing columns folds the SELECT
-- policy in, which would make expired rows unreachable even for deletion.
-- No read path ever sets it. (Common case short-circuits before the GUC.)
CREATE POLICY tuples_hide_expired ON authz.tuples
    FOR SELECT
    USING (expires_at IS NULL
           OR expires_at > now()
           OR current_setting('authz.tuples_include_expired', true) = 'on');

-- Writes stay unrestricted at the RLS layer (the function API enforces
-- namespaces/restrictions): INSERT always allowed; UPDATE/DELETE must see
-- expired rows too (upsert-refresh of an expired grant, cleanup, offboarding,
-- delete_store).
CREATE POLICY tuples_insert ON authz.tuples FOR INSERT WITH CHECK (true);
CREATE POLICY tuples_update ON authz.tuples FOR UPDATE USING (true) WITH CHECK (true);
CREATE POLICY tuples_delete ON authz.tuples FOR DELETE USING (true);
