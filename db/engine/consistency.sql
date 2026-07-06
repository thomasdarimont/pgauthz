-- Freshness-token primitives for read-your-writes across replicas (ADR 0009).
--
-- The token is an LSN watermark tagged with the WAL timeline (the "epoch"):
--   token = { epoch = timeline_id, lsn = WAL position }
-- A replica can satisfy a token once it has replayed to >= lsn ON the token's
-- timeline. The timeline guard is what makes this sound across failover: after
-- promotion the LSN space forks onto a new timeline, so a naive `replay >= lsn`
-- compare would false-ALLOW against diverged/lost WAL.
--
-- CRITICAL (proven by the prototype behind ADR 0009): the timeline MUST be read
-- from the WAL position, NEVER from pg_control_checkpoint().timeline_id — the
-- control file only advances at a checkpoint and lags promotion, which would
-- open a false-ALLOW window. Sources used here:
--   * mint  (primary, out of recovery): pg_walfile_name(pg_current_wal_insert_lsn())
--   * guard (standby, in recovery):     pg_stat_wal_receiver.received_tli
--     (pg_walfile_name() errors during recovery, so it cannot be used reader-side).
--
-- Privilege: pg_stat_wal_receiver.received_tli is only visible to a role with
-- pg_read_all_stats. These functions are SECURITY DEFINER (roles.sql) and their
-- owner (authz_owner) is granted pg_read_all_stats there. Without that grant the
-- guard degrades safely to 'unknown' (caller routes to the primary), never a
-- false 'fresh'.

------------------------------------------------------------------------
-- freshness_token() — mint a token on the PRIMARY, post-commit, on the
-- writer's connection. Returns (epoch, lsn). Errors on a standby: the
-- WAL insert functions are primary-only (they raise during recovery).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.freshness_token(
    OUT epoch int,
    OUT lsn   pg_lsn
)
LANGUAGE plpgsql
AS $$
BEGIN
    IF pg_is_in_recovery() THEN
        RAISE EXCEPTION 'freshness_token() must be minted on the primary, not a standby'
            USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
    lsn := pg_current_wal_insert_lsn();
    -- timeline = first 8 hex chars of the WAL file name (WAL position, NOT the
    -- lagging control file — see the header / ADR 0009).
    epoch := ('x' || substr(pg_walfile_name(lsn), 1, 8))::bit(32)::int;
END;
$$;

COMMENT ON FUNCTION authz.freshness_token() IS
    'ADR 0009: mint an LSN-watermark freshness token {epoch=timeline, lsn} on the primary (post-commit).';

------------------------------------------------------------------------
-- _freshness_verdict(...) — the PURE decision from a node's (timeline, WAL
-- position) vs the token, no environment calls (unit-testable with synthetic
-- inputs). assert_fresh() below feeds it this node's live values.
--   'fresh'       node is on the token's timeline AND at/after its LSN → serve
--   'stale'       right timeline, position behind the token → wait / route to primary
--   'wrong_epoch' node is on a DIFFERENT timeline than the token → route to primary
--   'unknown'     timeline unreadable (standby not streaming / no stats) → fail closed
--
-- There is NO primary special-case: a PROMOTED primary is on a NEW timeline, so
-- a token minted on the old one is wrong_epoch — NOT blindly 'fresh'. That is
-- the lossy-failover read-your-writes guard (ADR 0009): the old primary may have
-- acked a write the promoted primary never received, and returning 'fresh' there
-- would be a stale-allow. Timeline comparison is exact (conservative): even a
-- CLEAN promotion makes old-timeline tokens re-mint, which beats a false allow.
------------------------------------------------------------------------
DROP FUNCTION IF EXISTS authz._freshness_verdict(boolean, int, pg_lsn, int, pg_lsn);
CREATE OR REPLACE FUNCTION authz._freshness_verdict(
    p_node_tli int,     -- this node's timeline (NULL ⇒ unknown, fail closed)
    p_node_pos pg_lsn,  -- this node's WAL position (replay on a standby, insert on a primary)
    p_epoch    int,     -- token timeline (epoch)
    p_lsn      pg_lsn   -- token LSN
)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE
        WHEN p_node_tli IS NULL                             THEN 'unknown'
        WHEN p_node_tli <> p_epoch                          THEN 'wrong_epoch'
        WHEN p_node_pos IS NOT NULL AND p_node_pos >= p_lsn THEN 'fresh'
        ELSE 'stale'
    END;
$$;

------------------------------------------------------------------------
-- assert_fresh(epoch, lsn) — probe THIS node's timeline + WAL position and
-- apply the verdict. The only environment reads live here.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.assert_fresh(
    p_epoch int,
    p_lsn   pg_lsn
)
RETURNS text
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_tli int;
    v_pos pg_lsn;
BEGIN
    IF pg_is_in_recovery() THEN
        -- Standby: the timeline it is replaying (recovery-safe via the WAL
        -- receiver; NULL without pg_read_all_stats or when not streaming) + its
        -- replay position. pg_walfile_name() cannot run during recovery.
        SELECT received_tli INTO v_tli FROM pg_stat_wal_receiver;
        v_pos := pg_last_wal_replay_lsn();
    ELSE
        -- Primary: its CURRENT timeline + insert position, derived from the WAL
        -- position (never the lagging control file). A promoted primary is on a
        -- new timeline, so a token from the old one comes out wrong_epoch.
        v_pos := pg_current_wal_insert_lsn();
        v_tli := ('x' || substr(pg_walfile_name(v_pos), 1, 8))::bit(32)::int;
    END IF;
    RETURN authz._freshness_verdict(v_tli, v_pos, p_epoch, p_lsn);
END;
$$;

COMMENT ON FUNCTION authz.assert_fresh(int, pg_lsn) IS
    'ADR 0009: does this node satisfy a freshness token? fresh|stale|wrong_epoch|unknown (fail-closed; timeline-guarded on primary AND standby).';
