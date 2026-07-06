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
-- _freshness_verdict(...) — the PURE decision, with no environment calls, so
-- every branch is unit-testable with synthetic inputs (the standby paths are
-- unreachable on a primary-only test DB). assert_fresh() below is the thin
-- env-probe wrapper. Verdicts:
--   'fresh'       node is at/after the token on the token''s timeline → serve locally
--   'stale'       right timeline, not yet replayed to the token → wait / route to primary
--   'wrong_epoch' node is on a different timeline than the token → route to primary
--   'unknown'     standby not streaming / timeline unreadable → route to primary (fail closed)
-- Not in recovery ⇒ primary ⇒ authoritative for the current timeline ⇒ 'fresh'.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._freshness_verdict(
    p_in_recovery  boolean,
    p_received_tli int,
    p_replay       pg_lsn,
    p_epoch        int,
    p_lsn          pg_lsn
)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE
        WHEN NOT p_in_recovery                        THEN 'fresh'
        WHEN p_received_tli IS NULL                   THEN 'unknown'
        WHEN p_received_tli <> p_epoch                THEN 'wrong_epoch'
        WHEN p_replay IS NOT NULL AND p_replay >= p_lsn THEN 'fresh'
        ELSE 'stale'
    END;
$$;

------------------------------------------------------------------------
-- assert_fresh(epoch, lsn) — probe THIS node and return the verdict. The only
-- environment reads live here; the decision is _freshness_verdict above.
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
    v_recovery boolean := pg_is_in_recovery();
    v_tli      int;
    v_replay   pg_lsn;
BEGIN
    IF v_recovery THEN
        SELECT received_tli INTO v_tli FROM pg_stat_wal_receiver;  -- NULL without pg_read_all_stats
        v_replay := pg_last_wal_replay_lsn();
    END IF;
    RETURN authz._freshness_verdict(v_recovery, v_tli, v_replay, p_epoch, p_lsn);
END;
$$;

COMMENT ON FUNCTION authz.assert_fresh(int, pg_lsn) IS
    'ADR 0009: does this node satisfy a freshness token? fresh|stale|wrong_epoch|unknown (fail-closed).';
