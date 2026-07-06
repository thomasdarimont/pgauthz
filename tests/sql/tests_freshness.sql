-- Freshness-token primitives (ADR 0009): freshness_token / assert_fresh /
-- _freshness_verdict.
--
-- The standby verdicts (stale / wrong_epoch / unknown) cannot be reached on a
-- primary-only test DB, so they are exercised against the PURE decision function
-- _freshness_verdict with synthetic inputs. The environment probe in
-- assert_fresh (pg_is_in_recovery / pg_stat_wal_receiver / replay LSN) and the
-- real cross-failover behavior are covered by the streaming-replication
-- prototype behind the ADR and the scaling integration test.

SELECT _test_reset();

DO $$
DECLARE
    v_epoch  int;
    v_lsn    pg_lsn;
    v_lsn2   pg_lsn;
BEGIN
    -- ── mint (primary) ───────────────────────────────────────────────
    SELECT epoch, lsn INTO v_epoch, v_lsn FROM authz.freshness_token();
    PERFORM _test_assert_true('mint_lsn_not_null',   v_lsn IS NOT NULL);
    PERFORM _test_assert_true('mint_epoch_positive', v_epoch >= 1,
        format('epoch=%s', v_epoch));
    -- monotonic: a later mint is never behind an earlier one
    SELECT lsn INTO v_lsn2 FROM authz.freshness_token();
    PERFORM _test_assert_true('mint_lsn_monotonic', v_lsn2 >= v_lsn,
        format('%s -> %s', v_lsn, v_lsn2));

    -- ── assert_fresh on the primary: own token fresh; a future LSN or a
    --    cross-timeline token is NOT blindly fresh (lossy-failover guard) ──
    PERFORM _test_assert('primary_own_token_fresh',
        authz.assert_fresh(v_epoch, v_lsn), 'fresh');
    -- a token beyond the primary's own insert LSN ⇒ stale (not written here yet)
    PERFORM _test_assert('primary_future_lsn_stale',
        authz.assert_fresh(v_epoch, 'FFFFFFFF/FFFFFFFF'::pg_lsn), 'stale');
    -- a token from a DIFFERENT timeline (e.g. minted on the pre-promotion
    -- primary) ⇒ wrong_epoch, even though THIS node is a primary
    PERFORM _test_assert('primary_wrong_epoch',
        authz.assert_fresh(v_epoch + 5, v_lsn), 'wrong_epoch');

    -- ── pure verdict: every branch (synthetic node timeline + position) ──
    -- timeline unreadable (standby not streaming / no stats) ⇒ fail closed
    PERFORM _test_assert('verdict_unknown_null_tli',
        authz._freshness_verdict(NULL, '0/100'::pg_lsn, 1, '0/50'::pg_lsn), 'unknown');
    -- node on a different timeline than the token ⇒ wrong_epoch
    PERFORM _test_assert('verdict_wrong_epoch',
        authz._freshness_verdict(2, '0/100'::pg_lsn, 1, '0/50'::pg_lsn), 'wrong_epoch');
    -- same timeline, position past the token ⇒ fresh
    PERFORM _test_assert('verdict_fresh_caught_up',
        authz._freshness_verdict(1, '0/100'::pg_lsn, 1, '0/50'::pg_lsn), 'fresh');
    -- same timeline, position exactly at the token ⇒ fresh (>=)
    PERFORM _test_assert('verdict_fresh_exact',
        authz._freshness_verdict(1, '0/50'::pg_lsn, 1, '0/50'::pg_lsn), 'fresh');
    -- same timeline, position behind the token ⇒ stale
    PERFORM _test_assert('verdict_stale_behind',
        authz._freshness_verdict(1, '0/40'::pg_lsn, 1, '0/50'::pg_lsn), 'stale');
    -- same timeline, position NULL ⇒ stale (never a false fresh)
    PERFORM _test_assert('verdict_stale_null_pos',
        authz._freshness_verdict(1, NULL, 1, '0/50'::pg_lsn), 'stale');
END;
$$;

SELECT _test_report('freshness checks');
