-- 0007_expiry_statement_time.sql
--
-- Expiry freshness fix (review 2026-07-05, P0): the RLS SELECT policy compared
-- expires_at against now(), which in PostgreSQL is transaction_timestamp() —
-- FIXED at transaction start. A long-lived direct-SQL transaction could keep
-- seeing a tuple after its wall-clock expiry, contradicting the documented
-- "stops granting the moment expiry passes". (The request-per-transaction
-- front door — PostgREST/OPA/AuthZEN — is unaffected: each request is its own
-- transaction.)
--
-- statement_timestamp() advances per statement, so every check/search
-- re-evaluates expiry at its own start — fresh per authorization decision, and
-- consistent within a single statement (all rows of one list_* judged at one
-- instant). Time-travel is unaffected (it replays against p_at, not this
-- policy); cleanup and the write-time "already expired" guard keep
-- transaction-time now(), which is correct for those maintenance/write paths.

DROP POLICY IF EXISTS tuples_hide_expired ON authz.tuples;
CREATE POLICY tuples_hide_expired ON authz.tuples
    FOR SELECT
    USING (expires_at IS NULL OR expires_at > statement_timestamp());
