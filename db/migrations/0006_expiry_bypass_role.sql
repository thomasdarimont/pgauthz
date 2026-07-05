-- 0006_expiry_bypass_role.sql
--
-- Security fix (SECURITY-AUDIT F11): the tuple-expiry RLS escape must not be a
-- caller-settable GUC.
--
-- 0005 let sanctioned engine paths reveal expired rows for upsert/cleanup by
-- arming a transaction-local GUC (authz.tuples_include_expired) that the SELECT
-- policy honored. But a *custom GUC is settable by any role*, and expiry is
-- read inside SECURITY DEFINER functions (check_access, list_*) that app roles
-- legitimately invoke — so a direct `authz_reader` connection could
-- `SET authz.tuples_include_expired = 'on'` and make expired tuples grant again
-- (fail-open). No policy predicate can distinguish a legitimate arming from a
-- forged one. (Not reachable through the OPA/PostgREST front door, which
-- exposes RPC only; a direct-SQL trust-tier hole.)
--
-- Fix (structure here; role + grants in db/security/roles.sql, which loads
-- after migrations): the SELECT policy has NO GUC escape and cannot be
-- bypassed by any caller-set value. The two operations that must SEE expired
-- rows — the reactivating ON CONFLICT upsert and cleanup — run inside
-- SECURITY DEFINER helper functions (authz._rls_*) owned by a dedicated
-- BYPASSRLS role, called normally (no SET ROLE, which Postgres rejects inside
-- definer functions anyway).

DROP POLICY IF EXISTS tuples_hide_expired ON authz.tuples;
CREATE POLICY tuples_hide_expired ON authz.tuples
    FOR SELECT
    USING (expires_at IS NULL OR expires_at > now());
