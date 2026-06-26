-- Read-only role setup for an embedded read-only deployment.
--
-- Companion to roles.sql, but for a deployment that installed only the
-- substrate + read profiles (see db/engine/manifest.sh, init-readonly.sh) —
-- e.g. an application database fed by replication that answers access queries
-- locally. There is no write/management API to grant, so this just wires up
-- the reader role and makes the read functions SECURITY DEFINER (so the app
-- role needs no direct table access).
--
-- authz_eval (the zero-privilege condition sandbox) is created by schema.sql.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authz_reader') THEN
        CREATE ROLE authz_reader NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA authz TO authz_reader;

-- Read API — SECURITY DEFINER so the reader role needs no table grants.
ALTER FUNCTION authz.check_access(text, text, text, text, text, text) SECURITY DEFINER;
ALTER FUNCTION authz.check_access_with_context(text, text, text, text, text, text, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.list_objects(text, text, text, text, text, jsonb, int, int, text) SECURITY DEFINER;
ALTER FUNCTION authz.list_subjects(text, text, text, text, text, jsonb, int, int, text) SECURITY DEFINER;
ALTER FUNCTION authz.list_actions(text, text, text, text, text, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.explain_access(text, text, text, text, text, text, jsonb, boolean, boolean) SECURITY DEFINER;
ALTER FUNCTION authz.validate_condition(text, text, jsonb, jsonb) SECURITY DEFINER;

GRANT EXECUTE ON FUNCTION authz.check_access(text, text, text, text, text, text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.check_access_with_context(text, text, text, text, text, text, jsonb) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.list_objects(text, text, text, text, text, jsonb, int, int, text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.list_subjects(text, text, text, text, text, jsonb, int, int, text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.list_actions(text, text, text, text, text, jsonb) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.explain_access(text, text, text, text, text, text, jsonb, boolean, boolean) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.validate_condition(text, text, jsonb, jsonb) TO authz_reader;
