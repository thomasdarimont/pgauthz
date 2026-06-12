-- Role setup for authorization API access control.
--
-- Application roles (NOLOGIN — used via SET ROLE or inheritance):
--   authz_reader  — access checks and search queries (PostgREST/OPA)
--   authz_auditor — reader + audit trail queries (compliance/security teams)
--   authz_writer  — reader + write tuples (application backends)
--   authz_admin   — full control including store management
--   api_anon      — PostgREST anonymous role (inherits authz_reader)
--
-- Connection role (LOGIN, NOINHERIT):
--   authz_authenticator — PostgREST connects as this role and switches
--                         to api_anon or the JWT role via SET ROLE
--
-- Role hierarchy:
--
--   api_anon ─→ authz_reader ─┬─→ authz_auditor ──┬─→ authz_admin
--                             └─→ authz_writer ───┘
--
-- Note: authz_eval (condition expression sandbox) is created in
-- schema.sql because core_internal.sql depends on it at load time.

------------------------------------------------------------------------
-- Revoke default PUBLIC execute on all authz functions.
-- After this, only explicitly granted roles can call anything.
------------------------------------------------------------------------
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;

------------------------------------------------------------------------
-- Create roles (idempotent)
------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authz_reader') THEN
        CREATE ROLE authz_reader NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authz_writer') THEN
        CREATE ROLE authz_writer NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authz_auditor') THEN
        CREATE ROLE authz_auditor NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authz_admin') THEN
        CREATE ROLE authz_admin NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'api_anon') THEN
        CREATE ROLE api_anon NOLOGIN;
    END IF;
END
$$;

-- Role hierarchy: auditor and writer inherit reader, admin inherits writer + auditor.
GRANT authz_reader TO authz_auditor;
GRANT authz_reader TO authz_writer;
GRANT authz_writer TO authz_admin;
GRANT authz_auditor TO authz_admin;

-- PostgREST anonymous role inherits reader privileges.
GRANT authz_reader TO api_anon;

-- PostgREST authenticator: a dedicated non-superuser LOGIN role.
-- PostgREST connects as this role and switches the per-request identity
-- with SET ROLE (api_anon, or the role claimed in the JWT). NOINHERIT
-- ensures the authenticator has no privileges of its own — every request
-- runs as the switched role. Never use a superuser here: namespace
-- enforcement keys on the effective role and a superuser passes every
-- pg_has_role() check.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authz_authenticator') THEN
        -- Dev password — override in production deployments.
        CREATE ROLE authz_authenticator LOGIN NOINHERIT PASSWORD 'authz';
    END IF;
END
$$;

-- The authenticator must be able to SET ROLE to any role a request
-- (anonymous or JWT-claimed) may run as.
GRANT api_anon      TO authz_authenticator;
GRANT authz_reader  TO authz_authenticator;
GRANT authz_auditor TO authz_authenticator;
GRANT authz_writer  TO authz_authenticator;
GRANT authz_admin   TO authz_authenticator;

-- All roles need schema access.
GRANT USAGE ON SCHEMA authz TO authz_auditor, authz_reader, authz_writer, authz_admin;

------------------------------------------------------------------------
-- authz_auditor: audit trail and time-travel queries (compliance/security)
------------------------------------------------------------------------
GRANT EXECUTE ON FUNCTION authz.audit_list_user(text, text, text, timestamptz, timestamptz) TO authz_auditor;
GRANT EXECUTE ON FUNCTION authz.audit_list_object(text, text, text, timestamptz, timestamptz) TO authz_auditor;
GRANT EXECUTE ON FUNCTION authz.audit_check_access(text, text, text, text, text, text, timestamptz, jsonb) TO authz_auditor;
GRANT EXECUTE ON FUNCTION authz.audit_list_actions(text, text, text, text, text, timestamptz, jsonb) TO authz_auditor;

------------------------------------------------------------------------
-- authz_reader: access checks and search queries
------------------------------------------------------------------------
GRANT EXECUTE ON FUNCTION authz.check_access(text, text, text, text, text, text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.check_access_with_context(text, text, text, text, text, text, jsonb) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.check_access_with_contextual_tuples(text, text, text, text, text, text, jsonb, authz.tuple_input[]) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.check_access_with_contextual_tuples_jsonb(text, text, text, text, text, text, jsonb, jsonb) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.check_access_batch(text, jsonb, jsonb, text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.check_access_batch_typed(text, authz.access_check[], jsonb, text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.check_access_batch_typed_jsonb(text, jsonb, jsonb, text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.list_objects(text, text, text, text, text, jsonb, int, int) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.list_subjects(text, text, text, text, text, jsonb, int, int) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.list_actions(text, text, text, text, text, jsonb) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.validate_condition(text, text, jsonb, jsonb) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.explain_access(text, text, text, text, text, text, jsonb, boolean) TO authz_reader;

------------------------------------------------------------------------
-- authz_writer: tuple management (inherits reader grants above)
------------------------------------------------------------------------
GRANT EXECUTE ON FUNCTION authz.write_tuple(text, text, text, text, text, text, text, text, jsonb, text) TO authz_writer;
GRANT EXECUTE ON FUNCTION authz.delete_tuple(text, text, text, text, text, text, text, text) TO authz_writer;
GRANT EXECUTE ON FUNCTION authz.write_tuples(text, authz.tuple_input[], text) TO authz_writer;
GRANT EXECUTE ON FUNCTION authz.write_tuples_jsonb(text, jsonb, text) TO authz_writer;
GRANT EXECUTE ON FUNCTION authz.delete_tuples(text, authz.tuple_input[], text) TO authz_writer;
GRANT EXECUTE ON FUNCTION authz.delete_tuples_jsonb(text, jsonb, text) TO authz_writer;
GRANT EXECUTE ON FUNCTION authz.delete_user_tuples(text, text, text, text) TO authz_writer;

------------------------------------------------------------------------
-- authz_admin: store lifecycle and namespace management
-- (inherits writer + reader grants above)
------------------------------------------------------------------------
-- No direct table grants — all access goes through SECURITY DEFINER functions.
-- This prevents PostgREST from exposing table endpoints via REST.
GRANT EXECUTE ON FUNCTION authz.grant_namespace_access(text, text, text, boolean, boolean) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.revoke_namespace_access(text, text, text, boolean, boolean) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.find_redundant_tuples(text, text, text, jsonb) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.cleanup_redundant_tuples(text, text, text, jsonb, boolean) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.ensure_audit_partitions(int) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.create_store(text, text) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.delete_store(text, boolean) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_register_type(text, text, int, text, text) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_register_relation(text, text, text) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_add_rule(text, text, text, text, text, text, text, smallint, text, boolean) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_remove_rule(text, smallint) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_remove_rules(text, text, text) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_add_type_restriction(text, text, text, text, text, boolean) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_remove_type_restriction(text, smallint) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_remove_type_restrictions(text, text, text) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.import_openfga_model(text, jsonb) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.import_openfga_tuples(text, jsonb) TO authz_admin;

------------------------------------------------------------------------
-- SECURITY DEFINER: all public functions run as the owning role (authz)
-- so application roles need no direct table access.
------------------------------------------------------------------------
ALTER FUNCTION authz.check_access(text, text, text, text, text, text) SECURITY DEFINER;
ALTER FUNCTION authz.check_access_with_context(text, text, text, text, text, text, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.check_access_with_contextual_tuples(text, text, text, text, text, text, jsonb, authz.tuple_input[]) SECURITY DEFINER;
ALTER FUNCTION authz.check_access_batch_typed(text, authz.access_check[], jsonb, text) SECURITY DEFINER;
ALTER FUNCTION authz.check_access_batch(text, jsonb, jsonb, text) SECURITY DEFINER;
ALTER FUNCTION authz.list_objects(text, text, text, text, text, jsonb, int, int) SECURITY DEFINER;
ALTER FUNCTION authz.list_subjects(text, text, text, text, text, jsonb, int, int) SECURITY DEFINER;
ALTER FUNCTION authz.list_actions(text, text, text, text, text, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.validate_condition(text, text, jsonb, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.audit_check_access(text, text, text, text, text, text, timestamptz, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.audit_list_actions(text, text, text, text, text, timestamptz, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.audit_list_user(text, text, text, timestamptz, timestamptz) SECURITY DEFINER;
ALTER FUNCTION authz.audit_list_object(text, text, text, timestamptz, timestamptz) SECURITY DEFINER;
ALTER FUNCTION authz.explain_access(text, text, text, text, text, text, jsonb, boolean) SECURITY DEFINER;
ALTER FUNCTION authz.write_tuple(text, text, text, text, text, text, text, text, jsonb, text) SECURITY DEFINER;
ALTER FUNCTION authz.delete_tuple(text, text, text, text, text, text, text, text) SECURITY DEFINER;
ALTER FUNCTION authz.write_tuples(text, authz.tuple_input[], text) SECURITY DEFINER;
ALTER FUNCTION authz.delete_tuples(text, authz.tuple_input[], text) SECURITY DEFINER;
ALTER FUNCTION authz.delete_user_tuples(text, text, text, text) SECURITY DEFINER;
ALTER FUNCTION authz.grant_namespace_access(text, text, text, boolean, boolean) SECURITY DEFINER;
ALTER FUNCTION authz.revoke_namespace_access(text, text, text, boolean, boolean) SECURITY DEFINER;
ALTER FUNCTION authz.find_redundant_tuples(text, text, text, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.cleanup_redundant_tuples(text, text, text, jsonb, boolean) SECURITY DEFINER;
ALTER FUNCTION authz.ensure_audit_partitions(int) SECURITY DEFINER;
ALTER FUNCTION authz.create_store(text, text) SECURITY DEFINER;
ALTER FUNCTION authz.delete_store(text, boolean) SECURITY DEFINER;
ALTER FUNCTION authz.model_register_type(text, text, int, text, text) SECURITY DEFINER;
ALTER FUNCTION authz.model_register_relation(text, text, text) SECURITY DEFINER;
ALTER FUNCTION authz.model_add_rule(text, text, text, text, text, text, text, smallint, text, boolean) SECURITY DEFINER;
ALTER FUNCTION authz.model_remove_rule(text, smallint) SECURITY DEFINER;
ALTER FUNCTION authz.model_remove_rules(text, text, text) SECURITY DEFINER;
ALTER FUNCTION authz.model_add_type_restriction(text, text, text, text, text, boolean) SECURITY DEFINER;
ALTER FUNCTION authz.model_remove_type_restriction(text, smallint) SECURITY DEFINER;
ALTER FUNCTION authz.model_remove_type_restrictions(text, text, text) SECURITY DEFINER;
ALTER FUNCTION authz.import_openfga_model(text, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.import_openfga_tuples(text, jsonb) SECURITY DEFINER;

------------------------------------------------------------------------
-- Pin search_path on every SECURITY DEFINER function so a caller's
-- search_path cannot influence name resolution inside trusted code
-- (standard definer-function hardening). pg_temp must be listed last:
-- explain_access / audit_check_access reference their session temp
-- tables (_access_trace, _snapshot_tuples) unqualified, and an
-- implicit pg_temp would otherwise be searched FIRST for relations.
--
-- Only definer functions are pinned: search_path is dynamically
-- scoped, so internal helpers called from a pinned entry point resolve
-- under the pinned path too — and a SET clause would prevent inlining
-- of the hot-path helper functions.
--
-- Runs dynamically over pg_proc so newly added definer functions are
-- covered on the next init without touching this file.
------------------------------------------------------------------------
DO $$
DECLARE
    f record;
BEGIN
    FOR f IN
        SELECT p.oid::regprocedure AS sig
          FROM pg_catalog.pg_proc p
          JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'authz'
           AND p.prosecdef
    LOOP
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, authz, pg_temp', f.sig);
    END LOOP;
END
$$;
