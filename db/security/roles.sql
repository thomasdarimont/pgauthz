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
    -- Dedicated privilege for contextual-tuple checks (see grants below):
    -- callers can inject ephemeral tuples into a decision, so this is kept
    -- separate from the general authz_reader and granted only to trusted PDPs.
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authz_contextual_reader') THEN
        CREATE ROLE authz_contextual_reader NOLOGIN;
    END IF;
    -- Non-superuser owner of the schema and its objects (see the
    -- ownership transfer at the end of this file).
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authz_owner') THEN
        CREATE ROLE authz_owner NOLOGIN;
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

-- AuthZEN Go service (authzen-direct): connects directly and calls the
-- read API (evaluation + search). A dedicated non-superuser LOGIN role
-- that INHERITs authz_reader — read-only, no SET ROLE in the service.
-- Created in db/security/initdb on first boot; created here too so
-- existing databases pick it up on re-init.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authzen_direct') THEN
        -- Dev password — override in production deployments.
        CREATE ROLE authzen_direct LOGIN PASSWORD 'authz';
    END IF;
END
$$;
GRANT authz_reader TO authzen_direct;

-- Playground BFF metadata/explore role: a dedicated read-only LOGIN role for the
-- web playground's ENGINE_DSN. It INHERITs authz_reader (check/explain/describe_model)
-- AND gets direct SELECT on the metadata tables, because the playground browses
-- stores/types/relations/conditions/tuples directly (not only via functions). Never
-- point ENGINE_DSN at a superuser outside the demo — use this role.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authz_metadata') THEN
        -- Dev password — override in production deployments.
        CREATE ROLE authz_metadata LOGIN PASSWORD 'authz';
    END IF;
END
$$;
GRANT authz_reader TO authz_metadata;
GRANT SELECT ON authz.stores, authz.types, authz.relations, authz.conditions, authz.tuples TO authz_metadata;

-- ── Condition-evaluation hardening ──────────────────────────────────
-- Condition expressions are arbitrary SQL evaluated in a sandbox
-- (_exec_condition runs as the zero-privilege authz_eval role). That role
-- already cannot read tables or files (verified: file/table access is denied);
-- the residual risk is resource exhaustion. Two complementary bounds:
--
-- 1. Time — arm a statement_timeout on the service LOGIN roles as a generous
--    hang-backstop. NOTE: this is per-role and applies to EVERY statement on
--    those connections (every check, listing, batch write, and PostgREST's
--    own schema introspection) — not only condition evaluation. So it must be
--    larger than the slowest LEGITIMATE operation: time-travel
--    (audit_check_access, ~seconds) and broad list_objects/list_subjects can
--    take seconds on large stores. 60s reclaims a truly-stuck connection
--    without tripping those. A timed-out condition fails closed: the cancel
--    aborts the check (never a silent allow). Tune per deployment; for large
--    listings prefer pagination (p_limit) and object/user wildcards (O(1)).
ALTER ROLE authz_authenticator SET statement_timeout = '60s';
ALTER ROLE authzen_direct      SET statement_timeout = '60s';
ALTER ROLE authz_metadata      SET statement_timeout = '60s';

-- 2. Capability — pg_sleep is a PUBLIC builtin and the one obvious
--    hang-via-DoS primitive reachable from the sandbox; revoke it (and its
--    siblings) from PUBLIC. Superusers bypass grants and are unaffected; no
--    non-superuser authorization path needs to sleep. NOTE: this is
--    database-wide for non-superusers — if pgauthz shares its database with
--    other applications that legitimately call pg_sleep, drop these REVOKEs.
--    (Blocking named functions is defense-in-depth, not a substitute for the
--    statement_timeout above — arbitrary expensive pure-SQL needs no builtin.)
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_sleep(double precision)               FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_sleep_for(interval)                   FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_catalog.pg_sleep_until(timestamp with time zone) FROM PUBLIC;

-- All roles need schema access.
GRANT USAGE ON SCHEMA authz TO authz_auditor, authz_reader, authz_writer, authz_admin, authz_contextual_reader;

------------------------------------------------------------------------
-- authz_auditor: audit trail and time-travel queries (compliance/security)
------------------------------------------------------------------------
GRANT EXECUTE ON FUNCTION authz.audit_list_user(text, text, text, timestamptz, timestamptz) TO authz_auditor;
GRANT EXECUTE ON FUNCTION authz.audit_list_object(text, text, text, timestamptz, timestamptz) TO authz_auditor;
GRANT EXECUTE ON FUNCTION authz.audit_check_access(text, text, text, text, text, text, timestamptz, jsonb) TO authz_auditor;
GRANT EXECUTE ON FUNCTION authz.audit_list_actions(text, text, text, text, text, timestamptz, jsonb) TO authz_auditor;
-- Watch / changefeed (reads the audit log) — auditor-level privilege.
GRANT EXECUTE ON FUNCTION authz.watch_changes(text, timestamptz, bigint, int, interval, text[], text[], text[]) TO authz_auditor;
GRANT EXECUTE ON FUNCTION authz.watch_cursor(text) TO authz_auditor;

------------------------------------------------------------------------
-- authz_reader: access checks and search queries
------------------------------------------------------------------------
GRANT EXECUTE ON FUNCTION authz.check_access(text, text, text, text, text, text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.check_access_with_context(text, text, text, text, text, text, jsonb) TO authz_reader;
-- Contextual-tuple checks let the caller inject EPHEMERAL tuples into a
-- decision (e.g. "would alice be a viewer if this grant existed?"). That is
-- powerful for trusted backend/PDP usage, but if exposed to user-controlled
-- clients a caller could inject the very grant being tested. So they live
-- behind a SEPARATE role — authz_contextual_reader — NOT the general
-- authz_reader (which api_anon inherits). Grant authz_contextual_reader only
-- to trusted callers; never to a role reachable by untrusted clients.
--   e.g.  GRANT authz_contextual_reader TO <trusted_backend_role>;
-- (REVOKE from authz_reader too, in case an older install granted it there.)
REVOKE EXECUTE ON FUNCTION authz.check_access_with_contextual_tuples(text, text, text, text, text, text, jsonb, authz.tuple_input[]) FROM authz_reader;
REVOKE EXECUTE ON FUNCTION authz.check_access_with_contextual_tuples_jsonb(text, text, text, text, text, text, jsonb, jsonb) FROM authz_reader;
GRANT EXECUTE ON FUNCTION authz.check_access_with_contextual_tuples(text, text, text, text, text, text, jsonb, authz.tuple_input[]) TO authz_contextual_reader;
GRANT EXECUTE ON FUNCTION authz.check_access_with_contextual_tuples_jsonb(text, text, text, text, text, text, jsonb, jsonb) TO authz_contextual_reader;
GRANT EXECUTE ON FUNCTION authz.check_access_batch(text, jsonb, jsonb, text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.check_access_batch_typed(text, authz.access_check[], jsonb, text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.check_access_batch_typed_jsonb(text, jsonb, jsonb, text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.list_objects(text, text, text, text, text, jsonb, int, int, text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.list_subjects(text, text, text, text, text, jsonb, int, int, text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.list_actions(text, text, text, text, text, jsonb) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.validate_condition(text, text, jsonb, jsonb) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.explain_access(text, text, text, text, text, text, jsonb, boolean, boolean) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.check_access_detailed(text, text, text, text, text, text, jsonb) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.describe_model(text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.export_model(text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.model_status(text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.model_rollout_status(text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.list_model_versions(text) TO authz_reader;
GRANT EXECUTE ON FUNCTION authz.plan_model_apply(text, text, integer) TO authz_reader;

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
GRANT EXECUTE ON FUNCTION authz.write_tuples_checked(text, jsonb, jsonb, jsonb, text) TO authz_writer;
-- PostgREST db-pre-request hook (runs as the anon->authz_writer role).
GRANT EXECUTE ON FUNCTION authz._pre_request() TO authz_writer;
-- Reader-side hook (runs as api_anon → per-app reader role; see slice B of
-- per-app namespace isolation). Granted to authz_reader so api_anon inherits.
GRANT EXECUTE ON FUNCTION authz._pre_request_reader() TO authz_reader;

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
GRANT EXECUTE ON FUNCTION authz.retire_store(text) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.delete_store(text, boolean) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_register_type(text, text, int, text, text, text[]) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_set_type_labels(text, text, text[]) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_add_type_labels(text, text, text[]) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_remove_type_labels(text, text, text[]) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_register_relation(text, text, text) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_add_rule(text, text, text, text, text, text, text, integer, text, boolean, boolean) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_remove_rule(text, integer) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_remove_rules(text, text, text) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_add_type_restriction(text, text, text, text, text, boolean) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_remove_type_restriction(text, integer) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.model_remove_type_restrictions(text, text, text) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.import_openfga_model(text, jsonb) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.import_openfga_tuples(text, jsonb) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.create_condition(text, text, text, text, jsonb) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.create_condition_sql(text, text, text, jsonb) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.create_condition_cel(text, text, text, jsonb) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.delete_condition(text, text) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.publish_model(text, text, text) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.apply_model(text, text, integer) TO authz_admin;
GRANT EXECUTE ON FUNCTION authz.apply_model(text[], text, integer) TO authz_admin;

------------------------------------------------------------------------
-- SECURITY DEFINER: all public functions run as the owning role
-- (authz_owner, a non-superuser — see the ownership transfer below) so
-- application roles need no direct table access.
------------------------------------------------------------------------
ALTER FUNCTION authz.check_access(text, text, text, text, text, text) SECURITY DEFINER;
ALTER FUNCTION authz.check_access_with_context(text, text, text, text, text, text, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.check_access_with_contextual_tuples(text, text, text, text, text, text, jsonb, authz.tuple_input[]) SECURITY DEFINER;
ALTER FUNCTION authz.check_access_batch_typed(text, authz.access_check[], jsonb, text) SECURITY DEFINER;
ALTER FUNCTION authz.check_access_batch(text, jsonb, jsonb, text) SECURITY DEFINER;
-- jsonb-input wrappers: keep the whole public API uniformly SECURITY DEFINER
-- (they only validate + delegate to the variants above, but this makes the
-- posture explicit and gets them search_path pinning below). See SECURITY-AUDIT F1.
ALTER FUNCTION authz.check_access_with_contextual_tuples_jsonb(text, text, text, text, text, text, jsonb, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.check_access_batch_typed_jsonb(text, jsonb, jsonb, text) SECURITY DEFINER;
ALTER FUNCTION authz.list_objects(text, text, text, text, text, jsonb, int, int, text) SECURITY DEFINER;
ALTER FUNCTION authz.list_subjects(text, text, text, text, text, jsonb, int, int, text) SECURITY DEFINER;
ALTER FUNCTION authz.list_actions(text, text, text, text, text, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.validate_condition(text, text, jsonb, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.audit_check_access(text, text, text, text, text, text, timestamptz, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.audit_list_actions(text, text, text, text, text, timestamptz, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.audit_list_user(text, text, text, timestamptz, timestamptz) SECURITY DEFINER;
ALTER FUNCTION authz.audit_list_object(text, text, text, timestamptz, timestamptz) SECURITY DEFINER;
ALTER FUNCTION authz.watch_changes(text, timestamptz, bigint, int, interval, text[], text[], text[]) SECURITY DEFINER;
ALTER FUNCTION authz.watch_cursor(text) SECURITY DEFINER;
ALTER FUNCTION authz.explain_access(text, text, text, text, text, text, jsonb, boolean, boolean) SECURITY DEFINER;
ALTER FUNCTION authz.check_access_detailed(text, text, text, text, text, text, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.describe_model(text) SECURITY DEFINER;
ALTER FUNCTION authz.write_tuple(text, text, text, text, text, text, text, text, jsonb, text) SECURITY DEFINER;
ALTER FUNCTION authz.delete_tuple(text, text, text, text, text, text, text, text) SECURITY DEFINER;
ALTER FUNCTION authz.write_tuples(text, authz.tuple_input[], text) SECURITY DEFINER;
ALTER FUNCTION authz.write_tuples_jsonb(text, jsonb, text) SECURITY DEFINER;
ALTER FUNCTION authz.delete_tuples(text, authz.tuple_input[], text) SECURITY DEFINER;
ALTER FUNCTION authz.delete_tuples_jsonb(text, jsonb, text) SECURITY DEFINER;
ALTER FUNCTION authz.delete_user_tuples(text, text, text, text) SECURITY DEFINER;
ALTER FUNCTION authz.write_tuples_checked(text, jsonb, jsonb, jsonb, text) SECURITY DEFINER;
ALTER FUNCTION authz.grant_namespace_access(text, text, text, boolean, boolean) SECURITY DEFINER;
ALTER FUNCTION authz.revoke_namespace_access(text, text, text, boolean, boolean) SECURITY DEFINER;
ALTER FUNCTION authz.find_redundant_tuples(text, text, text, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.cleanup_redundant_tuples(text, text, text, jsonb, boolean) SECURITY DEFINER;
ALTER FUNCTION authz.ensure_audit_partitions(int) SECURITY DEFINER;
ALTER FUNCTION authz.create_store(text, text) SECURITY DEFINER;
ALTER FUNCTION authz.retire_store(text) SECURITY DEFINER;
ALTER FUNCTION authz.delete_store(text, boolean) SECURITY DEFINER;
ALTER FUNCTION authz.model_register_type(text, text, int, text, text, text[]) SECURITY DEFINER;
ALTER FUNCTION authz.model_set_type_labels(text, text, text[]) SECURITY DEFINER;
ALTER FUNCTION authz.model_add_type_labels(text, text, text[]) SECURITY DEFINER;
ALTER FUNCTION authz.model_remove_type_labels(text, text, text[]) SECURITY DEFINER;
ALTER FUNCTION authz.model_register_relation(text, text, text) SECURITY DEFINER;
ALTER FUNCTION authz.model_add_rule(text, text, text, text, text, text, text, integer, text, boolean, boolean) SECURITY DEFINER;
ALTER FUNCTION authz.model_remove_rule(text, integer) SECURITY DEFINER;
ALTER FUNCTION authz.model_remove_rules(text, text, text) SECURITY DEFINER;
ALTER FUNCTION authz.model_add_type_restriction(text, text, text, text, text, boolean) SECURITY DEFINER;
ALTER FUNCTION authz.model_remove_type_restriction(text, integer) SECURITY DEFINER;
ALTER FUNCTION authz.model_remove_type_restrictions(text, text, text) SECURITY DEFINER;
ALTER FUNCTION authz.import_openfga_model(text, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.import_openfga_tuples(text, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.create_condition(text, text, text, text, jsonb) SECURITY DEFINER;
-- The lang-specific wrappers delegate to create_condition; making them definer
-- keeps the API uniform and prevents inlining from running them as the caller.
-- See SECURITY-AUDIT F2.
ALTER FUNCTION authz.create_condition_sql(text, text, text, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.create_condition_cel(text, text, text, jsonb) SECURITY DEFINER;
ALTER FUNCTION authz.delete_condition(text, text) SECURITY DEFINER;
ALTER FUNCTION authz.export_model(text) SECURITY DEFINER;
ALTER FUNCTION authz.model_status(text) SECURITY DEFINER;
ALTER FUNCTION authz.model_rollout_status(text) SECURITY DEFINER;
ALTER FUNCTION authz.list_model_versions(text) SECURITY DEFINER;
ALTER FUNCTION authz.publish_model(text, text, text) SECURITY DEFINER;
ALTER FUNCTION authz.apply_model(text, text, integer) SECURITY DEFINER;
ALTER FUNCTION authz.apply_model(text[], text, integer) SECURITY DEFINER;
ALTER FUNCTION authz.plan_model_apply(text, text, integer) SECURITY DEFINER;

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

------------------------------------------------------------------------
-- The condition sandbox stays owned by authz_eval, so authz_owner does
-- not own it and (PUBLIC execute having been revoked above) needs an
-- explicit grant to call it. The sandbox boundary is unaffected:
-- _exec_condition still RUNS as authz_eval; this only lets the engine
-- invoke it. Every other internal function is owned by authz_owner, so
-- no other grant is needed.
------------------------------------------------------------------------
GRANT EXECUTE ON FUNCTION authz._exec_condition(text, jsonb, jsonb) TO authz_owner;

------------------------------------------------------------------------
-- Transfer ownership to the non-superuser authz_owner.
--
-- The database is bootstrapped by the superuser 'authz', so everything
-- it created is superuser-owned — which means every SECURITY DEFINER
-- function would run with superuser privileges. Reassign the schema and
-- all its objects to authz_owner so definer functions run with only the
-- privileges they actually need: ownership of the authz tables and
-- functions, nothing more. Defense in depth — a flaw in a definer
-- function cannot escalate to superuser.
--
-- REASSIGN OWNED is not usable here: 'authz' is the bootstrap superuser
-- and owns system-required objects, which it refuses to reassign. So we
-- transfer the authz schema's own objects explicitly.
--
-- The condition sandbox (_exec_condition, owned by the zero-privilege
-- authz_eval role) is deliberately excluded so it keeps running with no
-- table/function access. The database itself stays owned by 'authz'.
--
-- Objects created later through the API functions (store/partition
-- management) are owned by authz_owner automatically, because those
-- functions now run as authz_owner.
------------------------------------------------------------------------
ALTER SCHEMA authz OWNER TO authz_owner;

DO $$
DECLARE
    r record;
BEGIN
    -- Tables (incl. partitions), partitioned tables, views, matviews.
    FOR r IN
        SELECT c.oid::regclass AS obj,
               CASE c.relkind WHEN 'v' THEN 'VIEW'
                              WHEN 'm' THEN 'MATERIALIZED VIEW'
                              ELSE 'TABLE' END AS kind
          FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'authz'
           AND c.relkind IN ('r', 'p', 'v', 'm')
    LOOP
        EXECUTE format('ALTER %s %s OWNER TO authz_owner', r.kind, r.obj);
    END LOOP;

    -- Standalone types (composite/base/domain/enum). Excludes array
    -- types and tables' implicit row types, which follow their table.
    FOR r IN
        SELECT t.oid::regtype AS obj
          FROM pg_catalog.pg_type t
          JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
         WHERE n.nspname = 'authz'
           AND t.typtype IN ('c', 'b', 'd', 'e')
           AND t.typcategory <> 'A'
           AND (t.typrelid = 0
                OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c
                            WHERE c.oid = t.typrelid AND c.relkind = 'c'))
    LOOP
        EXECUTE format('ALTER TYPE %s OWNER TO authz_owner', r.obj);
    END LOOP;

    -- Routines, except the condition sandbox (stays on authz_eval).
    FOR r IN
        SELECT p.oid::regprocedure AS obj
          FROM pg_catalog.pg_proc p
          JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'authz'
           AND p.proname <> '_exec_condition'
    LOOP
        EXECUTE format('ALTER ROUTINE %s OWNER TO authz_owner', r.obj);
    END LOOP;
END
$$;
