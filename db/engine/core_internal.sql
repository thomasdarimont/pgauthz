-- Internal core functions: ID resolution, namespace access, constants,
-- partition management, and condition evaluation.
-- These use integer IDs for performance and are not meant to be called directly.
-- All function names are prefixed with an underscore.
--
-- Depends on: engine/schema.sql (must be loaded first)

------------------------------------------------------------------------
-- ID resolution helpers — used at schema-load time and by public API
-- functions to convert text names to integer IDs.
--
-- Strict by default: unknown names raise instead of returning NULL,
-- so a typo'd store, type, or relation name surfaces as an error
-- rather than a silent deny — a silent false is indistinguishable
-- from a correct denial and makes expected-deny tests pass even when
-- the name is misspelled. User/object IDs are data, not schema, and
-- are never validated. Code that genuinely needs to probe for
-- existence should query the lookup tables directly.
--
-- VOLATILE, not STABLE, deliberately: the planner pre-evaluates STABLE
-- functions used as comparison constants (selectivity estimation) with
-- a snapshot that can predate same-transaction changes — a query like
-- "WHERE store_id = authz._s('x')" right after creating store 'x' in
-- the same transaction would then raise 'Unknown store' at plan time.
-- VOLATILE functions are never pre-evaluated by the planner.
------------------------------------------------------------------------

-- Resolve a store name (e.g. 'demo') to its integer ID.
-- Resolve a store name to its integer ID.
--
-- By default resolves only LIVE (non-retired) stores, so every live API
-- (check / write / model / list) automatically rejects a retired store with
-- a clear error. The audit_* time-travel functions pass p_include_retired =>
-- true so a retired store's preserved history stays queryable by name.
-- See retire_store (engine/store.sql) and migration 0002_store_retire.sql.
CREATE OR REPLACE FUNCTION authz._s(p_name text, p_include_retired boolean) RETURNS integer
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    v_id      integer;
    v_deleted timestamptz;
BEGIN
    SELECT id, deleted_at INTO v_id, v_deleted FROM authz.stores WHERE name = p_name;
    IF v_id IS NULL THEN
        RAISE EXCEPTION 'Unknown store: %', p_name;
    END IF;
    IF v_deleted IS NOT NULL AND NOT p_include_retired THEN
        RAISE EXCEPTION 'Store is retired: % (at %) — use the audit_* functions for its history, or delete_store to purge it',
            p_name, v_deleted;
    END IF;
    RETURN v_id;
END;
$$;

-- Default overload: live stores only (the common case).
CREATE OR REPLACE FUNCTION authz._s(p_name text) RETURNS integer
    LANGUAGE sql VOLATILE AS $$ SELECT authz._s(p_name, false) $$;

-- Resolve a type name (e.g. 'document') to its integer ID within a store.
CREATE OR REPLACE FUNCTION authz._t(p_store_id integer, p_name text) RETURNS integer
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    v_id integer;
BEGIN
    SELECT id INTO v_id FROM authz.types WHERE store_id = p_store_id AND name = p_name;
    IF v_id IS NULL THEN
        RAISE EXCEPTION 'Unknown type: %', p_name;
    END IF;
    RETURN v_id;
END;
$$;

-- Convenience overload: resolve type by store name instead of store ID.
CREATE OR REPLACE FUNCTION authz._t(p_store text, p_name text) RETURNS integer
    LANGUAGE sql VOLATILE AS $$ SELECT authz._t(authz._s(p_store), p_name) $$;

-- Resolve a relation name (e.g. 'can_read') to its integer ID within a store.
CREATE OR REPLACE FUNCTION authz._r(p_store_id integer, p_name text) RETURNS integer
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    v_id integer;
BEGIN
    SELECT id INTO v_id FROM authz.relations WHERE store_id = p_store_id AND name = p_name;
    IF v_id IS NULL THEN
        RAISE EXCEPTION 'Unknown relation: %', p_name;
    END IF;
    RETURN v_id;
END;
$$;

-- Convenience overload: resolve relation by store name instead of store ID.
CREATE OR REPLACE FUNCTION authz._r(p_store text, p_name text) RETURNS integer
    LANGUAGE sql VOLATILE AS $$ SELECT authz._r(authz._s(p_store), p_name) $$;

------------------------------------------------------------------------
-- _validate_tuple_jsonb: validates that each element in a JSONB array
-- contains the required keys for a tuple_input.
-- Required: user_type, user_id, relation, object_type, object_id.
-- Optional: user_relation (may be omitted or null).
-- Raises EXCEPTION with a descriptive message on the first violation.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._validate_tuple_jsonb(p_tuples jsonb) RETURNS void
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    v_len      int;
    v_elem     jsonb;
    v_key      text;
    v_required text[] := ARRAY['user_type', 'user_id', 'relation', 'object_type', 'object_id'];
    i          int;
BEGIN
    IF p_tuples IS NULL OR jsonb_typeof(p_tuples) != 'array' THEN
        RAISE EXCEPTION 'p_tuples must be a JSON array, got: %', jsonb_typeof(p_tuples);
    END IF;

    v_len := jsonb_array_length(p_tuples);

    FOR i IN 0 .. v_len - 1 LOOP
        v_elem := p_tuples->i;

        IF jsonb_typeof(v_elem) != 'object' THEN
            RAISE EXCEPTION 'Tuple at index % must be a JSON object, got: %', i, jsonb_typeof(v_elem);
        END IF;

        FOREACH v_key IN ARRAY v_required LOOP
            IF NOT (v_elem ? v_key) OR v_elem->>v_key IS NULL THEN
                RAISE EXCEPTION 'Missing required key "%" in tuple at index %', v_key, i;
            END IF;
        END LOOP;
    END LOOP;
END;
$$;

------------------------------------------------------------------------
-- _effective_role: the identity used for permission decisions.
--
-- API gateways like PostgREST connect as a single authenticator role
-- and switch the per-request identity with SET ROLE. That updates the
-- 'role' GUC but not session_user — and inside SECURITY DEFINER
-- functions current_user is the function owner — so neither built-in
-- reflects the request identity. The 'role' GUC does; fall back to
-- session_user for direct connections that never ran SET ROLE.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._effective_role() RETURNS text
    LANGUAGE sql STABLE AS
    $$ SELECT COALESCE(NULLIF(current_setting('role', true), 'none'), session_user) $$;

------------------------------------------------------------------------
-- _pre_request: PostgREST db-pre-request hook for the OPA-fronted writer.
--
-- The writer connects as authz_authenticator and runs as a fixed authz_writer.
-- To preserve per-application namespace isolation, OPA forwards the caller's
-- app role in the X-Authz-Role request header; this hook validates it and
-- SET LOCAL ROLEs to it, so namespace enforcement (_check_namespace_access via
-- _effective_role) applies to the per-app role rather than the fixed one.
--
-- Security:
--   * Only a role that is a MEMBER of authz_writer (a tuple writer) and is NOT
--     a member of authz_admin may be assumed — a forged or over-scoped header
--     can never escalate to admin or any non-writer role.
--   * The header is trustworthy because the writer is reachable only by OPA,
--     which sets it from the verified JWT (clients cannot reach the writer).
--   * SET LOCAL ROLE is transaction-scoped, so the assumed role never leaks
--     across pooled PostgREST connections.
-- Wire it on the writer via PGRST_DB_PRE_REQUEST=authz._pre_request.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._pre_request() RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_headers     json := nullif(current_setting('request.headers', true), '')::json;
    v_role        text := v_headers ->> 'x-authz-role';
    v_consistency text := v_headers ->> 'x-authz-consistency';
BEGIN
    -- Per-write consistency mode (X-Authz-Consistency). Maps a caller-facing
    -- vocabulary onto synchronous_commit for THIS transaction only, so a
    -- deployment can default the writer connection to remote_apply while
    -- individual writes opt up or down:
    --   applied  → remote_apply  (ack only after every synchronous standby has
    --                             APPLIED it — strict-revocation / "t0" mode)
    --   durable  → on            (flushed on sync standbys: survives failover,
    --                             but NOT yet read-visible there)
    --   eventual → local         (primary-only durability; replicas catch up)
    -- Absent header → the connection default applies. Unknown values FAIL
    -- CLOSED — a misspelled consistency request must never be silently
    -- reinterpreted as a weaker guarantee.
    IF v_consistency IS NOT NULL AND v_consistency <> '' THEN
        CASE v_consistency
            WHEN 'applied'  THEN SET LOCAL synchronous_commit = remote_apply;
            WHEN 'durable'  THEN SET LOCAL synchronous_commit = on;
            WHEN 'eventual' THEN SET LOCAL synchronous_commit = local;
            ELSE RAISE EXCEPTION
                'Unknown consistency mode "%" (expected applied | durable | eventual)',
                v_consistency USING ERRCODE = 'invalid_parameter_value';
        END CASE;
    END IF;

    -- No requested role → keep the default writer role (no namespace scoping).
    IF v_role IS NULL OR v_role = '' THEN
        RETURN;
    END IF;

    -- The role must exist, be a tuple writer, and NOT be an admin role.
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_role)
       OR NOT pg_has_role(v_role, 'authz_writer', 'MEMBER')
       OR pg_has_role(v_role, 'authz_admin', 'MEMBER') THEN
        RAISE EXCEPTION 'Role "%" is not an allowed writer role', v_role
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    EXECUTE format('SET LOCAL ROLE %I', v_role);
END;
$$;

------------------------------------------------------------------------
-- _check_namespace_access: enforces namespace-based access restrictions.
-- Raises an exception if the effective role is not authorized to perform
-- the requested operation on tuples for the given object type's namespace.
-- p_permission must be 'can_read' or 'can_write'.
-- Types with namespace = NULL are unrestricted (always allowed).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._check_namespace_access(
    p_store_id    integer,
    p_object_type integer,
    p_permission  text DEFAULT 'can_write'
) RETURNS void
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_namespace text;
    v_type_name text;
    v_action    text;
    v_role      text := authz._effective_role();
BEGIN
    SELECT namespace, name INTO v_namespace, v_type_name
      FROM authz.types
     WHERE id = p_object_type AND store_id = p_store_id;

    -- NULL namespace = unrestricted
    IF v_namespace IS NULL THEN
        RETURN;
    END IF;

    -- Check if the effective role is a member of any granted role with
    -- the required permission
    IF EXISTS (
        SELECT 1 FROM authz.namespace_access na
         WHERE na.store_id  = p_store_id
           AND na.namespace = v_namespace
           AND CASE p_permission
                   WHEN 'can_read'  THEN na.can_read
                   WHEN 'can_write' THEN na.can_write
                   ELSE false
               END
           AND pg_has_role(v_role, na.db_role, 'MEMBER')
    ) THEN
        RETURN;
    END IF;

    v_action := CASE p_permission
        WHEN 'can_read'  THEN 'query'
        WHEN 'can_write' THEN 'manage tuples for'
        ELSE p_permission
    END;

    RAISE EXCEPTION 'Permission denied: role "%" cannot % object type "%" in namespace "%"',
        v_role, v_action, v_type_name, v_namespace;
END;
$$;

------------------------------------------------------------------------
-- Rule type constants — used when inserting model rules.
------------------------------------------------------------------------

-- Direct: relation satisfied by a stored tuple linking user to object.
CREATE OR REPLACE FUNCTION authz._rel_direct() RETURNS integer
    LANGUAGE sql IMMUTABLE AS $$ SELECT 1::integer $$;

-- Computed: relation is an alias for another relation on the same object.
CREATE OR REPLACE FUNCTION authz._rel_computed() RETURNS integer
    LANGUAGE sql IMMUTABLE AS $$ SELECT 2::integer $$;

-- Tuple-to-userset: follow a tupleset relation to a linked object,
-- then check a computed relation there.
CREATE OR REPLACE FUNCTION authz._rel_ttu() RETURNS integer
    LANGUAGE sql IMMUTABLE AS $$ SELECT 3::integer $$;

-- Maximum recursion depth for access checks. Every recursion step
-- (computed hop, TTU traversal, userset expansion) consumes one level,
-- so a typical schema layer costs 2-3. The default of 32 accommodates
-- ~10 schema layers or ~28 levels of TTU nesting (OpenFGA defaults
-- to 25). Cycles are pruned independently of this limit.
--
-- Override per session or per database via the authz.max_depth GUC:
--   SET authz.max_depth = '64';
--   ALTER DATABASE authz SET authz.max_depth = '64';
CREATE OR REPLACE FUNCTION authz._max_depth() RETURNS int
    LANGUAGE sql STABLE AS
    $$ SELECT COALESCE(NULLIF(current_setting('authz.max_depth', true), '')::int, 32) $$;

-- Maximum size (bytes) of a condition's request/stored context JSONB. Bounds
-- memory pressure from a caller passing an oversized context into condition
-- evaluation (SECURITY-AUDIT F5). Enforced in _eval_condition. Default 256 KiB.
-- Override per session or per database via the authz.max_context_bytes GUC:
--   SET authz.max_context_bytes = '524288';
CREATE OR REPLACE FUNCTION authz._max_context_bytes() RETURNS int
    LANGUAGE sql STABLE AS
    $$ SELECT COALESCE(NULLIF(current_setting('authz.max_context_bytes', true), '')::int, 262144) $$;

------------------------------------------------------------------------
-- Group operator constants — used when inserting model rules with
-- intersection (AND) or exclusion (BUT NOT) semantics.
------------------------------------------------------------------------

-- OR: any rule in the group matching grants access (default).
CREATE OR REPLACE FUNCTION authz._combine_or() RETURNS integer
    LANGUAGE sql IMMUTABLE AS $$ SELECT 0::integer $$;

-- Intersection: all rules in the group must match.
CREATE OR REPLACE FUNCTION authz._combine_and() RETURNS integer
    LANGUAGE sql IMMUTABLE AS $$ SELECT 1::integer $$;

-- Exclusion: base rules must match AND negated rules must NOT match.
CREATE OR REPLACE FUNCTION authz._combine_exclusion() RETURNS integer
    LANGUAGE sql IMMUTABLE AS $$ SELECT 2::integer $$;

-- (Condition language constants moved to conditions.sql)

------------------------------------------------------------------------
-- _check_type_restriction: validates a single tuple against type
-- restrictions. If no restrictions exist for the (store, object_type,
-- relation), any type is allowed (backward compatible).
-- Raises EXCEPTION on violation.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._check_type_restriction(
    p_store_id      integer,
    p_object_type   integer,
    p_relation      integer,
    p_user_type     integer,
    p_user_relation integer,
    p_user_id       text
) RETURNS void
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_has_restrictions boolean;
    v_allowed          boolean;
    v_object_type_name text;
    v_relation_name    text;
    v_user_type_name   text;
    v_user_rel_name    text;
BEGIN
    -- Check if ANY restrictions exist for this (store, object_type, relation)
    SELECT EXISTS (
        SELECT 1 FROM authz.type_restrictions
         WHERE store_id = p_store_id
           AND object_type = p_object_type
           AND relation = p_relation
    ) INTO v_has_restrictions;

    -- No restrictions defined = allow anything (backward compatible)
    IF NOT v_has_restrictions THEN
        RETURN;
    END IF;

    -- Wildcard tuple (user_id = '*')
    IF p_user_id = '*' THEN
        SELECT EXISTS (
            SELECT 1 FROM authz.type_restrictions
             WHERE store_id = p_store_id
               AND object_type = p_object_type
               AND relation = p_relation
               AND allowed_user_type = p_user_type
               AND allow_wildcard = true
        ) INTO v_allowed;

    -- Userset tuple (user_relation IS NOT NULL)
    ELSIF p_user_relation IS NOT NULL THEN
        SELECT EXISTS (
            SELECT 1 FROM authz.type_restrictions
             WHERE store_id = p_store_id
               AND object_type = p_object_type
               AND relation = p_relation
               AND allowed_user_type = p_user_type
               AND allowed_user_relation = p_user_relation
        ) INTO v_allowed;

    -- Direct user tuple
    ELSE
        SELECT EXISTS (
            SELECT 1 FROM authz.type_restrictions
             WHERE store_id = p_store_id
               AND object_type = p_object_type
               AND relation = p_relation
               AND allowed_user_type = p_user_type
               AND allowed_user_relation IS NULL
               AND allow_wildcard = false
        ) INTO v_allowed;
    END IF;

    IF NOT v_allowed THEN
        SELECT name INTO v_object_type_name FROM authz.types WHERE id = p_object_type;
        SELECT name INTO v_relation_name FROM authz.relations WHERE id = p_relation;
        SELECT name INTO v_user_type_name FROM authz.types WHERE id = p_user_type;
        IF p_user_relation IS NOT NULL THEN
            SELECT name INTO v_user_rel_name FROM authz.relations WHERE id = p_user_relation;
        END IF;

        IF p_user_id = '*' THEN
            RAISE EXCEPTION 'Type restriction violation: wildcard %:* is not allowed as % on %',
                v_user_type_name, v_relation_name, v_object_type_name;
        ELSIF p_user_relation IS NOT NULL THEN
            RAISE EXCEPTION 'Type restriction violation: %#% is not allowed as % on %',
                v_user_type_name, v_user_rel_name, v_relation_name, v_object_type_name;
        ELSE
            RAISE EXCEPTION 'Type restriction violation: % is not allowed as % on %',
                v_user_type_name, v_relation_name, v_object_type_name;
        END IF;
    END IF;
END;
$$;

------------------------------------------------------------------------
-- _ensure_audit_partition: creates a monthly partition for tuples_audit.
-- Partitions are named authz.tuples_audit_YYYY_MM and cover one month.
--
-- p_year:  the year (e.g. 2026)
-- p_month: the month (1-12)
--
-- Returns true if a new partition was created, false if it already existed.
-- Idempotent — safe to call multiple times.
--
-- Example:
--   SELECT authz._ensure_audit_partition(2026, 3);
--   -- creates tuples_audit_2026_03 covering 2026-03-01 to 2026-04-01
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._ensure_audit_partition(
    p_year  int,
    p_month int
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_table_name text;
    v_start      date;
    v_end        date;
BEGIN
    -- Unqualified name (integer-derived, so already safe); %I-quoted in the DDL
    -- below for consistency with the tuple partitions. See SECURITY-AUDIT F3.
    v_table_name := format('tuples_audit_%s_%s', p_year, lpad(p_month::text, 2, '0'));
    v_start      := make_date(p_year, p_month, 1);
    v_end        := v_start + interval '1 month';

    -- Check if partition already exists
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'authz'
           AND c.relname = format('tuples_audit_%s_%s', p_year, lpad(p_month::text, 2, '0'))
           AND c.relispartition
    ) THEN
        RETURN false;
    END IF;

    -- Detach default, create monthly partition, migrate rows, re-attach default
    EXECUTE 'ALTER TABLE authz.tuples_audit DETACH PARTITION authz.tuples_audit_default';
    EXECUTE format(
        'CREATE TABLE authz.%I PARTITION OF authz.tuples_audit FOR VALUES FROM (%L) TO (%L)',
        v_table_name, v_start, v_end
    );

    -- Move rows from the default partition into the new partition.
    -- OVERRIDING SYSTEM VALUE: the rows keep their original seq values
    -- (seq is the audit event order and must survive migration).
    EXECUTE format(
        'INSERT INTO authz.%I OVERRIDING SYSTEM VALUE SELECT * FROM authz.tuples_audit_default WHERE performed_at >= %L AND performed_at < %L',
        v_table_name, v_start, v_end
    );
    -- Sanctioned maintenance: the rows were copied above, so deleting
    -- them from the default partition preserves the audit data overall.
    PERFORM set_config('authz.audit_maintenance', 'on', true);
    EXECUTE format(
        'DELETE FROM authz.tuples_audit_default WHERE performed_at >= %L AND performed_at < %L',
        v_start, v_end
    );
    PERFORM set_config('authz.audit_maintenance', '', true);

    EXECUTE 'ALTER TABLE authz.tuples_audit ATTACH PARTITION authz.tuples_audit_default DEFAULT';

    RETURN true;
END;
$$;

------------------------------------------------------------------------
-- _ensure_tuple_partition: creates a dedicated tuples partition for
-- an object type if one does not already exist.
--
-- The tuples table is LIST-partitioned by object_type. Each object type
-- gets its own partition so that check_access queries benefit from
-- partition pruning — only the relevant partition is scanned.
--
-- For high-volume object types, a second level of HASH sub-partitioning
-- on object_id can be added. This spreads tuples across multiple
-- physical tables, reducing index size and lock contention.
--
-- Parameters:
--   p_type_name    — the object type to partition (must exist in authz.types)
--   p_hash_modulus — number of hash sub-partitions (default 0 = none)
--                    When > 0, creates a two-level partition:
--                      tuples_<type>   (LIST by object_type, partitioned by HASH)
--                        tuples_<type>_0 .. tuples_<type>_N (HASH by object_id)
--
-- Returns true if a new partition was created, false if it already existed.
-- Idempotent — safe to call multiple times for the same type.
--
-- Examples:
--   SELECT authz._ensure_tuple_partition(authz._s('demo'), 'document');
--   SELECT authz._ensure_tuple_partition(authz._s('demo'), 'invoice', 4);
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._ensure_tuple_partition(
    p_store_id     integer,
    p_type_name    text,
    p_hash_modulus int DEFAULT 0
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_type_id    integer;
    v_suffix     text;
    v_table_name text;
    v_store_name text;
    i            int;
BEGIN
    SELECT id INTO v_type_id FROM authz.types WHERE store_id = p_store_id AND name = p_type_name;
    IF v_type_id IS NULL THEN
        RAISE EXCEPTION 'Unknown type: %', p_type_name;
    END IF;

    SELECT name INTO v_store_name FROM authz.stores WHERE id = p_store_id;

    -- Sanitize store + type name for use as table suffix (replace non-alphanumeric with _)
    v_suffix     := regexp_replace(v_store_name, '[^a-zA-Z0-9]', '_', 'g')
                 || '_'
                 || regexp_replace(p_type_name, '[^a-zA-Z0-9]', '_', 'g');
    v_table_name := 'tuples_' || v_suffix;  -- unqualified; quoted via %I in the DDL below

    -- Check if a partition for this type already exists
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'authz'
           AND c.relname = v_table_name
           AND c.relispartition
    ) THEN
        RETURN false;  -- partition already exists
    END IF;

    -- Detach default partition to allow creating a specific one
    EXECUTE 'ALTER TABLE authz.tuples DETACH PARTITION authz.tuples_default';

    -- v_type_id is a integer; %s is safe for the integer partition value.
    -- The table name is %I-quoted (defense-in-depth; the suffix is already
    -- regexp-sanitized to [a-zA-Z0-9_]). See SECURITY-AUDIT F3.
    IF COALESCE(p_hash_modulus, 0) > 0 THEN
        -- Create a sub-partitioned table (HASH on object_id)
        EXECUTE format(
            'CREATE TABLE authz.%I PARTITION OF authz.tuples FOR VALUES IN (%s) PARTITION BY HASH (object_id)',
            v_table_name, v_type_id
        );
        -- Create hash sub-partitions
        FOR i IN 0 .. (p_hash_modulus - 1) LOOP
            EXECUTE format(
                'CREATE TABLE authz.%I PARTITION OF authz.%I FOR VALUES WITH (MODULUS %s, REMAINDER %s)',
                v_table_name || '_' || i, v_table_name, p_hash_modulus, i
            );
        END LOOP;
    ELSE
        -- Simple single partition
        EXECUTE format(
            'CREATE TABLE authz.%I PARTITION OF authz.tuples FOR VALUES IN (%s)',
            v_table_name, v_type_id
        );
    END IF;

    -- Re-attach default partition
    EXECUTE 'ALTER TABLE authz.tuples ATTACH PARTITION authz.tuples_default DEFAULT';

    RETURN true;  -- partition created
END;
$$;

-- (Condition evaluation functions — _exec_condition, _eval_condition_expr,
--  _eval_condition, _condition_missing_keys — moved to conditions.sql)
