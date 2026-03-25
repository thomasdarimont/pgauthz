-- Internal core functions: ID resolution, namespace access, constants,
-- partition management, and condition evaluation.
-- These use integer IDs for performance and are not meant to be called directly.
-- All function names are prefixed with an underscore.
--
-- Depends on: engine/schema.sql (must be loaded first)

------------------------------------------------------------------------
-- ID resolution helpers — used at schema-load time and by public API
-- functions to convert text names to smallint IDs.
------------------------------------------------------------------------

-- Resolve a store name (e.g. 'demo') to its smallint ID.
CREATE OR REPLACE FUNCTION authz._s(p_name text) RETURNS smallint
    LANGUAGE sql STABLE AS $$ SELECT id FROM authz.stores WHERE name = p_name $$;

-- Resolve a type name (e.g. 'document') to its smallint ID within a store.
CREATE OR REPLACE FUNCTION authz._t(p_store_id smallint, p_name text) RETURNS smallint
    LANGUAGE sql STABLE AS $$ SELECT id FROM authz.types WHERE store_id = p_store_id AND name = p_name $$;

-- Convenience overload: resolve type by store name instead of store ID.
CREATE OR REPLACE FUNCTION authz._t(p_store text, p_name text) RETURNS smallint
    LANGUAGE sql STABLE AS $$ SELECT id FROM authz.types WHERE store_id = authz._s(p_store) AND name = p_name $$;

-- Resolve a relation name (e.g. 'can_read') to its smallint ID within a store.
CREATE OR REPLACE FUNCTION authz._r(p_store_id smallint, p_name text) RETURNS smallint
    LANGUAGE sql STABLE AS $$ SELECT id FROM authz.relations WHERE store_id = p_store_id AND name = p_name $$;

-- Convenience overload: resolve relation by store name instead of store ID.
CREATE OR REPLACE FUNCTION authz._r(p_store text, p_name text) RETURNS smallint
    LANGUAGE sql STABLE AS $$ SELECT id FROM authz.relations WHERE store_id = authz._s(p_store) AND name = p_name $$;

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
-- _check_namespace_access: enforces namespace-based access restrictions.
-- Raises an exception if the session user is not authorized to perform
-- the requested operation on tuples for the given object type's namespace.
-- p_permission must be 'can_read' or 'can_write'.
-- Types with namespace = NULL are unrestricted (always allowed).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._check_namespace_access(
    p_store_id    smallint,
    p_object_type smallint,
    p_permission  text DEFAULT 'can_write'
) RETURNS void
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_namespace text;
    v_type_name text;
    v_action    text;
BEGIN
    SELECT namespace, name INTO v_namespace, v_type_name
      FROM authz.types
     WHERE id = p_object_type AND store_id = p_store_id;

    -- NULL namespace = unrestricted
    IF v_namespace IS NULL THEN
        RETURN;
    END IF;

    -- Check if session_user is a member of any granted role with the required permission
    IF EXISTS (
        SELECT 1 FROM authz.namespace_access na
         WHERE na.store_id  = p_store_id
           AND na.namespace = v_namespace
           AND CASE p_permission
                   WHEN 'can_read'  THEN na.can_read
                   WHEN 'can_write' THEN na.can_write
                   ELSE false
               END
           AND pg_has_role(session_user, na.db_role, 'MEMBER')
    ) THEN
        RETURN;
    END IF;

    v_action := CASE p_permission
        WHEN 'can_read'  THEN 'query'
        WHEN 'can_write' THEN 'manage tuples for'
        ELSE p_permission
    END;

    RAISE EXCEPTION 'Permission denied: role "%" cannot % object type "%" in namespace "%"',
        session_user, v_action, v_type_name, v_namespace;
END;
$$;

------------------------------------------------------------------------
-- Rule type constants — used when inserting model rules.
------------------------------------------------------------------------

-- Direct: relation satisfied by a stored tuple linking user to object.
CREATE OR REPLACE FUNCTION authz._rel_direct() RETURNS smallint
    LANGUAGE sql IMMUTABLE AS $$ SELECT 1::smallint $$;

-- Computed: relation is an alias for another relation on the same object.
CREATE OR REPLACE FUNCTION authz._rel_computed() RETURNS smallint
    LANGUAGE sql IMMUTABLE AS $$ SELECT 2::smallint $$;

-- Tuple-to-userset: follow a tupleset relation to a linked object,
-- then check a computed relation there.
CREATE OR REPLACE FUNCTION authz._rel_ttu() RETURNS smallint
    LANGUAGE sql IMMUTABLE AS $$ SELECT 3::smallint $$;

-- Maximum recursion depth for access checks.
CREATE OR REPLACE FUNCTION authz._max_depth() RETURNS int
    LANGUAGE sql IMMUTABLE AS $$ SELECT 15 $$;

------------------------------------------------------------------------
-- Group operator constants — used when inserting model rules with
-- intersection (AND) or exclusion (BUT NOT) semantics.
------------------------------------------------------------------------

-- OR: any rule in the group matching grants access (default).
CREATE OR REPLACE FUNCTION authz._combine_or() RETURNS smallint
    LANGUAGE sql IMMUTABLE AS $$ SELECT 0::smallint $$;

-- Intersection: all rules in the group must match.
CREATE OR REPLACE FUNCTION authz._combine_and() RETURNS smallint
    LANGUAGE sql IMMUTABLE AS $$ SELECT 1::smallint $$;

-- Exclusion: base rules must match AND negated rules must NOT match.
CREATE OR REPLACE FUNCTION authz._combine_exclusion() RETURNS smallint
    LANGUAGE sql IMMUTABLE AS $$ SELECT 2::smallint $$;

------------------------------------------------------------------------
-- _check_type_restriction: validates a single tuple against type
-- restrictions. If no restrictions exist for the (store, object_type,
-- relation), any type is allowed (backward compatible).
-- Raises EXCEPTION on violation.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._check_type_restriction(
    p_store_id      smallint,
    p_object_type   smallint,
    p_relation      smallint,
    p_user_type     smallint,
    p_user_relation smallint,
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
    v_table_name := format('authz.tuples_audit_%s_%s', p_year, lpad(p_month::text, 2, '0'));
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
        'CREATE TABLE %s PARTITION OF authz.tuples_audit FOR VALUES FROM (%L) TO (%L)',
        v_table_name, v_start, v_end
    );

    -- Move rows from the default partition into the new partition
    EXECUTE format(
        'INSERT INTO %s SELECT * FROM authz.tuples_audit_default WHERE performed_at >= %L AND performed_at < %L',
        v_table_name, v_start, v_end
    );
    EXECUTE format(
        'DELETE FROM authz.tuples_audit_default WHERE performed_at >= %L AND performed_at < %L',
        v_start, v_end
    );

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
    p_store_id     smallint,
    p_type_name    text,
    p_hash_modulus int DEFAULT 0
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_type_id    smallint;
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
    v_table_name := 'authz.tuples_' || v_suffix;

    -- Check if a partition for this type already exists
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'authz'
           AND c.relname = 'tuples_' || v_suffix
           AND c.relispartition
    ) THEN
        RETURN false;  -- partition already exists
    END IF;

    -- Detach default partition to allow creating a specific one
    EXECUTE 'ALTER TABLE authz.tuples DETACH PARTITION authz.tuples_default';

    IF COALESCE(p_hash_modulus, 0) > 0 THEN
        -- Create a sub-partitioned table (HASH on object_id)
        EXECUTE format(
            'CREATE TABLE %s PARTITION OF authz.tuples FOR VALUES IN (%s) PARTITION BY HASH (object_id)',
            v_table_name, v_type_id
        );
        -- Create hash sub-partitions
        FOR i IN 0 .. (p_hash_modulus - 1) LOOP
            EXECUTE format(
                'CREATE TABLE %s_%s PARTITION OF %s FOR VALUES WITH (MODULUS %s, REMAINDER %s)',
                v_table_name, i, v_table_name, p_hash_modulus, i
            );
        END LOOP;
    ELSE
        -- Simple single partition
        EXECUTE format(
            'CREATE TABLE %s PARTITION OF authz.tuples FOR VALUES IN (%s)',
            v_table_name, v_type_id
        );
    END IF;

    -- Re-attach default partition
    EXECUTE 'ALTER TABLE authz.tuples ATTACH PARTITION authz.tuples_default DEFAULT';

    RETURN true;  -- partition created
END;
$$;

------------------------------------------------------------------------
-- Online (non-blocking) partition management procedures.
-- Use DETACH PARTITION ... CONCURRENTLY (PG14+) to avoid ACCESS EXCLUSIVE
-- locks. These are PROCEDUREs (not functions) because CONCURRENTLY
-- cannot run inside a transaction block — the procedure uses internal
-- COMMITs to release locks between steps.
--
-- Use these for adding partitions to a live system under load.
-- For initial schema setup (inside init.sh), use the transactional
-- _ensure_tuple_partition / _ensure_audit_partition functions above.
------------------------------------------------------------------------

CREATE OR REPLACE PROCEDURE authz.ensure_tuple_partition_online(
    p_store_id     smallint,
    p_type_name    text,
    p_hash_modulus int DEFAULT 0
)
LANGUAGE plpgsql AS $$
DECLARE
    v_type_id    smallint;
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

    v_suffix     := regexp_replace(v_store_name, '[^a-zA-Z0-9]', '_', 'g')
                 || '_'
                 || regexp_replace(p_type_name, '[^a-zA-Z0-9]', '_', 'g');
    v_table_name := 'authz.tuples_' || v_suffix;

    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'authz'
           AND c.relname = 'tuples_' || v_suffix
           AND c.relispartition
    ) THEN
        RETURN;  -- partition already exists
    END IF;

    -- Detach default concurrently — releases ACCESS EXCLUSIVE immediately
    EXECUTE 'ALTER TABLE authz.tuples DETACH PARTITION authz.tuples_default CONCURRENTLY';
    COMMIT;

    IF COALESCE(p_hash_modulus, 0) > 0 THEN
        EXECUTE format(
            'CREATE TABLE %s PARTITION OF authz.tuples FOR VALUES IN (%s) PARTITION BY HASH (object_id)',
            v_table_name, v_type_id
        );
        FOR i IN 0 .. (p_hash_modulus - 1) LOOP
            EXECUTE format(
                'CREATE TABLE %s_%s PARTITION OF %s FOR VALUES WITH (MODULUS %s, REMAINDER %s)',
                v_table_name, i, v_table_name, p_hash_modulus, i
            );
        END LOOP;
    ELSE
        EXECUTE format(
            'CREATE TABLE %s PARTITION OF authz.tuples FOR VALUES IN (%s)',
            v_table_name, v_type_id
        );
    END IF;
    COMMIT;

    -- Move any existing rows from default into the new partition
    EXECUTE format(
        'INSERT INTO %s SELECT * FROM authz.tuples_default WHERE object_type = %s',
        v_table_name, v_type_id
    );
    EXECUTE format('DELETE FROM authz.tuples_default WHERE object_type = %s', v_type_id);
    COMMIT;

    -- Re-attach default
    EXECUTE 'ALTER TABLE authz.tuples ATTACH PARTITION authz.tuples_default DEFAULT';
    COMMIT;
END;
$$;

CREATE OR REPLACE PROCEDURE authz.ensure_audit_partition_online(
    p_year  int,
    p_month int
)
LANGUAGE plpgsql AS $$
DECLARE
    v_table_name text;
    v_start      date;
    v_end        date;
BEGIN
    v_table_name := format('authz.tuples_audit_%s_%s', p_year, lpad(p_month::text, 2, '0'));
    v_start      := make_date(p_year, p_month, 1);
    v_end        := v_start + interval '1 month';

    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'authz'
           AND c.relname = format('tuples_audit_%s_%s', p_year, lpad(p_month::text, 2, '0'))
           AND c.relispartition
    ) THEN
        RETURN;  -- partition already exists
    END IF;

    EXECUTE 'ALTER TABLE authz.tuples_audit DETACH PARTITION authz.tuples_audit_default CONCURRENTLY';
    COMMIT;

    EXECUTE format(
        'CREATE TABLE %s PARTITION OF authz.tuples_audit FOR VALUES FROM (%L) TO (%L)',
        v_table_name, v_start, v_end
    );
    COMMIT;

    -- Move rows from default into new partition
    EXECUTE format(
        'INSERT INTO %s SELECT * FROM authz.tuples_audit_default WHERE performed_at >= %L AND performed_at < %L',
        v_table_name, v_start, v_end
    );
    EXECUTE format(
        'DELETE FROM authz.tuples_audit_default WHERE performed_at >= %L AND performed_at < %L',
        v_start, v_end
    );
    COMMIT;

    EXECUTE 'ALTER TABLE authz.tuples_audit ATTACH PARTITION authz.tuples_audit_default DEFAULT';
    COMMIT;
END;
$$;

------------------------------------------------------------------------
-- _exec_condition: evaluates a SQL expression as the restricted
-- authz_eval role. SECURITY DEFINER + owned by authz_eval ensures the
-- expression runs with zero table/function access, preventing malicious
-- expressions from reading or modifying data.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._exec_condition(
    p_expr              text,
    p_request_context   jsonb,
    p_condition_context jsonb
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_result boolean;
BEGIN
    EXECUTE format('SELECT (%s)::boolean', p_expr)
    INTO v_result
    USING p_request_context, p_condition_context;

    RETURN COALESCE(v_result, false);
END;
$$;

ALTER FUNCTION authz._exec_condition(text, jsonb, jsonb) OWNER TO authz_eval;

------------------------------------------------------------------------
-- _eval_condition: evaluates a condition expression against context.
-- Returns true if no condition (unconditional tuple) or condition passes.
-- Takes condition_id (PK) so no store scoping needed.
--
-- Security: the expression is evaluated via _exec_condition which runs
-- as authz_eval — a role with zero table/function access. Only pure SQL
-- operators and casts work inside expressions.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._eval_condition(
    p_condition_id      smallint,
    p_condition_context jsonb,      -- stored with the tuple
    p_request_context   jsonb       -- passed at check time
) RETURNS boolean
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_expr   text;
BEGIN
    -- No condition = unconditional access
    IF p_condition_id IS NULL THEN
        RETURN true;
    END IF;

    SELECT expression INTO v_expr FROM authz.conditions WHERE id = p_condition_id;
    IF v_expr IS NULL THEN
        RETURN false;  -- unknown condition = deny
    END IF;

    RETURN authz._exec_condition(
        v_expr,
        COALESCE(p_request_context, '{}'::jsonb),
        COALESCE(p_condition_context, '{}'::jsonb)
    );
EXCEPTION
    WHEN OTHERS THEN
        RETURN false;  -- condition evaluation error = deny
END;
$$;
