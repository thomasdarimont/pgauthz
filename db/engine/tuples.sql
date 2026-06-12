-- Public tuple management API: write, delete, and batch operations.
-- All functions accept text parameters and resolve IDs internally.
--
-- Depends on: engine/core_internal.sql

------------------------------------------------------------------------
-- write_tuple: explicit parameters — no string parsing needed.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.write_tuple(
    p_store             text,
    p_user_type         text,
    p_user_id           text,
    p_relation          text,
    p_object_type       text,
    p_object_id         text,
    p_user_relation     text DEFAULT NULL,
    p_condition         text DEFAULT NULL,
    p_condition_context jsonb DEFAULT NULL,
    p_performed_by      text DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id      smallint := authz._s(p_store);
    v_user_type     smallint := authz._t(v_store_id, p_user_type);
    v_relation      smallint := authz._r(v_store_id, p_relation);
    v_object_type   smallint := authz._t(v_store_id, p_object_type);
    v_user_relation smallint;
    v_condition_id  smallint;
BEGIN
    -- Set application user for the audit trigger (transaction-local)
    -- The true in set_config(..., true) makes the variable transaction-local, so it auto-resets after each call — no risk of leaking between requests.
    PERFORM set_config('authz.performed_by', COALESCE(p_performed_by, ''), true);

    -- Enforce namespace-based write restrictions
    PERFORM authz._check_namespace_access(v_store_id, v_object_type);

    IF p_user_relation IS NOT NULL THEN
        v_user_relation := authz._r(v_store_id, p_user_relation);
    END IF;

    -- Wildcard tuples cannot have a user_relation (usersets on * are not meaningful)
    IF p_user_id = '*' AND v_user_relation IS NOT NULL THEN
        RAISE EXCEPTION 'Wildcard user_id (*) cannot be combined with a user_relation';
    END IF;

    -- Validate type restrictions (if any are defined for this relation)
    PERFORM authz._check_type_restriction(
        v_store_id, v_object_type, v_relation,
        v_user_type, v_user_relation, p_user_id
    );

    -- Resolve condition (if any) and validate stored context keys
    IF p_condition IS NOT NULL THEN
        DECLARE
            v_required jsonb;
            v_missing  text[];
            v_key      text;
        BEGIN
            SELECT id, required_context
              INTO STRICT v_condition_id, v_required
              FROM authz.conditions WHERE store_id = v_store_id AND name = p_condition;

            -- Validate required stored context keys
            IF v_required IS NOT NULL AND v_required ? 'stored' THEN
                FOR v_key IN SELECT jsonb_array_elements_text(v_required->'stored') LOOP
                    IF p_condition_context IS NULL OR NOT (p_condition_context ? v_key) THEN
                        v_missing := array_append(v_missing, v_key);
                    END IF;
                END LOOP;

                IF v_missing IS NOT NULL THEN
                    RAISE EXCEPTION 'Condition "%" requires stored context keys [%], but got: %',
                        p_condition, array_to_string(v_missing, ', '),
                        COALESCE(p_condition_context::text, 'NULL');
                END IF;
            END IF;
        END;
    END IF;

    INSERT INTO authz.tuples (store_id, user_type, user_id, user_relation, relation, object_type, object_id, condition_id, condition_context)
    VALUES (v_store_id, v_user_type, p_user_id, v_user_relation, v_relation, v_object_type, p_object_id, v_condition_id, p_condition_context)
    ON CONFLICT DO NOTHING;

    RETURN FOUND;
END;
$$;

------------------------------------------------------------------------
-- write_tuples: batch insert using a single INSERT ... SELECT.
-- Much more efficient than calling write_tuple in a loop — one statement,
-- one set of audit trigger events, and ID resolution via joins.
--
-- Returns the number of tuples actually inserted (duplicates are skipped).
--
-- Examples:
--   SELECT authz.write_tuples('demo', ARRAY[
--       ('internal_user','alice',NULL,'viewer','document','doc1'),
--       ('internal_user','bob',  NULL,'editor','document','doc1')
--   ]::authz.tuple_input[]);
--
--   -- With application user tracking:
--   SELECT authz.write_tuples('demo', ARRAY[
--       ('team','engineering','member','viewer','document','doc1')
--   ]::authz.tuple_input[], p_performed_by => 'admin');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.write_tuples(
    p_store        text,
    p_tuples       authz.tuple_input[],
    p_performed_by text DEFAULT NULL
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id smallint := authz._s(p_store);
    v_count    integer;
    v_bad      text;
BEGIN
    -- Set application user for the audit trigger (transaction-local)
    PERFORM set_config('authz.performed_by', COALESCE(p_performed_by, ''), true);

    -- Validate all type and relation names resolve (fail-fast like write_tuple)
    SELECT string_agg(DISTINCT 'user_type=' || t.user_type, ', ')
      INTO v_bad
      FROM unnest(p_tuples) AS t
      LEFT JOIN authz.types ut ON ut.store_id = v_store_id AND ut.name = t.user_type
     WHERE ut.id IS NULL;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'Unknown type(s) in store "%": %', p_store, v_bad;
    END IF;

    SELECT string_agg(DISTINCT 'object_type=' || t.object_type, ', ')
      INTO v_bad
      FROM unnest(p_tuples) AS t
      LEFT JOIN authz.types ot ON ot.store_id = v_store_id AND ot.name = t.object_type
     WHERE ot.id IS NULL;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'Unknown type(s) in store "%": %', p_store, v_bad;
    END IF;

    SELECT string_agg(DISTINCT 'relation=' || t.relation, ', ')
      INTO v_bad
      FROM unnest(p_tuples) AS t
      LEFT JOIN authz.relations r ON r.store_id = v_store_id AND r.name = t.relation
     WHERE r.id IS NULL;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'Unknown relation(s) in store "%": %', p_store, v_bad;
    END IF;

    SELECT string_agg(DISTINCT 'user_relation=' || t.user_relation, ', ')
      INTO v_bad
      FROM unnest(p_tuples) AS t
      LEFT JOIN authz.relations ur ON ur.store_id = v_store_id AND ur.name = t.user_relation
     WHERE t.user_relation IS NOT NULL AND ur.id IS NULL;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'Unknown relation(s) in store "%": %', p_store, v_bad;
    END IF;

    -- Enforce namespace-based write restrictions for all object types in the batch
    PERFORM authz._check_namespace_access(v_store_id, ot.id)
       FROM (SELECT DISTINCT t.object_type FROM unnest(p_tuples) AS t) AS t
       JOIN authz.types ot ON ot.store_id = v_store_id AND ot.name = t.object_type;

    -- Validate type restrictions for all tuples in the batch
    v_bad := NULL;
    SELECT string_agg(DISTINCT format('%s%s -> %s on %s',
               t.user_type,
               CASE WHEN t.user_id = '*' THEN ':*'
                    WHEN t.user_relation IS NOT NULL THEN '#' || t.user_relation
                    ELSE '' END,
               t.relation, t.object_type), ', ')
      INTO v_bad
      FROM unnest(p_tuples) AS t
      JOIN authz.types ut     ON ut.store_id = v_store_id AND ut.name = t.user_type
      JOIN authz.relations r  ON r.store_id  = v_store_id AND r.name  = t.relation
      JOIN authz.types ot     ON ot.store_id = v_store_id AND ot.name = t.object_type
      LEFT JOIN authz.relations ur ON ur.store_id = v_store_id AND ur.name = t.user_relation
     WHERE EXISTS (
               SELECT 1 FROM authz.type_restrictions tr
                WHERE tr.store_id = v_store_id AND tr.object_type = ot.id AND tr.relation = r.id
           )
       AND NOT EXISTS (
               SELECT 1 FROM authz.type_restrictions tr
                WHERE tr.store_id = v_store_id
                  AND tr.object_type = ot.id
                  AND tr.relation = r.id
                  AND tr.allowed_user_type = ut.id
                  AND CASE
                          WHEN t.user_id = '*' THEN tr.allow_wildcard = true
                          WHEN t.user_relation IS NOT NULL THEN tr.allowed_user_relation = ur.id
                          ELSE tr.allowed_user_relation IS NULL AND tr.allow_wildcard = false
                      END
           );
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'Type restriction violation(s): %', v_bad;
    END IF;

    INSERT INTO authz.tuples (store_id, user_type, user_id, user_relation, relation, object_type, object_id)
    SELECT v_store_id,
           ut.id,
           t.user_id,
           ur.id,
           r.id,
           ot.id,
           t.object_id
      FROM unnest(p_tuples) AS t
      JOIN authz.types ut     ON ut.store_id = v_store_id AND ut.name = t.user_type
      JOIN authz.relations r  ON r.store_id  = v_store_id AND r.name  = t.relation
      JOIN authz.types ot     ON ot.store_id = v_store_id AND ot.name = t.object_type
      LEFT JOIN authz.relations ur ON ur.store_id = v_store_id AND ur.name = t.user_relation
    ON CONFLICT DO NOTHING;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

------------------------------------------------------------------------
-- write_tuples_jsonb: HTTP/JSON-friendly version of write_tuples.
-- Accepts tuples as a JSONB array of objects, each with:
--   {"user_type", "user_id", "relation", "object_type", "object_id"}
--   and optionally "user_relation" (for userset tuples) and
--   "condition" / "condition_context" (for conditional grants).
--
-- Note: the composite authz.tuple_input type used by write_tuples has
-- no condition fields — use this JSONB variant (or write_tuple) for
-- conditional grants.
--
-- Example via PostgREST:
--   POST /rpc/write_tuples_jsonb
--   {"p_store": "demo", "p_tuples": [
--       {"user_type":"internal_user","user_id":"alice","relation":"member","object_type":"team","object_id":"payroll_team"},
--       {"user_type":"internal_user","user_id":"bob","relation":"viewer","object_type":"document","object_id":"doc_temp_001",
--        "condition":"non_expired_grant",
--        "condition_context":{"grant_time":"2026-03-11T09:00:00Z","grant_duration":"2 hours"}}
--   ], "p_performed_by": "hr_system"}
--   => 2
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.write_tuples_jsonb(
    p_store        text,
    p_tuples       jsonb,
    p_performed_by text DEFAULT NULL
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_count integer;
    t       jsonb;
BEGIN
    PERFORM authz._validate_tuple_jsonb(p_tuples);

    -- Unconditional elements take the set-based batch path.
    v_count := authz.write_tuples(
        p_store,
        (SELECT coalesce(array_agg(ROW(
            e->>'user_type',
            e->>'user_id',
            e->>'user_relation',
            e->>'relation',
            e->>'object_type',
            e->>'object_id'
        )::authz.tuple_input), '{}')
        FROM jsonb_array_elements(p_tuples) AS e
        WHERE e->>'condition' IS NULL),
        p_performed_by
    );

    -- Conditional elements go through write_tuple, which validates the
    -- condition name and its required stored-context keys.
    FOR t IN
        SELECT e FROM jsonb_array_elements(p_tuples) AS e
         WHERE e->>'condition' IS NOT NULL
    LOOP
        IF authz.write_tuple(p_store,
               t->>'user_type', t->>'user_id', t->>'relation',
               t->>'object_type', t->>'object_id',
               p_user_relation     => t->>'user_relation',
               p_condition         => t->>'condition',
               p_condition_context => t->'condition_context',
               p_performed_by      => p_performed_by) THEN
            v_count := v_count + 1;
        END IF;
    END LOOP;

    RETURN v_count;
END;
$$;

------------------------------------------------------------------------
-- delete_tuple: explicit parameters — mirrors write_tuple.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.delete_tuple(
    p_store         text,
    p_user_type     text,
    p_user_id       text,
    p_relation      text,
    p_object_type   text,
    p_object_id     text,
    p_user_relation text DEFAULT NULL,
    p_performed_by  text DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id      smallint := authz._s(p_store);
    v_user_type     smallint := authz._t(v_store_id, p_user_type);
    v_relation      smallint := authz._r(v_store_id, p_relation);
    v_object_type   smallint := authz._t(v_store_id, p_object_type);
    v_user_relation smallint;
BEGIN
    -- Set application user for the audit trigger (transaction-local)
    PERFORM set_config('authz.performed_by', COALESCE(p_performed_by, ''), true);

    -- Enforce namespace-based write restrictions
    PERFORM authz._check_namespace_access(v_store_id, v_object_type);

    IF p_user_relation IS NOT NULL THEN
        v_user_relation := authz._r(v_store_id, p_user_relation);
    END IF;

    DELETE FROM authz.tuples
     WHERE store_id      = v_store_id
       AND object_type   = v_object_type
       AND object_id     = p_object_id
       AND relation      = v_relation
       AND user_type     = v_user_type
       AND user_id       = p_user_id
       AND user_relation IS NOT DISTINCT FROM v_user_relation;

    RETURN FOUND;
END;
$$;


------------------------------------------------------------------------
-- delete_tuples: batch delete using a single DELETE ... USING.
-- Returns the number of tuples actually deleted.
--
-- Example:
--   SELECT authz.delete_tuples('demo', ARRAY[
--       ('internal_user','alice',NULL,'viewer','document','doc1'),
--       ('internal_user','bob',  NULL,'editor','document','doc1')
--   ]::authz.tuple_input[]);
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.delete_tuples(
    p_store        text,
    p_tuples       authz.tuple_input[],
    p_performed_by text DEFAULT NULL
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id smallint := authz._s(p_store);
    v_count    integer;
    v_bad      text;
BEGIN
    -- Set application user for the audit trigger (transaction-local)
    PERFORM set_config('authz.performed_by', COALESCE(p_performed_by, ''), true);

    -- Validate all type and relation names resolve (fail-fast like delete_tuple)
    SELECT string_agg(DISTINCT 'user_type=' || t.user_type, ', ')
      INTO v_bad
      FROM unnest(p_tuples) AS t
      LEFT JOIN authz.types ut ON ut.store_id = v_store_id AND ut.name = t.user_type
     WHERE ut.id IS NULL;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'Unknown type(s) in store "%": %', p_store, v_bad;
    END IF;

    SELECT string_agg(DISTINCT 'object_type=' || t.object_type, ', ')
      INTO v_bad
      FROM unnest(p_tuples) AS t
      LEFT JOIN authz.types ot ON ot.store_id = v_store_id AND ot.name = t.object_type
     WHERE ot.id IS NULL;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'Unknown type(s) in store "%": %', p_store, v_bad;
    END IF;

    SELECT string_agg(DISTINCT 'relation=' || t.relation, ', ')
      INTO v_bad
      FROM unnest(p_tuples) AS t
      LEFT JOIN authz.relations r ON r.store_id = v_store_id AND r.name = t.relation
     WHERE r.id IS NULL;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'Unknown relation(s) in store "%": %', p_store, v_bad;
    END IF;

    SELECT string_agg(DISTINCT 'user_relation=' || t.user_relation, ', ')
      INTO v_bad
      FROM unnest(p_tuples) AS t
      LEFT JOIN authz.relations ur ON ur.store_id = v_store_id AND ur.name = t.user_relation
     WHERE t.user_relation IS NOT NULL AND ur.id IS NULL;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'Unknown relation(s) in store "%": %', p_store, v_bad;
    END IF;

    -- Enforce namespace-based write restrictions for all object types in the batch
    PERFORM authz._check_namespace_access(v_store_id, ot.id)
       FROM (SELECT DISTINCT t.object_type FROM unnest(p_tuples) AS t) AS t
       JOIN authz.types ot ON ot.store_id = v_store_id AND ot.name = t.object_type;

    DELETE FROM authz.tuples tup
     USING (
        SELECT ut.id AS user_type,
               t.user_id,
               ur.id AS user_relation,
               r.id  AS relation,
               ot.id AS object_type,
               t.object_id
          FROM unnest(p_tuples) AS t
          JOIN authz.types ut     ON ut.store_id = v_store_id AND ut.name = t.user_type
          JOIN authz.relations r  ON r.store_id  = v_store_id AND r.name  = t.relation
          JOIN authz.types ot     ON ot.store_id = v_store_id AND ot.name = t.object_type
          LEFT JOIN authz.relations ur ON ur.store_id = v_store_id AND ur.name = t.user_relation
     ) AS d
     WHERE tup.store_id      = v_store_id
       AND tup.user_type     = d.user_type
       AND tup.user_id       = d.user_id
       AND tup.user_relation IS NOT DISTINCT FROM d.user_relation
       AND tup.relation      = d.relation
       AND tup.object_type   = d.object_type
       AND tup.object_id     = d.object_id;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

------------------------------------------------------------------------
-- delete_tuples_jsonb: HTTP/JSON-friendly version of delete_tuples.
-- Accepts tuples as a JSONB array of objects, each with:
--   {"user_type", "user_id", "relation", "object_type", "object_id"}
--   and optionally "user_relation" (for userset tuples).
-- Delegates to the native array version after conversion.
--
-- Example via PostgREST:
--   POST /rpc/delete_tuples_jsonb
--   {"p_store": "demo", "p_tuples": [
--       {"user_type":"internal_user","user_id":"alice","relation":"member","object_type":"team","object_id":"payroll_team"},
--       {"user_type":"internal_user","user_id":"bob","relation":"member","object_type":"team","object_id":"accounting_team"}
--   ], "p_performed_by": "hr_system"}
--   => 2
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.delete_tuples_jsonb(
    p_store        text,
    p_tuples       jsonb,
    p_performed_by text DEFAULT NULL
) RETURNS integer
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM authz._validate_tuple_jsonb(p_tuples);
    RETURN authz.delete_tuples(
        p_store,
        (SELECT coalesce(array_agg(ROW(
            t->>'user_type',
            t->>'user_id',
            t->>'user_relation',
            t->>'relation',
            t->>'object_type',
            t->>'object_id'
        )::authz.tuple_input), '{}')
        FROM jsonb_array_elements(p_tuples) AS t),
        p_performed_by
    );
END;
$$;

------------------------------------------------------------------------
-- delete_user_tuples: remove all tuples for a specific user.
-- Revokes all permissions the user has in the given store.
-- Returns the number of tuples deleted.
--
-- Examples:
--   -- Remove all access for alice:
--   SELECT authz.delete_user_tuples('demo', 'internal_user', 'alice');
--
--   -- Remove all access for alice, with audit tracking:
--   SELECT authz.delete_user_tuples('demo', 'internal_user', 'alice',
--       p_performed_by => 'admin');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.delete_user_tuples(
    p_store        text,
    p_user_type    text,
    p_user_id      text,
    p_performed_by text DEFAULT NULL
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id  smallint := authz._s(p_store);
    v_user_type smallint := authz._t(v_store_id, p_user_type);
    v_count     integer;
BEGIN
    PERFORM set_config('authz.performed_by', COALESCE(p_performed_by, ''), true);

    -- Enforce namespace-based write restrictions for all object types the user has tuples in
    PERFORM authz._check_namespace_access(v_store_id, t.object_type)
       FROM (SELECT DISTINCT object_type FROM authz.tuples
              WHERE store_id = v_store_id AND user_type = v_user_type AND user_id = p_user_id) t;

    DELETE FROM authz.tuples
     WHERE store_id  = v_store_id
       AND user_type = v_user_type
       AND user_id   = p_user_id;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;
