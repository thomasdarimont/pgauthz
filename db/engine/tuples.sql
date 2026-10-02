-- Public tuple management API: write, delete, and batch operations.
-- All functions accept text parameters and resolve IDs internally.
--
-- Depends on: engine/core_internal.sql

------------------------------------------------------------------------
-- write_tuple: explicit parameters — no string parsing needed.
--
-- Upsert semantics: if the tuple already exists with a DIFFERENT
-- condition (or condition context), the new condition is applied —
-- the caller's intent wins, and the change is audited as a
-- DELETE(old) + INSERT(new) event pair. Returns true if the tuple was
-- created or its condition changed, false if an identical tuple
-- already existed.
------------------------------------------------------------------------
-- Drop the pre-expiry signature so adding the trailing param doesn't leave a
-- second (10-arg) overload behind on upgraded installs.
DROP FUNCTION IF EXISTS authz.write_tuple(text, text, text, text, text, text, text, text, jsonb, text);

------------------------------------------------------------------------
-- RLS-bypass helpers (SECURITY-AUDIT F11 / migrations 0005-0006).
--
-- The tuple-expiry SELECT policy hides expired rows from EVERY read, including
-- the ON CONFLICT read inside an upsert and the row scan inside a cleanup
-- DELETE. These two operations must see expired rows (to reactivate a re-grant
-- and to garbage-collect). They are the ONLY paths that need to; the escape is
-- therefore a dedicated BYPASSRLS role that OWNS these helpers — roles.sql
-- makes them SECURITY DEFINER owned by authz_rls_bypass, so they run with
-- BYPASSRLS while the caller (a definer function owned by authz_owner) does
-- not. EXECUTE is granted only to authz_owner: app roles cannot call them
-- directly, so they never sidestep the namespace/type checks the public
-- write functions perform first. Plain SET ROLE cannot achieve this — Postgres
-- forbids setting `role` inside a SECURITY DEFINER function.
--
-- Targeted deletes (delete_tuple/tuples/user) deliberately do NOT bypass: an
-- already-expired row they cannot reach grants nothing and is reclaimed by
-- cleanup_expired_tuples — leaving it is harmless, so they stay minimal.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._rls_upsert_tuple(
    p_store_id int, p_user_type int, p_user_id text, p_user_relation int,
    p_relation int, p_object_type int, p_object_id text,
    p_condition_id int, p_condition_context jsonb, p_expires_at timestamptz
) RETURNS boolean
LANGUAGE plpgsql AS $$
BEGIN
    -- Runs as authz_rls_bypass (BYPASSRLS): the ON CONFLICT read of an EXPIRED
    -- conflicting row succeeds, so a re-grant reactivates it.
    INSERT INTO authz.tuples (store_id, user_type, user_id, user_relation, relation, object_type, object_id, condition_id, condition_context, expires_at)
    VALUES (p_store_id, p_user_type, p_user_id, p_user_relation, p_relation, p_object_type, p_object_id, p_condition_id, p_condition_context, p_expires_at)
    ON CONFLICT (store_id, object_type, object_id, relation, user_type, user_id, COALESCE(user_relation::int, 0))
    DO UPDATE SET
        condition_id      = EXCLUDED.condition_id,
        condition_context = EXCLUDED.condition_context,
        expires_at        = EXCLUDED.expires_at
    WHERE tuples.condition_id      IS DISTINCT FROM EXCLUDED.condition_id
       OR tuples.condition_context IS DISTINCT FROM EXCLUDED.condition_context
       OR tuples.expires_at        IS DISTINCT FROM EXCLUDED.expires_at;
    RETURN FOUND;  -- inserted or condition/expiry changed; false for an identical live tuple
END;
$$;

CREATE OR REPLACE FUNCTION authz._rls_write_tuples(
    p_store_id int, p_tuples authz.tuple_input[]
) RETURNS int
LANGUAGE plpgsql AS $$
DECLARE
    v_count int;
BEGIN
    -- Set-based batch insert; the tuple_input type has no expiry field, so a
    -- batch re-grant over an EXPIRING/EXPIRED row makes it permanent (see
    -- write_tuples). Runs as authz_rls_bypass so the ON CONFLICT reactivation
    -- can see hidden rows. Name resolution needs SELECT on types/relations
    -- (granted to the bypass role in roles.sql).
    INSERT INTO authz.tuples (store_id, user_type, user_id, user_relation, relation, object_type, object_id)
    SELECT p_store_id, ut.id, t.user_id, ur.id, r.id, ot.id, t.object_id
      FROM unnest(p_tuples) AS t
      JOIN authz.types ut     ON ut.store_id = p_store_id AND ut.name = t.user_type
      JOIN authz.relations r  ON r.store_id  = p_store_id AND r.name  = t.relation
      JOIN authz.types ot     ON ot.store_id = p_store_id AND ot.name = t.object_type
      LEFT JOIN authz.relations ur ON ur.store_id = p_store_id AND ur.name = t.user_relation
    ON CONFLICT (store_id, object_type, object_id, relation, user_type, user_id, COALESCE(user_relation::int, 0))
    DO UPDATE SET expires_at = NULL
    WHERE tuples.expires_at IS NOT NULL;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

CREATE OR REPLACE FUNCTION authz._rls_delete_expired(
    p_store_id int, p_grace interval
) RETURNS int
LANGUAGE plpgsql AS $$
DECLARE
    v_count int;
BEGIN
    -- Runs as authz_rls_bypass so the WHERE (which reads expires_at) can see
    -- the expired rows it deletes. Audited via the ordinary trigger.
    DELETE FROM authz.tuples t
     WHERE t.expires_at IS NOT NULL
       AND t.expires_at <= now() - p_grace
       AND (p_store_id IS NULL OR t.store_id = p_store_id);
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

CREATE OR REPLACE FUNCTION authz._rls_delete_store_tuples(
    p_store_id int
) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    -- Purge ALL of a store's tuples incl. expired ones (delete_store; the
    -- store row's FK requires no tuples remain). Runs as authz_rls_bypass.
    DELETE FROM authz.tuples WHERE store_id = p_store_id;
END;
$$;

CREATE OR REPLACE FUNCTION authz._rls_delete_type_tuples(
    p_store_id int,
    p_type_id  int
) RETURNS int
LANGUAGE plpgsql AS $$
DECLARE
    v_count int;
BEGIN
    -- Purge every tuple that names the type on EITHER side, incl. expired
    -- rows (model_remove_type with p_force). The object side lives in the
    -- type's own partition, the subject side in other types' partitions.
    -- Runs as authz_rls_bypass; the audit trigger logs each row.
    DELETE FROM authz.tuples
     WHERE store_id = p_store_id
       AND (object_type = p_type_id OR user_type = p_type_id);
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

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
    p_performed_by      text DEFAULT NULL,
    p_expires_at        timestamptz DEFAULT NULL  -- server-time expiry; NULL = never
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id      integer := authz._s(p_store);
    v_user_type     integer := authz._t(v_store_id, p_user_type);
    v_relation      integer := authz._r(v_store_id, p_relation);
    v_object_type   integer := authz._t(v_store_id, p_object_type);
    v_user_relation integer;
    v_condition_id  integer;
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

    -- A grant that is already expired is dead on arrival — almost certainly a
    -- caller bug (clock skew, stale payload). Reject it clearly instead of
    -- storing a row that can never grant. (RLS would reject it anyway via the
    -- ON CONFLICT SELECT-policy check, but with an opaque error.)
    IF p_expires_at IS NOT NULL AND p_expires_at <= now() THEN
        RAISE EXCEPTION 'expires_at (%) is in the past — the grant would never take effect', p_expires_at
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Object wildcards are privileged: one tuple grants the relation on
    -- EVERY object of the type. Default-deny — the direct model rule
    -- must be explicitly marked.
    IF p_object_id = '*' AND NOT EXISTS (
        SELECT 1 FROM authz.models m
         WHERE m.store_id    = v_store_id
           AND m.object_type = v_object_type
           AND m.relation    = v_relation
           AND m.rule_type   = authz._rel_direct()
           AND m.allow_object_wildcard
    ) THEN
        RAISE EXCEPTION 'object wildcard (object_id = ''*'') is not allowed for relation "%" on type "%" — mark the direct model rule with allow_object_wildcard',
            p_relation, p_object_type;
    END IF;

    -- Resolve condition (if any) and validate stored context keys
    IF p_condition IS NOT NULL THEN
        DECLARE
            v_required jsonb;
            v_missing  text[];
            v_key      text;
        BEGIN
            SELECT id, required_context
              INTO v_condition_id, v_required
              FROM authz.conditions WHERE store_id = v_store_id AND name = p_condition;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'Unknown condition "%" in store "%"', p_condition, p_store
                    USING HINT = 'Define it in authz.conditions, or omit p_condition';
            END IF;

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

    -- Validate type restrictions (if any are defined for this relation) —
    -- after the condition is resolved, because a facet may REQUIRE one
    -- (migration 0015: `[user:* with cond]`).
    PERFORM authz._check_type_restriction(
        v_store_id, v_object_type, v_relation,
        v_user_type, v_user_relation, p_user_id, v_condition_id
    );

    -- The upsert must SEE an expired row to reactivate a re-grant, which the
    -- RLS SELECT policy hides; the bypass helper (owned by a BYPASSRLS role)
    -- does it. Namespace/type checks above already ran as the effective role.
    RETURN authz._rls_upsert_tuple(v_store_id, v_user_type, p_user_id, v_user_relation,
                                   v_relation, v_object_type, p_object_id,
                                   v_condition_id, p_condition_context, p_expires_at);
END;
$$;

------------------------------------------------------------------------
-- write_tuples: batch insert using a single INSERT ... SELECT.
-- Much more efficient than calling write_tuple in a loop — one statement,
-- one set of audit trigger events, and ID resolution via joins.
--
-- Returns the number of tuples actually inserted (duplicates are skipped).
--
-- Unlike write_tuple, the batch path is strictly insert-only: existing
-- tuples are never modified, so a bulk sync cannot accidentally strip
-- conditions from existing conditional grants.
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
    v_store_id integer := authz._s(p_store);
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

    -- Wildcard users cannot carry a user_relation — usersets on '*' are not
    -- meaningful. Mirror the single write_tuple guard for the batch path.
    SELECT string_agg(DISTINCT format('%s:* #%s', t.user_type, t.user_relation), ', ')
      INTO v_bad
      FROM unnest(p_tuples) AS t
     WHERE t.user_id = '*' AND t.user_relation IS NOT NULL;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'Wildcard user_id (*) cannot be combined with a user_relation: %', v_bad;
    END IF;

    -- Object wildcards are privileged (see write_tuple): reject batch
    -- elements targeting object_id = '*' unless the direct rule allows it.
    SELECT string_agg(DISTINCT format('%s on %s', t.relation, t.object_type), ', ')
      INTO v_bad
      FROM unnest(p_tuples) AS t
      JOIN authz.types ot    ON ot.store_id = v_store_id AND ot.name = t.object_type
      JOIN authz.relations r ON r.store_id  = v_store_id AND r.name  = t.relation
     WHERE t.object_id = '*'
       AND NOT EXISTS (
           SELECT 1 FROM authz.models m
            WHERE m.store_id    = v_store_id
              AND m.object_type = ot.id
              AND m.relation    = r.id
              AND m.rule_type   = authz._rel_direct()
              AND m.allow_object_wildcard
       );
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'object wildcard (object_id = ''*'') is not allowed for: % — mark the direct model rule with allow_object_wildcard', v_bad;
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
                  -- tuple_input carries no condition: only an OPEN facet matches
                  -- (a facet that requires a condition needs write_tuple /
                  -- write_tuples_jsonb with p_condition — migration 0015).
                  AND tr.condition_id IS NULL
           );
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'Type restriction violation(s): %', v_bad
            USING HINT = 'A facet may require a condition: write those tuples with a condition (write_tuple / write_tuples_jsonb).';
    END IF;

    -- The set-based insert (with ON CONFLICT reactivation of expired rows)
    -- must see hidden rows: the bypass helper owns that statement. All
    -- validation above ran as the effective role.
    v_count := authz._rls_write_tuples(v_store_id, p_tuples);
    RETURN v_count;
END;
$$;

------------------------------------------------------------------------
-- write_tuples_jsonb: HTTP/JSON-friendly version of write_tuples.
-- Accepts tuples as a JSONB array of objects, each with:
--   {"user_type", "user_id", "relation", "object_type", "object_id"}
--   and optionally "user_relation" (for userset tuples),
--   "condition" / "condition_context" (for conditional grants), and
--   "expires_at" (server-time expiry, e.g. "2026-08-01T00:00:00Z").
--
-- Note: the composite authz.tuple_input type used by write_tuples has
-- no condition or expiry fields — use this JSONB variant (or write_tuple)
-- for conditional or expiring grants.
--
-- Example via pgauthzd (native `/pgauthz/v1`):
--   POST /pgauthz/v1/write
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

    -- Plain elements take the set-based batch path.
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
        WHERE e->>'condition' IS NULL AND e->>'expires_at' IS NULL),
        p_performed_by
    );

    -- Conditional / expiring elements go through write_tuple, which validates
    -- the condition name, its required stored-context keys, and the expiry.
    FOR t IN
        SELECT e FROM jsonb_array_elements(p_tuples) AS e
         WHERE e->>'condition' IS NOT NULL OR e->>'expires_at' IS NOT NULL
    LOOP
        IF authz.write_tuple(p_store,
               t->>'user_type', t->>'user_id', t->>'relation',
               t->>'object_type', t->>'object_id',
               p_user_relation     => t->>'user_relation',
               p_condition         => t->>'condition',
               p_condition_context => t->'condition_context',
               p_performed_by      => p_performed_by,
               p_expires_at        => (t->>'expires_at')::timestamptz) THEN
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
    v_store_id      integer := authz._s(p_store);
    v_user_type     integer := authz._t(v_store_id, p_user_type);
    v_relation      integer := authz._r(v_store_id, p_relation);
    v_object_type   integer := authz._t(v_store_id, p_object_type);
    v_user_relation integer;
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
    v_store_id integer := authz._s(p_store);
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
-- Example via pgauthzd (native `/pgauthz/v1`):
--   POST /pgauthz/v1/delete
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
    v_store_id  integer := authz._s(p_store);
    v_user_type integer := authz._t(v_store_id, p_user_type);
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

------------------------------------------------------------------------
-- _precondition_matches: does any tuple match a (partial) precondition
-- filter? Only the fields present in the JSON constrain the match, so
-- {object_type, object_id, relation} (no user) means "any tuple with that
-- relation on that object". Used by write_tuples_checked.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._precondition_matches(p_store_id integer, p_pc jsonb)
RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM authz.tuples t
         WHERE t.store_id = p_store_id
           AND (p_pc->>'object_type'   IS NULL OR t.object_type   = authz._t(p_store_id, p_pc->>'object_type'))
           AND (p_pc->>'object_id'     IS NULL OR t.object_id     = p_pc->>'object_id')
           AND (p_pc->>'relation'      IS NULL OR t.relation      = authz._r(p_store_id, p_pc->>'relation'))
           AND (p_pc->>'user_type'     IS NULL OR t.user_type     = authz._t(p_store_id, p_pc->>'user_type'))
           AND (p_pc->>'user_id'       IS NULL OR t.user_id       = p_pc->>'user_id')
           AND (p_pc->>'user_relation' IS NULL OR t.user_relation = authz._r(p_store_id, p_pc->>'user_relation'))
    );
$$;

------------------------------------------------------------------------
-- write_tuples_checked: conditional, atomic writes (optimistic concurrency).
--
-- Checks each precondition, then applies the deletes and writes — all in ONE
-- transaction. Any failed precondition aborts everything (nothing is written).
-- This is the only way to do a race-free "write X only if state Y holds" over
-- the API (each plain-write RPC is its own transaction).
--
--   p_preconditions: [{ "match": "exists" | "absent", <partial tuple filter> }
--                     | { "match": "allowed" | "denied", user_type, user_id,
--                         relation, object_type, object_id, context? }]
--     exists/absent match STORED tuples (only the fields present constrain).
--     allowed/denied run a full access check — graph, conditions with the
--     given request context, temporal gates — exactly as
--     check_access_with_context would decide it, inside this transaction and
--     under the same locks. "Write this grant only if the granter may X":
--     delegation attenuated at issuance, share-on-behalf, approvals.
--   p_deletes / p_writes: tuple arrays, same element shape as *_tuples_jsonb
--                         (applied deletes-first, then writes).
--   returns: {"written": n, "deleted": m}
--
-- Concurrency: a transaction-scoped advisory lock is taken on every object
-- referenced (sorted, so no deadlock) before the checks run. Concurrent
-- checked-writes on the same object therefore serialize, and because the lock
-- is only acquired after a conflicting transaction commits, the precondition
-- re-reads its committed effect — giving compare-and-swap semantics for both
-- "exists" and "absent". NOTE: this protects checked-writes against each other;
-- a hard invariant requires ALL mutators of those tuples to go through this
-- function (or a DB constraint).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.write_tuples_checked(
    p_store         text,
    p_preconditions jsonb DEFAULT '[]'::jsonb,
    p_deletes       jsonb DEFAULT '[]'::jsonb,
    p_writes        jsonb DEFAULT '[]'::jsonb,
    p_performed_by  text  DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_obj      record;
    v_pc       jsonb;
    v_match    text;
    v_found    boolean;
    v_written  integer := 0;
    v_deleted  integer := 0;
BEGIN
    -- Lock every referenced object, in a stable order (deadlock-free), so
    -- concurrent checked-writes on the same object serialize.
    FOR v_obj IN
        SELECT DISTINCT e->>'object_type' AS ot, e->>'object_id' AS oid
          FROM jsonb_array_elements(p_preconditions || p_deletes || p_writes) AS e
         WHERE e ? 'object_id'
         ORDER BY 1, 2
    LOOP
        PERFORM pg_advisory_xact_lock(
            hashtextextended(p_store || ':' || v_obj.ot || ':' || v_obj.oid, 0));
    END LOOP;

    -- Check preconditions: exists/absent are partial tuple filters (only
    -- present fields constrain); allowed/denied are access checks.
    FOR v_pc IN SELECT * FROM jsonb_array_elements(p_preconditions)
    LOOP
        v_match := coalesce(v_pc->>'match', 'exists');
        IF v_match NOT IN ('exists', 'absent', 'allowed', 'denied') THEN
            RAISE EXCEPTION 'Unknown precondition match "%": expected "exists", "absent", "allowed" or "denied"', v_match;
        END IF;
        IF v_match IN ('allowed', 'denied') THEN
            IF v_pc->>'user_type' IS NULL OR v_pc->>'user_id' IS NULL OR v_pc->>'relation' IS NULL
               OR v_pc->>'object_type' IS NULL OR v_pc->>'object_id' IS NULL THEN
                RAISE EXCEPTION 'Precondition "%" needs user_type, user_id, relation, object_type and object_id: %', v_match, v_pc
                    USING ERRCODE = 'invalid_parameter_value';
            END IF;
            IF v_pc ? 'context' AND jsonb_typeof(v_pc->'context') NOT IN ('object', 'null') THEN
                RAISE EXCEPTION 'Precondition "%": context must be a JSON object', v_match
                    USING ERRCODE = 'invalid_parameter_value';
            END IF;
            -- The same decision check_access_with_context makes (the _decide
            -- seam: graph, conditions, gates), on committed state under the
            -- advisory locks taken above.
            v_found := authz._decide(v_store_id,
                authz._t(v_store_id, v_pc->>'user_type'), v_pc->>'user_id',
                authz._r(v_store_id, v_pc->>'relation'),
                authz._t(v_store_id, v_pc->>'object_type'), v_pc->>'object_id',
                CASE WHEN jsonb_typeof(v_pc->'context') = 'object' THEN v_pc->'context' END);
            IF (v_match = 'allowed' AND NOT v_found) OR (v_match = 'denied' AND v_found) THEN
                RAISE EXCEPTION 'Write precondition failed: % %', v_match, v_pc - 'context'
                    USING ERRCODE = 'check_violation';
            END IF;
            CONTINUE;
        END IF;
        v_found := authz._precondition_matches(v_store_id, v_pc);
        IF (v_match = 'exists' AND NOT v_found) OR (v_match = 'absent' AND v_found) THEN
            RAISE EXCEPTION 'Write precondition failed: % %', v_match, v_pc
                USING ERRCODE = 'check_violation';
        END IF;
    END LOOP;

    -- Apply deletes, then writes, in this same transaction.
    IF jsonb_array_length(p_deletes) > 0 THEN
        v_deleted := authz.delete_tuples_jsonb(p_store, p_deletes, p_performed_by);
    END IF;
    IF jsonb_array_length(p_writes) > 0 THEN
        v_written := authz.write_tuples_jsonb(p_store, p_writes, p_performed_by);
    END IF;

    RETURN jsonb_build_object('written', v_written, 'deleted', v_deleted);
END;
$$;

------------------------------------------------------------------------
-- authz.grant / authz.revoke: sharing as a first-class API (migration
-- 0017). "actor gives user relation on object" — allowed only if the
-- store's GRANT RULE for (object_type, relation) exists and the actor is
-- allowed its `requires` relation on that same object (`requires_revoke`
-- for authz.revoke). The decision is the full one (graph, conditions with
-- p_request_context, temporal gates), taken under the same per-object
-- advisory lock write_tuples_checked uses, so a right revoked concurrently
-- is seen; the tuple is then written / deleted with performed_by = the
-- actor, so the audit trail answers "who gave carol access" directly.
--
-- Fail-closed by construction: no rule → raise (the writer role's
-- write_tuple is unaffected). Object wildcards are refused — a per-object
-- check cannot cover "every object"; privileged wildcard grants stay a
-- writer-role write_tuple. Usersets, conditions and expiry pass through to
-- write_tuple, whose type-restriction and wildcard gates still apply.
--
-- Returns write_tuple's boolean (true = written, false = already present)
-- resp. delete_tuple's (true = deleted, false = no such tuple).
--
-- `grant` / `revoke` are SQL reserved words: call them schema-qualified,
-- as every authz function is (`SELECT authz.grant(...)`; a bare `grant(...)`
-- is a syntax error).
--
--   SELECT authz.grant('docs',  'user', 'bob', 'user', 'dave',  'editor', 'document', 'plan');
--   SELECT authz.revoke('docs', 'user', 'bob', 'user', 'carol', 'viewer', 'document', 'plan');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._grant_rule_check(
    p_store         text,
    p_store_id      integer,
    p_actor_type    text,
    p_actor_id      text,
    p_relation      text,
    p_object_type   text,
    p_object_id     text,
    p_revoke        boolean,
    p_context       jsonb
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_type    integer := authz._t(p_store_id, p_object_type);
    v_rel     integer := authz._r(p_store_id, p_relation);
    v_req     integer;
    v_req_nm  text;
    v_detail  jsonb;
    v_verb    text := CASE WHEN p_revoke THEN 'revoke' ELSE 'grant' END;
BEGIN
    IF p_object_id = '*' THEN
        RAISE EXCEPTION '%: object wildcards cannot be granted per object — use write_tuple (writer role)', v_verb
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT CASE WHEN p_revoke THEN COALESCE(g.requires_revoke, g.requires) ELSE g.requires END
      INTO v_req
      FROM authz.grant_rules g
     WHERE g.store_id = p_store_id AND g.object_type = v_type AND g.relation = v_rel;
    IF v_req IS NULL THEN
        RAISE EXCEPTION '%: no grant rule for %.% in store % — declare one with model_add_grant_rule',
            v_verb, p_object_type, p_relation, p_store
            USING ERRCODE = 'check_violation';
    END IF;
    SELECT r.name INTO v_req_nm FROM authz.relations r WHERE r.id = v_req;

    -- Same lock key as write_tuples_checked, so checked writes and
    -- grant/revoke on one object serialize with each other.
    PERFORM pg_advisory_xact_lock(hashtextextended(p_store || ':' || p_object_type || ':' || p_object_id, 0));

    IF NOT authz._decide(p_store_id, authz._t(p_store_id, p_actor_type), p_actor_id,
                         v_req, v_type, p_object_id, p_context) THEN
        -- Say which right is missing, and which context would settle it.
        v_detail := authz.check_access_detailed(p_store, p_actor_type, p_actor_id, v_req_nm,
                                                p_object_type, p_object_id, p_context);
        RAISE EXCEPTION '% refused: %:% is not allowed % on %:%',
            v_verb, p_actor_type, p_actor_id, v_req_nm, p_object_type,
            p_object_id || CASE WHEN v_detail->>'state' = 'conditional'
                 THEN ' (missing request context: ' || (SELECT string_agg(k, ', ') FROM jsonb_array_elements_text(v_detail->'missing_context') k) || ')'
                 ELSE '' END
            USING ERRCODE = 'insufficient_privilege';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION authz.grant(
    p_store             text,
    p_actor_type        text,
    p_actor_id          text,
    p_user_type         text,
    p_user_id           text,
    p_relation          text,
    p_object_type       text,
    p_object_id         text,
    p_user_relation     text        DEFAULT NULL,
    p_condition         text        DEFAULT NULL,
    p_condition_context jsonb       DEFAULT NULL,
    p_expires_at        timestamptz DEFAULT NULL,
    p_request_context   jsonb       DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
BEGIN
    PERFORM authz._grant_rule_check(p_store, v_store_id, p_actor_type, p_actor_id,
                                    p_relation, p_object_type, p_object_id, false, p_request_context);
    RETURN authz.write_tuple(p_store, p_user_type, p_user_id, p_relation, p_object_type, p_object_id,
                             p_user_relation, p_condition, p_condition_context,
                             p_performed_by => p_actor_type || ':' || p_actor_id,
                             p_expires_at   => p_expires_at);
END;
$$;

CREATE OR REPLACE FUNCTION authz.revoke(
    p_store           text,
    p_actor_type      text,
    p_actor_id        text,
    p_user_type       text,
    p_user_id         text,
    p_relation        text,
    p_object_type     text,
    p_object_id       text,
    p_user_relation   text  DEFAULT NULL,
    p_request_context jsonb DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
BEGIN
    PERFORM authz._grant_rule_check(p_store, v_store_id, p_actor_type, p_actor_id,
                                    p_relation, p_object_type, p_object_id, true, p_request_context);
    RETURN authz.delete_tuple(p_store, p_user_type, p_user_id, p_relation, p_object_type, p_object_id,
                              p_user_relation, p_performed_by => p_actor_type || ':' || p_actor_id);
END;
$$;

------------------------------------------------------------------------
-- UI support for sharing (migration 0017): render what an actor may do
-- before offering it. The grantee never affects these answers — whether
-- bob may grant `editor` on the plan depends on bob, the relation and the
-- object alone; the grantee only matters through the (static) type
-- restrictions, reported here as grantee_types so a picker can offer only
-- subjects the relation may hold.
--
--   grant_options  — per object: every relation with a grant rule, whether
--                    the actor may grant / revoke it, and who may hold it.
--                    One call renders the share dialog AND the revoke
--                    button on each "who has access" row.
--   can_grant / can_revoke — the same as booleans (false, never raise, when
--                    the relation has no grant rule or the object is '*').
--   list_grant_rules — the store's rules by name (for "which of my
--                    documents can I share": list_objects on `requires`).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.list_grant_rules(p_store text)
RETURNS TABLE (object_type text, relation text, requires text, requires_revoke text)
LANGUAGE sql STABLE AS $$
    SELECT ot.name, rl.name, rq.name, COALESCE(rr.name, rq.name)
      FROM authz.grant_rules g
      JOIN authz.types     ot ON ot.id = g.object_type
      JOIN authz.relations rl ON rl.id = g.relation
      JOIN authz.relations rq ON rq.id = g.requires
 LEFT JOIN authz.relations rr ON rr.id = g.requires_revoke
     WHERE g.store_id = authz._s(p_store)
     ORDER BY 1, 2;
$$;

CREATE OR REPLACE FUNCTION authz.grant_options(
    p_store       text,
    p_actor_type  text,
    p_actor_id    text,
    p_object_type text,
    p_object_id   text,
    p_context     jsonb DEFAULT NULL
) RETURNS TABLE (
    relation        text,
    can_grant       boolean,
    can_revoke      boolean,
    requires        text,
    requires_revoke text,
    grantee_types   text[]
)
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_actor    integer := authz._t(v_store_id, p_actor_type);
    v_type     integer := authz._t(v_store_id, p_object_type);
    v_rule     record;
    v_req_rev  integer;
    v_ok_grant boolean;
    v_ok_rev   boolean;
BEGIN
    FOR v_rule IN
        SELECT g.relation, g.requires, g.requires_revoke, rl.name AS relation_name,
               rq.name AS requires_name, COALESCE(rr.name, rq.name) AS requires_revoke_name
          FROM authz.grant_rules g
          JOIN authz.relations rl ON rl.id = g.relation
          JOIN authz.relations rq ON rq.id = g.requires
     LEFT JOIN authz.relations rr ON rr.id = g.requires_revoke
         WHERE g.store_id = v_store_id AND g.object_type = v_type
         ORDER BY rl.name
    LOOP
        v_req_rev := COALESCE(v_rule.requires_revoke, v_rule.requires);
        IF p_object_id = '*' THEN
            v_ok_grant := false; v_ok_rev := false;   -- grant/revoke refuse wildcards
        ELSE
            v_ok_grant := authz._decide(v_store_id, v_actor, p_actor_id, v_rule.requires, v_type, p_object_id, p_context);
            v_ok_rev   := CASE WHEN v_req_rev = v_rule.requires THEN v_ok_grant
                               ELSE authz._decide(v_store_id, v_actor, p_actor_id, v_req_rev, v_type, p_object_id, p_context) END;
        END IF;
        relation        := v_rule.relation_name;
        can_grant       := v_ok_grant;
        can_revoke      := v_ok_rev;
        requires        := v_rule.requires_name;
        requires_revoke := v_rule.requires_revoke_name;
        -- Who may hold the relation: "user", "team#member", "user:*" (wildcard allowed).
        SELECT COALESCE(array_agg(
                   ut.name || CASE WHEN ur.name IS NOT NULL THEN '#' || ur.name ELSE '' END
                           || CASE WHEN x.allow_wildcard THEN ':*' ELSE '' END
                   ORDER BY ut.name, ur.name NULLS FIRST), '{}')
          INTO grantee_types
          FROM authz.type_restrictions x
          JOIN authz.types ut ON ut.id = x.allowed_user_type
     LEFT JOIN authz.relations ur ON ur.id = x.allowed_user_relation
         WHERE x.store_id = v_store_id AND x.object_type = v_type AND x.relation = v_rule.relation;
        RETURN NEXT;
    END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION authz.can_grant(
    p_store text, p_actor_type text, p_actor_id text,
    p_relation text, p_object_type text, p_object_id text,
    p_context jsonb DEFAULT NULL
) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT COALESCE((SELECT o.can_grant FROM authz.grant_options(p_store, p_actor_type, p_actor_id, p_object_type, p_object_id, p_context) o
                      WHERE o.relation = p_relation), false);
$$;

CREATE OR REPLACE FUNCTION authz.can_revoke(
    p_store text, p_actor_type text, p_actor_id text,
    p_relation text, p_object_type text, p_object_id text,
    p_context jsonb DEFAULT NULL
) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT COALESCE((SELECT o.can_revoke FROM authz.grant_options(p_store, p_actor_type, p_actor_id, p_object_type, p_object_id, p_context) o
                      WHERE o.relation = p_relation), false);
$$;

------------------------------------------------------------------------
-- apply_grants: apply a set of grant changes — additions AND removals — as
-- ONE transaction: a share dialog's save. Every entry is decided under its
-- object lock exactly as authz.grant / authz.revoke would, all-or-nothing:
-- a single refusal rolls the whole batch back, and the error names the
-- entry. Grants-only or revokes-only is just an empty other array.
--
--   p_grants / p_revokes: arrays of {user_type, user_id, relation,
--     object_type, object_id, user_relation?, condition?, condition_context?,
--     expires_at? (grants), context?}; an entry's `context` overrides
--     p_context (the actor's request context for the check).
--   returns {"granted": n, "revoked": m} — counts of entries that changed
--     something (an already-present grant / absent revoke counts 0).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.apply_grants(
    p_store      text,
    p_actor_type text,
    p_actor_id   text,
    p_grants     jsonb DEFAULT '[]'::jsonb,
    p_revokes    jsonb DEFAULT '[]'::jsonb,
    p_context    jsonb DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v_obj     record;
    v_e       jsonb;
    v_i       integer := 0;
    v_granted integer := 0;
    v_revoked integer := 0;
    v_ctx     jsonb;
BEGIN
    IF jsonb_typeof(p_grants) <> 'array' OR jsonb_typeof(p_revokes) <> 'array' THEN
        RAISE EXCEPTION 'apply_grants: p_grants and p_revokes must be JSON arrays'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- Lock every object up front in a stable order (deadlock-free), as
    -- write_tuples_checked does; grant/revoke re-take the same locks (held).
    FOR v_obj IN
        SELECT DISTINCT e->>'object_type' AS ot, e->>'object_id' AS oid
          FROM jsonb_array_elements(p_grants || p_revokes) e
         ORDER BY 1, 2
    LOOP
        PERFORM pg_advisory_xact_lock(hashtextextended(p_store || ':' || v_obj.ot || ':' || v_obj.oid, 0));
    END LOOP;

    FOR v_e IN SELECT * FROM jsonb_array_elements(p_revokes)
    LOOP
        v_i := v_i + 1;
        v_ctx := CASE WHEN jsonb_typeof(v_e->'context') = 'object' THEN v_e->'context' ELSE p_context END;
        BEGIN
            IF authz.revoke(p_store, p_actor_type, p_actor_id,
                            v_e->>'user_type', v_e->>'user_id', v_e->>'relation',
                            v_e->>'object_type', v_e->>'object_id',
                            p_user_relation => v_e->>'user_relation', p_request_context => v_ctx) THEN
                v_revoked := v_revoked + 1;
            END IF;
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION 'apply_grants: revoke entry %: %', v_i, SQLERRM USING ERRCODE = SQLSTATE;
        END;
    END LOOP;
    v_i := 0;
    FOR v_e IN SELECT * FROM jsonb_array_elements(p_grants)
    LOOP
        v_i := v_i + 1;
        v_ctx := CASE WHEN jsonb_typeof(v_e->'context') = 'object' THEN v_e->'context' ELSE p_context END;
        BEGIN
            IF authz.grant(p_store, p_actor_type, p_actor_id,
                           v_e->>'user_type', v_e->>'user_id', v_e->>'relation',
                           v_e->>'object_type', v_e->>'object_id',
                           p_user_relation     => v_e->>'user_relation',
                           p_condition         => v_e->>'condition',
                           p_condition_context => CASE WHEN jsonb_typeof(v_e->'condition_context') = 'object' THEN v_e->'condition_context' END,
                           p_expires_at        => (v_e->>'expires_at')::timestamptz,
                           p_request_context   => v_ctx) THEN
                v_granted := v_granted + 1;
            END IF;
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION 'apply_grants: grant entry %: %', v_i, SQLERRM USING ERRCODE = SQLSTATE;
        END;
    END LOOP;
    RETURN jsonb_build_object('granted', v_granted, 'revoked', v_revoked);
END;
$$;

------------------------------------------------------------------------
-- grant_options_batch: grant_options for many (actor, object) pairs in one
-- call — a list view rendering a "Share" button per row (one actor, many
-- objects), or an admin view comparing actors. p_requests is a JSON array of
-- {actor_type, actor_id, object_type, object_id, context?}; each row of the
-- result carries the request's index (0-based) and identity, then the same
-- columns as grant_options. A request whose object type has no grant rules
-- yields no rows.
--
--   SELECT * FROM authz.grant_options_batch('gdrive', '[
--     {"actor_type": "user", "actor_id": "bob",   "object_type": "doc", "object_id": "design_spec"},
--     {"actor_type": "user", "actor_id": "alice", "object_type": "doc", "object_id": "design_spec"}]');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.grant_options_batch(
    p_store    text,
    p_requests jsonb
) RETURNS TABLE (
    idx             integer,
    actor_type      text,
    actor_id        text,
    object_type     text,
    object_id       text,
    relation        text,
    can_grant       boolean,
    can_revoke      boolean,
    requires        text,
    requires_revoke text,
    grantee_types   text[]
)
LANGUAGE plpgsql AS $$
DECLARE
    v_req jsonb;
    v_i   integer := -1;
BEGIN
    IF jsonb_typeof(p_requests) <> 'array' THEN
        RAISE EXCEPTION 'grant_options_batch: p_requests must be a JSON array'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOR v_req IN SELECT * FROM jsonb_array_elements(p_requests)
    LOOP
        v_i := v_i + 1;
        IF v_req->>'actor_type' IS NULL OR v_req->>'actor_id' IS NULL
           OR v_req->>'object_type' IS NULL OR v_req->>'object_id' IS NULL THEN
            RAISE EXCEPTION 'grant_options_batch: request % needs actor_type, actor_id, object_type and object_id', v_i
                USING ERRCODE = 'invalid_parameter_value';
        END IF;
        RETURN QUERY
            SELECT v_i, v_req->>'actor_type', v_req->>'actor_id', v_req->>'object_type', v_req->>'object_id',
                   o.relation, o.can_grant, o.can_revoke, o.requires, o.requires_revoke, o.grantee_types
              FROM authz.grant_options(p_store, v_req->>'actor_type', v_req->>'actor_id',
                                       v_req->>'object_type', v_req->>'object_id',
                                       CASE WHEN jsonb_typeof(v_req->'context') = 'object' THEN v_req->'context' END) o;
    END LOOP;
END;
$$;
