-- Public access check API: check_access, list_objects, list_subjects,
-- list_actions, validate_condition, find_redundant_tuples.
-- (explain_access and its helpers live in engine/explain.sql.)
-- All functions accept text parameters and resolve IDs internally.
--
-- Depends on: engine/core_internal.sql, engine/access_internal.sql

------------------------------------------------------------------------
-- check_access: "Can user X do action Y on resource Z?"
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.check_access(
    p_store       text,
    p_user_type   text,
    p_user_id     text,
    p_relation    text,
    p_object_type text,
    p_object_id   text
) RETURNS boolean
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id    smallint := authz._s(p_store);
    v_object_type smallint := authz._t(v_store_id, p_object_type);
BEGIN
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');
    RETURN authz._check_access(
        v_store_id,
        authz._t(v_store_id, p_user_type),
        p_user_id,
        authz._r(v_store_id, p_relation),
        v_object_type,
        p_object_id
    );
END;
$$;

------------------------------------------------------------------------
-- check_access_with_context: with request context for condition evaluation.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.check_access_with_context(
    p_store       text,
    p_user_type   text,
    p_user_id     text,
    p_relation    text,
    p_object_type text,
    p_object_id   text,
    context       jsonb
) RETURNS boolean
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id    smallint := authz._s(p_store);
    v_object_type smallint := authz._t(v_store_id, p_object_type);
BEGIN
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');
    RETURN authz._check_access(
        v_store_id,
        authz._t(v_store_id, p_user_type),
        p_user_id,
        authz._r(v_store_id, p_relation),
        v_object_type,
        p_object_id,
        context
    );
END;
$$;

------------------------------------------------------------------------
-- check_access_with_contextual_tuples: with ephemeral tuples AND request context.
-- Contextual tuples exist only for this single check — they are not persisted.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.check_access_with_contextual_tuples(
    p_store            text,
    p_user_type        text,
    p_user_id          text,
    p_relation         text,
    p_object_type      text,
    p_object_id        text,
    context            jsonb DEFAULT NULL,
    contextual_tuples  authz.tuple_input[] DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id    smallint := authz._s(p_store);
    v_has_ctx     boolean := false;
    v_result      boolean;
    v_user_type   smallint;
    v_relation    smallint;
    v_object_type smallint;
BEGIN
    v_user_type   := authz._t(v_store_id, p_user_type);
    v_relation    := authz._r(v_store_id, p_relation);
    v_object_type := authz._t(v_store_id, p_object_type);

    -- Enforce namespace-based read restrictions
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');

    -- Also check namespace access for every distinct object type in contextual tuples
    IF contextual_tuples IS NOT NULL AND array_length(contextual_tuples, 1) > 0 THEN
        PERFORM authz._check_namespace_access(
            v_store_id, authz._t(v_store_id, ct.object_type), 'can_read'
        )
        FROM (SELECT DISTINCT ct.object_type FROM unnest(contextual_tuples) AS ct) ct
        WHERE ct.object_type IS DISTINCT FROM p_object_type;
    END IF;

    -- Load contextual tuples into a temp table (if provided)
    IF contextual_tuples IS NOT NULL AND array_length(contextual_tuples, 1) > 0 THEN
        CREATE TEMP TABLE IF NOT EXISTS ctx_tuples (
            user_type     smallint,
            user_id       text,
            user_relation smallint,
            relation      smallint,
            object_type   smallint,
            object_id     text
        ) ON COMMIT DROP;

        TRUNCATE pg_temp.ctx_tuples;

        INSERT INTO pg_temp.ctx_tuples (user_type, user_id, user_relation, relation, object_type, object_id)
        SELECT
            authz._t(v_store_id, ct.user_type),
            ct.user_id,
            CASE WHEN ct.user_relation IS NULL THEN NULL
                 ELSE authz._r(v_store_id, ct.user_relation) END,
            authz._r(v_store_id, ct.relation),
            authz._t(v_store_id, ct.object_type),
            ct.object_id
        FROM unnest(contextual_tuples) AS ct;

        v_has_ctx := true;
    END IF;

    v_result := authz._check_access(
        v_store_id, v_user_type, p_user_id, v_relation, v_object_type, p_object_id,
        context, v_has_ctx
    );

    -- ctx_tuples has ON COMMIT DROP — no explicit cleanup needed.

    RETURN v_result;
END;
$$;

------------------------------------------------------------------------
-- check_access_with_contextual_tuples_jsonb: HTTP/JSON-friendly version.
-- Accepts contextual tuples as a JSONB array of objects, each with:
--   {"user_type", "user_id", "relation", "object_type", "object_id"}
--   and optionally "user_relation" (for userset tuples).
-- Delegates to the native array version after conversion.
--
-- Example via PostgREST:
--   POST /rpc/check_access_with_contextual_tuples_jsonb
--   {"p_store": "demo", "p_user_type": "internal_user", "p_user_id": "frank",
--    "p_relation": "viewer", "p_object_type": "document", "p_object_id": "doc_client_001",
--    "context": null,
--    "contextual_tuples": [
--        {"user_type":"internal_user","user_id":"frank","relation":"viewer",
--         "object_type":"document","object_id":"doc_client_001"}
--    ]}
--   => true
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.check_access_with_contextual_tuples_jsonb(
    p_store            text,
    p_user_type        text,
    p_user_id          text,
    p_relation         text,
    p_object_type      text,
    p_object_id        text,
    context            jsonb DEFAULT NULL,
    contextual_tuples  jsonb DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql AS $$
BEGIN
    IF contextual_tuples IS NOT NULL THEN
        PERFORM authz._validate_tuple_jsonb(contextual_tuples);
    END IF;
    RETURN authz.check_access_with_contextual_tuples(
        p_store, p_user_type, p_user_id, p_relation, p_object_type, p_object_id,
        context,
        (SELECT coalesce(array_agg(ROW(
            t->>'user_type',
            t->>'user_id',
            t->>'user_relation',
            t->>'relation',
            t->>'object_type',
            t->>'object_id'
        )::authz.tuple_input), '{}')
        FROM jsonb_array_elements(contextual_tuples) AS t)
    );
END;
$$;

------------------------------------------------------------------------
-- check_access_batch_typed_jsonb: HTTP/JSON-friendly version of
-- check_access_batch_typed. Accepts checks as a JSONB array of objects,
-- each with: {"user_type", "user_id", "relation", "object_type", "object_id"}.
-- Returns SETOF access_check_result (same as the array version).
-- Delegates to the native array version after validation and conversion.
--
-- Example via PostgREST:
--   POST /rpc/check_access_batch_typed_jsonb
--   {"p_store": "demo", "p_checks": [
--       {"user_type":"internal_user","user_id":"alice","relation":"can_read","object_type":"document","object_id":"doc1"},
--       {"user_type":"internal_user","user_id":"bob","relation":"can_edit","object_type":"document","object_id":"doc1"}
--   ]}
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.check_access_batch_typed_jsonb(
    p_store    text,
    p_checks   jsonb,
    p_context  jsonb DEFAULT NULL,
    p_semantic text DEFAULT 'execute_all'
) RETURNS SETOF authz.access_check_result
LANGUAGE plpgsql STABLE AS $$
BEGIN
    PERFORM authz._validate_tuple_jsonb(p_checks);
    RETURN QUERY SELECT * FROM authz.check_access_batch_typed(
        p_store,
        (SELECT coalesce(array_agg(ROW(
            c->>'user_type',
            c->>'user_id',
            c->>'relation',
            c->>'object_type',
            c->>'object_id'
        )::authz.access_check), '{}')
        FROM jsonb_array_elements(p_checks) AS c),
        p_context,
        p_semantic
    );
END;
$$;

------------------------------------------------------------------------
-- check_access_batch_typed: evaluate multiple access checks in a single call.
-- Native composite-array version for direct SQL callers.
-- Returns one access_check_result row per input check (same order).
--
-- Supports AuthZEN evaluation semantics via p_semantic:
--   'execute_all'           — evaluate all checks, return all results (default)
--   'deny_on_first_deny'    — short-circuit on first false
--   'permit_on_first_permit' — short-circuit on first true
--
-- When short-circuiting, remaining rows have decision = NULL.
--
-- Examples:
--   SELECT * FROM authz.check_access_batch_typed('demo', ARRAY[
--       ('internal_user','alice','can_read','document','doc1'),
--       ('internal_user','bob',  'can_edit','document','doc1')
--   ]::authz.access_check[]);
--
--   SELECT * FROM authz.check_access_batch_typed('demo', ARRAY[...]::authz.access_check[],
--       p_semantic => 'deny_on_first_deny')
--   WHERE decision;
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.check_access_batch_typed(
    p_store    text,
    p_checks   authz.access_check[],
    p_context  jsonb DEFAULT NULL,
    p_semantic text DEFAULT 'execute_all'
) RETURNS SETOF authz.access_check_result
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id    smallint := authz._s(p_store);
    v_check       authz.access_check;
    v_result      boolean;
    v_user_type   smallint;
    v_relation    smallint;
    v_object_type smallint;
    v_short       boolean := false;
    i             int := 0;
BEGIN
    IF p_semantic NOT IN ('execute_all', 'deny_on_first_deny', 'permit_on_first_permit') THEN
        RAISE EXCEPTION 'Invalid semantic: %. Must be execute_all, deny_on_first_deny, or permit_on_first_permit', p_semantic;
    END IF;

    FOREACH v_check IN ARRAY p_checks
    LOOP
        i := i + 1;

        IF v_short THEN
            -- Short-circuited: emit remaining checks with NULL decision
            RETURN NEXT (v_check.user_type, v_check.user_id, v_check.relation,
                         v_check.object_type, v_check.object_id, NULL)::authz.access_check_result;
            CONTINUE;
        END IF;

        v_user_type   := authz._t(v_store_id, v_check.user_type);
        v_relation    := authz._r(v_store_id, v_check.relation);
        v_object_type := authz._t(v_store_id, v_check.object_type);

        PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');

        v_result := authz._check_access(
            v_store_id, v_user_type, v_check.user_id,
            v_relation, v_object_type, v_check.object_id,
            p_context
        );

        RETURN NEXT (v_check.user_type, v_check.user_id, v_check.relation,
                     v_check.object_type, v_check.object_id, v_result)::authz.access_check_result;

        -- Short-circuit evaluation
        IF p_semantic = 'deny_on_first_deny' AND NOT v_result THEN
            v_short := true;
        ELSIF p_semantic = 'permit_on_first_permit' AND v_result THEN
            v_short := true;
        END IF;
    END LOOP;
END;
$$;

------------------------------------------------------------------------
-- check_access_batch (JSONB overload): HTTP/JSON-friendly version.
-- Accepts checks as a JSONB array of objects, each with:
--   {"user_type", "user_id", "relation", "object_type", "object_id"}
-- Returns a JSONB array of objects with {decision: bool} per check.
--
-- This overload is designed for PostgREST / HTTP callers where passing
-- PostgreSQL composite arrays is awkward. The native array overload
-- above is preferred for direct SQL callers.
--
-- Example via PostgREST:
--   POST /rpc/check_access_batch
--   {"p_store": "demo", "p_checks": [
--       {"user_type":"user","user_id":"alice","relation":"can_read","object_type":"doc","object_id":"doc1"},
--       {"user_type":"user","user_id":"bob","relation":"can_edit","object_type":"doc","object_id":"doc1"}
--   ]}
--   => [{"decision": true}, {"decision": false}]
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.check_access_batch(
    p_store    text,
    p_checks   jsonb,
    p_context  jsonb DEFAULT NULL,
    p_semantic text DEFAULT 'execute_all'
) RETURNS jsonb
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id    smallint := authz._s(p_store);
    v_results     jsonb := '[]'::jsonb;
    v_check       jsonb;
    v_result      boolean;
    v_user_type   smallint;
    v_relation    smallint;
    v_object_type smallint;
    v_len         int;
    i             int := 0;
BEGIN
    IF p_semantic NOT IN ('execute_all', 'deny_on_first_deny', 'permit_on_first_permit') THEN
        RAISE EXCEPTION 'Invalid semantic: %. Must be execute_all, deny_on_first_deny, or permit_on_first_permit', p_semantic;
    END IF;

    PERFORM authz._validate_tuple_jsonb(p_checks);

    v_len := jsonb_array_length(p_checks);

    FOR i IN 0 .. v_len - 1
    LOOP
        v_check := p_checks->i;

        v_user_type   := authz._t(v_store_id, v_check->>'user_type');
        v_relation    := authz._r(v_store_id, v_check->>'relation');
        v_object_type := authz._t(v_store_id, v_check->>'object_type');

        PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');

        v_result := authz._check_access(
            v_store_id, v_user_type, v_check->>'user_id',
            v_relation, v_object_type, v_check->>'object_id',
            p_context
        );

        v_results := v_results || jsonb_build_object('decision', v_result);

        -- Short-circuit evaluation
        IF p_semantic = 'deny_on_first_deny' AND NOT v_result THEN
            FOR j IN (i + 2) .. v_len LOOP
                v_results := v_results || jsonb_build_object('decision', null);
            END LOOP;
            RETURN v_results;
        END IF;

        IF p_semantic = 'permit_on_first_permit' AND v_result THEN
            FOR j IN (i + 2) .. v_len LOOP
                v_results := v_results || jsonb_build_object('decision', null);
            END LOOP;
            RETURN v_results;
        END IF;
    END LOOP;

    RETURN v_results;
END;
$$;

------------------------------------------------------------------------
-- validate_condition: dry-run a condition to check that the expression
-- evaluates without error given the provided context.
-- Returns true if valid, raises an exception with details if not.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.validate_condition(
    p_store             text,
    p_condition_name    text,
    p_condition_context jsonb DEFAULT '{}'::jsonb,
    p_request_context   jsonb DEFAULT '{}'::jsonb
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_cond   record;
    v_result boolean;
    v_missing text[];
    v_key    text;
BEGIN
    SELECT id, expression, required_context
      INTO v_cond
      FROM authz.conditions
     WHERE store_id = authz._s(p_store)
       AND name = p_condition_name;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown condition: %', p_condition_name;
    END IF;

    -- Check required keys if required_context is defined
    IF v_cond.required_context IS NOT NULL THEN
        -- Check required request context keys
        IF v_cond.required_context ? 'request' THEN
            FOR v_key IN SELECT jsonb_array_elements_text(v_cond.required_context->'request') LOOP
                IF NOT (p_request_context ? v_key) THEN
                    v_missing := array_append(v_missing, 'request.' || v_key);
                END IF;
            END LOOP;
        END IF;

        -- Check required stored context keys
        IF v_cond.required_context ? 'stored' THEN
            FOR v_key IN SELECT jsonb_array_elements_text(v_cond.required_context->'stored') LOOP
                IF NOT (p_condition_context ? v_key) THEN
                    v_missing := array_append(v_missing, 'stored.' || v_key);
                END IF;
            END LOOP;
        END IF;

        IF v_missing IS NOT NULL THEN
            RAISE EXCEPTION 'Condition "%" is missing required context keys: %',
                p_condition_name, array_to_string(v_missing, ', ');
        END IF;
    END IF;

    -- Try evaluating the expression via the sandboxed evaluator
    BEGIN
        v_result := authz._exec_condition(v_cond.expression, p_request_context, p_condition_context);
    EXCEPTION
        WHEN OTHERS THEN
            RAISE EXCEPTION 'Condition "%" failed evaluation: %', p_condition_name, SQLERRM;
    END;

    RETURN true;
END;
$$;

------------------------------------------------------------------------
-- list_objects: find all objects of a type that a user can access.
-- AuthZen Resource Search: "Which objects can user X do Y on?"
--
-- Two phases:
--
-- 1. Reverse expansion (recursive CTE): starting from the user's own
--    tuples (and wildcard tuples covering them), expand forward along
--    the three grant mechanisms — computed relations, userset
--    membership, and tuple-to-userset links — to collect every
--    (object, relation) pair the user can possibly reach. This is an
--    OVER-approximation: conditions, intersection legs, and exclusions
--    are ignored, so the candidate set is a guaranteed superset of the
--    accessible objects. Cost is O(user's reachable set), independent
--    of how many other objects exist in the store.
--
-- 2. Verification: each candidate runs through _check_access, which
--    is the final word on conditions, intersections, and exclusions.
--    The ordered candidate set lets the executor stop verifying once
--    OFFSET+LIMIT matches are found.
--
-- Note: for a user who can reach most of the store (e.g. a super
-- admin), the reachable set approaches the store size and this
-- degrades to the same O(all objects) as a candidate scan — the win
-- is for the common case of grant-sparse users on large stores.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.list_objects(
    p_store       text,
    p_user_type   text,
    p_user_id     text,
    p_relation    text,
    p_object_type text,
    context       jsonb DEFAULT NULL,
    p_limit       int DEFAULT NULL,
    p_offset      int DEFAULT 0
) RETURNS TABLE (object_id text, is_wildcard boolean)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id    smallint := authz._s(p_store);
    v_user_type   smallint := authz._t(v_store_id, p_user_type);
    v_relation    smallint := authz._r(v_store_id, p_relation);
    v_object_type smallint := authz._t(v_store_id, p_object_type);
BEGIN
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');
    RETURN QUERY
        WITH RECURSIVE reach (object_type, object_id, relation) AS (
            -- Seeds: tuples whose subject is the user, or a wildcard
            -- of the user's type.
            SELECT t.object_type, t.object_id, t.relation
              FROM authz.tuples t
             WHERE t.store_id      = v_store_id
               AND t.user_type     = v_user_type
               AND t.user_id       IN (p_user_id, '*')
               AND t.user_relation IS NULL
          UNION
            -- Expansion: from each reached (object A, relation r),
            -- follow every mechanism that can grant something further.
            -- The single LATERAL keeps one recursive reference, as
            -- required for multiple expansion branches.
            SELECT e.object_type, e.object_id, e.relation
              FROM reach r
              CROSS JOIN LATERAL (
                  -- computed: r on A implies R on A
                  SELECT r.object_type, r.object_id, m.relation
                    FROM authz.models m
                   WHERE m.store_id          = v_store_id
                     AND m.object_type       = r.object_type
                     AND m.rule_type         = 2  -- computed
                     AND m.computed_relation = r.relation
                UNION ALL
                  -- userset: tuples granting (A#r) something on B
                  SELECT t.object_type, t.object_id, t.relation
                    FROM authz.tuples t
                   WHERE t.store_id      = v_store_id
                     AND t.user_type     = r.object_type
                     AND t.user_id       = r.object_id
                     AND t.user_relation = r.relation
                UNION ALL
                  -- TTU: link tuple (A)-[ts]->(B) plus a rule on B
                  -- "R from ts" whose computed relation is r
                  SELECT t.object_type, t.object_id, m.relation
                    FROM authz.tuples t
                    JOIN authz.models m
                      ON m.store_id          = v_store_id
                     AND m.object_type       = t.object_type
                     AND m.rule_type         = 3  -- ttu
                     AND m.tupleset_relation = t.relation
                     AND m.tupleset_computed = r.relation
                   WHERE t.store_id      = v_store_id
                     AND t.user_type     = r.object_type
                     AND t.user_id       = r.object_id
                     AND t.user_relation IS NULL
              ) AS e (object_type, object_id, relation)
        )
        SELECT c.object_id, c.object_id = '*'
          FROM (SELECT DISTINCT r.object_id
                  FROM reach r
                 WHERE r.object_type = v_object_type
                   AND r.relation    = v_relation
                 ORDER BY r.object_id) c
         WHERE authz._check_access(v_store_id, v_user_type, p_user_id, v_relation, v_object_type, c.object_id, context)
         ORDER BY c.object_id
         OFFSET p_offset
         LIMIT p_limit;
END;
$$;

------------------------------------------------------------------------
-- list_subjects: find all users of a type that have a relation on an object.
-- AuthZen Subject Search: "Which users can do Y on object Z?"
--
-- Wildcard grants are reported as a typed row: subject_id '*' with
-- is_wildcard = true — "every user of this type has access". '*'
-- cannot collide with a real user (write_tuple reserves it as the
-- wildcard). Callers rendering subject lists (sharing panels, access
-- reviews) must branch on is_wildcard, typically rendering "Everyone"
-- — and must never drop the row: it is the one that says the object
-- is public.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.list_subjects(
    p_store        text,
    p_subject_type text,
    p_relation     text,
    p_object_type  text,
    p_object_id    text,
    context        jsonb DEFAULT NULL,
    p_limit        int DEFAULT NULL,
    p_offset       int DEFAULT 0
) RETURNS TABLE (subject_id text, is_wildcard boolean)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id     smallint := authz._s(p_store);
    v_subject_type smallint := authz._t(v_store_id, p_subject_type);
    v_relation     smallint := authz._r(v_store_id, p_relation);
    v_object_type  smallint := authz._t(v_store_id, p_object_type);
BEGIN
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');
    -- Deduplicate candidates BEFORE running the recursive check: a user
    -- appearing in N tuples must be checked once, not N times. Note the
    -- candidate set is every direct user of the type in the WHOLE store
    -- (there is no reverse index from object to potential users) — see
    -- the scaling note in docs/ARCHITECTURE.md.
    RETURN QUERY
        SELECT c.user_id, c.user_id = '*'
          FROM (SELECT DISTINCT t.user_id
                  FROM authz.tuples t
                 WHERE t.store_id = v_store_id
                   AND t.user_type = v_subject_type
                   AND t.user_relation IS NULL
                 ORDER BY t.user_id) c
         WHERE authz._check_access(v_store_id, v_subject_type, c.user_id, v_relation, v_object_type, p_object_id, context)
         ORDER BY c.user_id
         OFFSET p_offset
         LIMIT p_limit;
END;
$$;

------------------------------------------------------------------------
-- list_actions: find all permitted relations for a user on an object.
-- AuthZen Action Search: "What can user X do on object Z?"
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.list_actions(
    p_store       text,
    p_user_type   text,
    p_user_id     text,
    p_object_type text,
    p_object_id   text,
    context       jsonb DEFAULT NULL
) RETURNS TABLE (action text)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id    smallint := authz._s(p_store);
    v_user_type   smallint := authz._t(v_store_id, p_user_type);
    v_object_type smallint := authz._t(v_store_id, p_object_type);
BEGIN
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');
    RETURN QUERY
        SELECT r.name
          FROM (
              SELECT DISTINCT mr.relation
                FROM authz.models mr
               WHERE mr.store_id    = v_store_id
                 AND mr.object_type = v_object_type
          ) dr
          JOIN authz.relations r ON r.id = dr.relation
         WHERE authz._check_access(v_store_id, v_user_type, p_user_id, dr.relation, v_object_type, p_object_id, context);
END;
$$;

------------------------------------------------------------------------
-- find_redundant_tuples: identifies direct tuples that are already
-- granted by another rule path (computed, TTU, or userset expansion).
--
-- For each direct, non-userset tuple in the store, the function
-- temporarily hides it and checks whether _check_access still returns
-- true. If it does, the tuple is redundant — the user already has
-- access through another path.
--
-- This is an admin/maintenance function meant to be run periodically,
-- not on the hot path. Cost is O(N) check_access calls where N is the
-- number of direct tuples in scope.
--
-- Parameters:
--   p_store       — store name
--   p_object_type — optional: limit scan to one object type (NULL = all)
--   p_relation    — optional: limit scan to one relation (NULL = all)
--   context       — optional: request context for conditional tuples
--
-- Returns one row per redundant tuple with the user, relation, object,
-- and the tuple's creation timestamp.
--
-- Example:
--   SELECT * FROM authz.find_redundant_tuples('demo');
--   SELECT * FROM authz.find_redundant_tuples('demo', 'document', 'can_read');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.find_redundant_tuples(
    p_store       text,
    p_object_type text DEFAULT NULL,
    p_relation    text DEFAULT NULL,
    context       jsonb DEFAULT NULL
) RETURNS TABLE (
    user_type   text,
    user_id     text,
    relation    text,
    object_type text,
    object_id   text,
    created_at  timestamptz
)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id    smallint := authz._s(p_store);
    v_object_type smallint;
    v_relation    smallint;
    tpl           record;
    v_still_ok    boolean;
    v_exclude     authz._tuple_key;
BEGIN
    IF p_object_type IS NOT NULL THEN
        v_object_type := authz._t(v_store_id, p_object_type);
    END IF;
    IF p_relation IS NOT NULL THEN
        v_relation := authz._r(v_store_id, p_relation);
    END IF;

    -- Scan all direct, non-userset tuples in scope.
    FOR tpl IN
        SELECT t.store_id, t.user_type, t.user_id, t.relation,
               t.object_type, t.object_id, t.created_at,
               t.condition_id, t.condition_context
          FROM authz.tuples t
         WHERE t.store_id      = v_store_id
           AND t.user_relation IS NULL
           AND t.user_id      != '*'   -- skip wildcards: they're foundational, not redundant
           AND t.object_id    != '*'   -- same for object wildcards (privileged grants)
           AND (v_object_type IS NULL OR t.object_type = v_object_type)
           AND (v_relation    IS NULL OR t.relation    = v_relation)
    LOOP
        -- If the tuple has a condition that doesn't pass with the given
        -- context, it's not currently granting access — skip it.
        IF tpl.condition_id IS NOT NULL THEN
            IF NOT authz._eval_condition(tpl.condition_id, tpl.condition_context, context) THEN
                CONTINUE;
            END IF;
        END IF;

        -- Check if access is still granted when this specific tuple is excluded.
        -- The exclude propagates through the entire recursive check, causing
        -- _eval_direct to skip the direct match for this exact tuple while
        -- still evaluating all other paths (computed, TTU, usersets).
        v_exclude := ROW(tpl.user_type, tpl.user_id, tpl.relation,
                         tpl.object_type, tpl.object_id)::authz._tuple_key;

        v_still_ok := authz._check_access(
            v_store_id, tpl.user_type, tpl.user_id,
            tpl.relation, tpl.object_type, tpl.object_id,
            context,
            false,   -- p_has_ctx_tuples
            0,       -- p_depth
            NULL,    -- p_trace
            v_exclude
        );

        IF v_still_ok THEN
            user_type   := (SELECT t.name FROM authz.types t     WHERE t.id = tpl.user_type);
            user_id     := tpl.user_id;
            relation    := (SELECT r.name FROM authz.relations r WHERE r.id = tpl.relation);
            object_type := (SELECT t.name FROM authz.types t     WHERE t.id = tpl.object_type);
            object_id   := tpl.object_id;
            created_at  := tpl.created_at;
            RETURN NEXT;
        END IF;
    END LOOP;
END;
$$;

------------------------------------------------------------------------
-- cleanup_redundant_tuples: finds and optionally deletes direct tuples
-- that are already granted by another rule path.
--
-- Wraps find_redundant_tuples. By default performs a dry run (p_dry_run
-- = true) that only lists what would be deleted. Set p_dry_run = false
-- to actually delete the redundant tuples.
--
-- Deleted tuples are recorded in the audit trail via delete_tuple with
-- p_performed_by = 'cleanup_redundant_tuples'.
--
-- Parameters:
--   p_store       — store name
--   p_object_type — optional: limit to one object type (NULL = all)
--   p_relation    — optional: limit to one relation (NULL = all)
--   p_context     — optional: request context for conditional tuples
--   p_dry_run     — if true (default), only list; if false, delete
--
-- Returns one row per redundant tuple found (or deleted), with a
-- boolean indicating whether it was actually removed.
--
-- Example:
--   SELECT * FROM authz.cleanup_redundant_tuples('demo');
--   SELECT * FROM authz.cleanup_redundant_tuples('demo', p_dry_run := false);
--   SELECT * FROM authz.cleanup_redundant_tuples('demo', 'document', 'can_read');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.cleanup_redundant_tuples(
    p_store       text,
    p_object_type text    DEFAULT NULL,
    p_relation    text    DEFAULT NULL,
    p_context     jsonb   DEFAULT NULL,
    p_dry_run     boolean DEFAULT true
) RETURNS TABLE (
    user_type   text,
    user_id     text,
    relation    text,
    object_type text,
    object_id   text,
    created_at  timestamptz,
    deleted     boolean
)
LANGUAGE plpgsql AS $$
DECLARE
    tpl record;
    v_deleted boolean;
BEGIN
    FOR tpl IN
        SELECT r.user_type, r.user_id, r.relation,
               r.object_type, r.object_id, r.created_at
          FROM authz.find_redundant_tuples(p_store, p_object_type, p_relation, p_context) r
    LOOP
        v_deleted := false;

        IF NOT p_dry_run THEN
            PERFORM authz.delete_tuple(p_store,
                tpl.user_type, tpl.user_id, tpl.relation,
                tpl.object_type, tpl.object_id,
                p_performed_by := 'cleanup_redundant_tuples');
            v_deleted := true;
        END IF;

        user_type   := tpl.user_type;
        user_id     := tpl.user_id;
        relation    := tpl.relation;
        object_type := tpl.object_type;
        object_id   := tpl.object_id;
        created_at  := tpl.created_at;
        deleted     := v_deleted;
        RETURN NEXT;
    END LOOP;
END;
$$;
