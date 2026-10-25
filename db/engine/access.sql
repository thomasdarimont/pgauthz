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
    v_store_id    integer := authz._s(p_store);
    v_object_type integer := authz._t(v_store_id, p_object_type);
BEGIN
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');
    RETURN authz._decide(
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
    v_store_id    integer := authz._s(p_store);
    v_object_type integer := authz._t(v_store_id, p_object_type);
BEGIN
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');
    RETURN authz._decide(
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
    v_store_id    integer := authz._s(p_store);
    v_has_ctx     boolean := false;
    v_result      boolean;
    v_user_type   integer;
    v_relation    integer;
    v_object_type integer;
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
        -- no IF NOT EXISTS: that form raises a NOTICE on every reuse within a
        -- session (hundreds of thousands of lines in a long-lived connection's log)
        IF to_regclass('pg_temp.ctx_tuples') IS NULL THEN
            CREATE TEMP TABLE ctx_tuples (
                user_type     integer,
                user_id       text,
                user_relation integer,
                relation      integer,
                object_type   integer,
                object_id     text
            ) ON COMMIT DROP;
        END IF;

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

    -- Contextual tuples only affect the graph; the gates apply as usual.
    v_result := authz._decide(
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
-- Example via pgauthzd (native `/pgauthz/v1`):
--   POST /pgauthz/v1/check
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
-- Example via pgauthzd (native `/pgauthz/v1`):
--   POST /pgauthz/v1/check-batch
--   {"p_store": "demo", "p_checks": [
--       {"user_type":"internal_user","user_id":"alice","relation":"can_read","object_type":"document","object_id":"doc1"},
--       {"user_type":"internal_user","user_id":"bob","relation":"can_edit","object_type":"document","object_id":"doc1"}
--   ]}
------------------------------------------------------------------------
------------------------------------------------------------------------
-- _load_contextual_tuples: the one loader behind every
-- *_with_contextual_tuples_jsonb entry point. Validates the JSONB array
-- ({"user_type","user_id","relation","object_type","object_id"}, optionally
-- "user_relation"), checks namespace access for every object type the
-- tuples mention, and loads them — resolved to the store's ids — into the
-- per-transaction temp table pg_temp.ctx_tuples (ON COMMIT DROP; an
-- earlier load of the same transaction is replaced). Returns true when
-- tuples were loaded — the p_has_ctx_tuples the decision path takes —
-- false for NULL or an empty array, in which case nothing is touched.
-- VOLATILE (DDL on the temp table), so its callers are too: the plain,
-- STABLE search and explain functions never see the table (they pass
-- false), whatever the transaction loaded before.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._load_contextual_tuples(
    p_store_id          integer,
    p_contextual_tuples jsonb
) RETURNS boolean
LANGUAGE plpgsql AS $$
BEGIN
    IF p_contextual_tuples IS NULL THEN
        RETURN false;
    END IF;
    PERFORM authz._validate_tuple_jsonb(p_contextual_tuples);
    IF jsonb_array_length(p_contextual_tuples) = 0 THEN
        RETURN false;
    END IF;
    PERFORM authz._check_namespace_access(p_store_id, authz._t(p_store_id, x.object_type), 'can_read')
       FROM (SELECT DISTINCT t->>'object_type' AS object_type FROM jsonb_array_elements(p_contextual_tuples) t) x;
    -- no IF NOT EXISTS: that form raises a NOTICE on every reuse within a
    -- session (hundreds of thousands of lines in a long-lived connection's log)
    IF to_regclass('pg_temp.ctx_tuples') IS NULL THEN
        CREATE TEMP TABLE ctx_tuples (
            user_type     integer,
            user_id       text,
            user_relation integer,
            relation      integer,
            object_type   integer,
            object_id     text
        ) ON COMMIT DROP;
    END IF;
    TRUNCATE pg_temp.ctx_tuples;
    INSERT INTO pg_temp.ctx_tuples (user_type, user_id, user_relation, relation, object_type, object_id)
    SELECT authz._t(p_store_id, t->>'user_type'),
           t->>'user_id',
           CASE WHEN t->>'user_relation' IS NULL THEN NULL ELSE authz._r(p_store_id, t->>'user_relation') END,
           authz._r(p_store_id, t->>'relation'),
           authz._t(p_store_id, t->>'object_type'),
           t->>'object_id'
      FROM jsonb_array_elements(p_contextual_tuples) t;
    RETURN true;
END;
$$;

------------------------------------------------------------------------
-- check_access_batch_with_contextual_tuples_jsonb: many checks, one set of
-- contextual tuples, one call. The contextual tuples are validated and
-- loaded into the per-transaction temp table ONCE; every check then runs
-- through _decide against the same snapshot. The management console asks
-- "which of these capabilities does this person hold on each of these
-- stores" this way — hundreds of checks that would otherwise each pay for
-- their own setup.
--
--   p_checks: [{"user_type","user_id","relation","object_type","object_id"}, …]
--   p_contextual_tuples: as for check_access_with_contextual_tuples_jsonb
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.check_access_batch_with_contextual_tuples_jsonb(
    p_store             text,
    p_checks            jsonb,
    p_context           jsonb DEFAULT NULL,
    p_contextual_tuples jsonb DEFAULT NULL
) RETURNS SETOF authz.access_check_result
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_has_ctx  boolean := false;
    v_c        record;
    v_row      authz.access_check_result;
    v_n        integer := COALESCE(jsonb_array_length(p_checks), 0);
BEGIN
    IF v_n = 0 THEN
        RETURN;
    END IF;
    -- Cap per call (a runaway caller must not pin a backend): the GUC
    -- authz.max_batch_checks, default 5000; set it per session or per role.
    IF v_n > COALESCE(NULLIF(current_setting('authz.max_batch_checks', true), '')::int, 5000) THEN
        RAISE EXCEPTION 'at most % checks per batch (got %); raise authz.max_batch_checks to allow more',
            COALESCE(NULLIF(current_setting('authz.max_batch_checks', true), '')::int, 5000), v_n
            USING ERRCODE = 'check_violation';
    END IF;
    PERFORM authz._validate_tuple_jsonb(p_checks);

    v_has_ctx := authz._load_contextual_tuples(v_store_id, p_contextual_tuples);

    FOR v_c IN
        SELECT c->>'user_type' AS user_type, c->>'user_id' AS user_id, c->>'relation' AS relation,
               c->>'object_type' AS object_type, c->>'object_id' AS object_id
          FROM jsonb_array_elements(p_checks) c
    LOOP
        PERFORM authz._check_namespace_access(v_store_id, authz._t(v_store_id, v_c.object_type), 'can_read');
        v_row.user_type   := v_c.user_type;
        v_row.user_id     := v_c.user_id;
        v_row.relation    := v_c.relation;
        v_row.object_type := v_c.object_type;
        v_row.object_id   := v_c.object_id;
        v_row.decision    := authz._decide(
            v_store_id, authz._t(v_store_id, v_c.user_type), v_c.user_id,
            authz._r(v_store_id, v_c.relation), authz._t(v_store_id, v_c.object_type), v_c.object_id,
            p_context, v_has_ctx);
        RETURN NEXT v_row;
    END LOOP;
END;
$$;

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
    v_store_id    integer := authz._s(p_store);
    v_check       authz.access_check;
    v_result      boolean;
    v_user_type   integer;
    v_relation    integer;
    v_object_type integer;
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

        v_result := authz._decide(
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
-- and optionally "context": a per-check request context, merged over the
-- shared p_context (the check's keys win, top-level key by key) — what an
-- AuthZEN batch needs when each evaluation carries its own resource or
-- action properties (pgauthzd puts them into the context).
-- Returns a JSONB array of objects with {decision: bool} per check.
--
-- This overload is designed for pgauthzd / HTTP callers where passing
-- PostgreSQL composite arrays is awkward. The native array overload
-- above is preferred for direct SQL callers.
--
-- Example via pgauthzd (native `/pgauthz/v1`):
--   POST /pgauthz/v1/check-batch
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
    v_store_id    integer := authz._s(p_store);
    v_results     jsonb := '[]'::jsonb;
    v_check       jsonb;
    v_context     jsonb;
    v_result      boolean;
    v_user_type   integer;
    v_relation    integer;
    v_object_type integer;
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

        -- per-check context, merged over the shared one (check wins per key)
        IF jsonb_typeof(v_check->'context') = 'object' THEN
            v_context := COALESCE(p_context, '{}'::jsonb) || (v_check->'context');
        ELSE
            v_context := p_context;
        END IF;

        v_result := authz._decide(
            v_store_id, v_user_type, v_check->>'user_id',
            v_relation, v_object_type, v_check->>'object_id',
            v_context
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
    SELECT id, expression, lang, required_context
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

    -- Try evaluating the expression via the language dispatcher (sandboxed for 'sql')
    BEGIN
        v_result := authz._eval_condition_expr(v_cond.lang, v_cond.expression, p_request_context, p_condition_context);
    EXCEPTION
        WHEN OTHERS THEN
            RAISE EXCEPTION 'Condition "%" failed evaluation: %', p_condition_name, SQLERRM;
    END;

    RETURN true;
END;
$$;

------------------------------------------------------------------------
-- evaluate_condition: the condition's actual verdict for a request context
-- and a (mocked) stored context, with no tuple involved — what a tuple
-- carrying this condition would decide. Same checks as validate_condition
-- (unknown condition, missing required keys, evaluation errors raise), but
-- returns the expression's result instead of "it is well-formed".
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.evaluate_condition(
    p_store             text,
    p_condition_name    text,
    p_request_context   jsonb DEFAULT '{}'::jsonb,
    p_condition_context jsonb DEFAULT '{}'::jsonb
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_cond record;
    v_req  jsonb := COALESCE(p_request_context, '{}'::jsonb);
BEGIN
    SELECT expression, lang, time_source INTO v_cond
      FROM authz.conditions
     WHERE store_id = authz._s(p_store) AND name = p_condition_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown condition: %', p_condition_name;
    END IF;
    -- As in a real check: a server-time condition takes `current_time` from
    -- the engine's clock, whatever the caller sent (and need not send it).
    IF v_cond.time_source = 'server' THEN
        v_req := authz._with_server_time(v_req);
    END IF;
    PERFORM authz.validate_condition(p_store, p_condition_name, p_condition_context, v_req);
    RETURN COALESCE(authz._eval_condition_expr(v_cond.lang, v_cond.expression, v_req, p_condition_context), false);
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
-- The walk lives in _list_objects; list_objects is the public, stored-
-- tuples-only entry point and list_objects_with_contextual_tuples_jsonb
-- (below) the one that also walks the transaction's contextual tuples
-- (p_has_ctx): they seed and extend paths like stored tuples do, and the
-- final _decide sees them too. With p_has_ctx false the contextual
-- branches are gated out of the plan (a one-time filter on a constant).
CREATE OR REPLACE FUNCTION authz._list_objects(
    p_store       text,
    p_user_type   text,
    p_user_id     text,
    p_relation    text,
    p_object_type text,
    context       jsonb,
    p_limit       int,
    p_offset      int,
    p_after       text,               -- keyset cursor: last object_id of the previous page
    p_has_ctx     boolean
) RETURNS TABLE (object_id text, is_wildcard boolean)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id    integer := authz._s(p_store);
    v_user_type   integer := authz._t(v_store_id, p_user_type);
    v_relation    integer := authz._r(v_store_id, p_relation);
    v_object_type integer := authz._t(v_store_id, p_object_type);
    v_gates       jsonb;
    -- The store's own type ids, for partition pruning of the subject-rooted
    -- scans below (see the seed scan). An array parameter prunes at executor
    -- start; the earlier `IN (SELECT id FROM authz.types …)` form stopped
    -- pruning on PostgreSQL 18.4 (planned as a merge join over a Merge Append
    -- of EVERY partition of EVERY store — 130 partitions, 40k buffers, 8x
    -- slower; re-found by the benchmark 2026-09-29).
    v_type_ids    integer[] := ARRAY(SELECT ty.id FROM authz.types ty WHERE ty.store_id = v_store_id);
BEGIN
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');
    -- Temporal gates (ADR 0012): with subject-scoped clauses only, ONE
    -- evaluation settles every candidate (a gate deny is an empty page — no
    -- graph work at all) and '[]' below tells _decide they are settled. Any
    -- object-scoped clause ("3 downloads of THIS file") depends on the
    -- candidate, so the list is handed to _decide and evaluated per object.
    v_gates := authz._event_resolve_gates(v_store_id, v_object_type, v_relation);
    IF NOT authz._event_gates_object_scoped(v_gates) THEN
        IF NOT authz._event_check_gates(v_store_id, v_user_type, p_user_id, v_relation, v_object_type, NULL, context,
                                        p_gates => v_gates) THEN
            RETURN;
        END IF;
        v_gates := '[]'::jsonb;
    END IF;
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
               -- Partition pruning: these scans are SUBJECT-rooted, so the
               -- partition key (object_type) is otherwise unconstrained and
               -- EVERY tuple partition of EVERY store gets scanned per
               -- iteration (168 partitions from 3 stores in the dev DB —
               -- 115x slower). The predicate is a tautology (a store's tuples
               -- only reference its own types) that the executor turns into
               -- startup-time pruning down to this store's partitions. It
               -- must be an ARRAY parameter: an IN (subselect) was planned as
               -- a join on 18.4 and pruned nothing.
               AND t.object_type   = ANY (v_type_ids)
          UNION ALL
            -- Contextual tuples seed paths exactly like stored ones.
            SELECT ct.object_type, ct.object_id, ct.relation
              FROM authz._ctx_tuples() ct
             WHERE p_has_ctx
               AND ct.user_type     = v_user_type
               AND ct.user_id       IN (p_user_id, '*')
               AND ct.user_relation IS NULL
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
                     AND m.rule_type         = authz._rel_computed()
                     AND m.computed_relation = r.relation
                UNION ALL
                  -- userset: tuples granting (A#r) something on B
                  SELECT t.object_type, t.object_id, t.relation
                    FROM authz.tuples t
                   WHERE t.store_id      = v_store_id
                     AND t.user_type     = r.object_type
                     AND t.user_id       = r.object_id
                     AND t.user_relation = r.relation
                     AND t.object_type   = ANY (v_type_ids)  -- pruning (see seed scan)
                UNION ALL
                  -- TTU: link tuple (A)-[ts]->(B) plus a rule on B
                  -- "R from ts" whose computed relation is r
                  SELECT t.object_type, t.object_id, m.relation
                    FROM authz.tuples t
                    JOIN authz.models m
                      ON m.store_id          = v_store_id
                     AND m.object_type       = t.object_type
                     AND m.rule_type         = authz._rel_ttu()
                     AND m.tupleset_relation = t.relation
                     AND m.tupleset_computed = r.relation
                   WHERE t.store_id      = v_store_id
                     AND t.user_type     = r.object_type
                     AND t.user_id       = r.object_id
                     AND t.user_relation IS NULL
                     AND t.object_type   = ANY (v_type_ids)  -- pruning (see seed scan)
                UNION ALL
                  -- userset via a contextual tuple
                  SELECT ct.object_type, ct.object_id, ct.relation
                    FROM authz._ctx_tuples() ct
                   WHERE p_has_ctx
                     AND ct.user_type     = r.object_type
                     AND ct.user_id       = r.object_id
                     AND ct.user_relation = r.relation
                UNION ALL
                  -- TTU via a contextual link tuple
                  SELECT ct.object_type, ct.object_id, m.relation
                    FROM authz._ctx_tuples() ct
                    JOIN authz.models m
                      ON m.store_id          = v_store_id
                     AND m.object_type       = ct.object_type
                     AND m.rule_type         = authz._rel_ttu()
                     AND m.tupleset_relation = ct.relation
                     AND m.tupleset_computed = r.relation
                   WHERE p_has_ctx
                     AND ct.user_type     = r.object_type
                     AND ct.user_id       = r.object_id
                     AND ct.user_relation IS NULL
              ) AS e (object_type, object_id, relation)
        )
        SELECT c.object_id, c.object_id = '*'
          FROM (SELECT DISTINCT r.object_id
                  FROM reach r
                 WHERE r.object_type = v_object_type
                   AND r.relation    = v_relation
                   -- keyset cursor: only candidates after the previous page, so
                   -- _check_access never re-runs on earlier pages' objects.
                   AND (p_after IS NULL OR r.object_id > p_after)
                 ORDER BY r.object_id) c
         WHERE authz._decide(v_store_id, v_user_type, p_user_id, v_relation, v_object_type, c.object_id, context,
                             p_has_ctx_tuples => p_has_ctx, p_gates => v_gates)
         ORDER BY c.object_id
         -- p_after (keyset) takes precedence over p_offset when supplied.
         OFFSET (CASE WHEN p_after IS NULL THEN p_offset ELSE 0 END)
         LIMIT p_limit;
END;
$$;

CREATE OR REPLACE FUNCTION authz.list_objects(
    p_store       text,
    p_user_type   text,
    p_user_id     text,
    p_relation    text,
    p_object_type text,
    context       jsonb DEFAULT NULL,
    p_limit       int DEFAULT NULL,
    p_offset      int DEFAULT 0,
    p_after       text DEFAULT NULL   -- keyset cursor: last object_id of the previous page
) RETURNS TABLE (object_id text, is_wildcard boolean)
LANGUAGE plpgsql STABLE AS $$
BEGIN
    RETURN QUERY SELECT * FROM authz._list_objects(
        p_store, p_user_type, p_user_id, p_relation, p_object_type, context, p_limit, p_offset, p_after, false);
END;
$$;

------------------------------------------------------------------------
-- list_objects_with_contextual_tuples_jsonb: list_objects with ephemeral
-- tuples for this call (the shape of check_access_with_contextual_tuples_jsonb;
-- see _load_contextual_tuples). Gated by authz_contextual_reader like the
-- contextual checks: the caller can inject the very grant being searched.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.list_objects_with_contextual_tuples_jsonb(
    p_store             text,
    p_user_type         text,
    p_user_id           text,
    p_relation          text,
    p_object_type       text,
    context             jsonb DEFAULT NULL,
    p_contextual_tuples jsonb DEFAULT NULL,
    p_limit             int DEFAULT NULL,
    p_offset            int DEFAULT 0,
    p_after             text DEFAULT NULL
) RETURNS TABLE (object_id text, is_wildcard boolean)
LANGUAGE plpgsql AS $$
DECLARE
    v_has_ctx boolean := authz._load_contextual_tuples(authz._s(p_store), p_contextual_tuples);
BEGIN
    RETURN QUERY SELECT * FROM authz._list_objects(
        p_store, p_user_type, p_user_id, p_relation, p_object_type, context, p_limit, p_offset, p_after, v_has_ctx);
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
-- As for list_objects: the walk is _list_subjects, the public entry points
-- list_subjects (stored tuples only) and
-- list_subjects_with_contextual_tuples_jsonb (contextual tuples walked too).
CREATE OR REPLACE FUNCTION authz._list_subjects(
    p_store        text,
    p_subject_type text,
    p_relation     text,
    p_object_type  text,
    p_object_id    text,
    context        jsonb,
    p_limit        int,
    p_offset       int,
    p_after        text,               -- keyset cursor: last subject_id of the previous page
    p_has_ctx      boolean
) RETURNS TABLE (subject_id text, is_wildcard boolean)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id     integer := authz._s(p_store);
    v_subject_type integer := authz._t(v_store_id, p_subject_type);
    v_relation     integer := authz._r(v_store_id, p_relation);
    v_object_type  integer := authz._t(v_store_id, p_object_type);
    v_gates        jsonb;
BEGIN
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');
    -- Gate definitions (ADR 0012) are constant across candidates: resolve
    -- once, evaluate per candidate (one indexed window query each, bounded
    -- by the page size).
    v_gates := authz._event_resolve_gates(v_store_id, v_object_type, v_relation);
    -- Reverse expansion (the dual of list_objects): walk UP the grant graph
    -- from the object to the candidate subjects, so the candidate set is
    -- bounded by the object's reachable subjects — not by the store-wide
    -- user population. The walk follows the OR-union of all grant paths and
    -- ignores group_op (AND / BUT NOT) and conditions, so it over-
    -- approximates; the final _check_access filter makes it exact. A user
    -- appearing via N paths is deduplicated and checked once.
    RETURN QUERY
        WITH RECURSIVE reach (object_type, object_id, relation) AS (
            -- Seed: the queried (object, relation).
            SELECT v_object_type, p_object_id, v_relation
          UNION
            -- Expansion: from each reached (B, R), the (A, r) nodes that,
            -- if satisfied, imply R on B. One recursive reference (a single
            -- LATERAL with multiple branches), as the SQL standard requires.
            SELECT e.object_type, e.object_id, e.relation
              FROM reach r
              CROSS JOIN LATERAL (
                  -- computed: rule "R = computed(C)" on B's type ⇒ (B, C)
                  SELECT r.object_type, r.object_id, m.computed_relation
                    FROM authz.models m
                   WHERE m.store_id          = v_store_id
                     AND m.object_type       = r.object_type
                     AND m.rule_type         = authz._rel_computed()
                     AND m.relation          = r.relation
                     AND m.computed_relation IS NOT NULL
                UNION ALL
                  -- userset: tuple (B, R, A#ur) ⇒ (A, ur)
                  SELECT t.user_type, t.user_id, t.user_relation
                    FROM authz.tuples t
                   WHERE t.store_id      = v_store_id
                     AND t.object_type   = r.object_type
                     AND t.object_id     IN (r.object_id, '*')
                     AND t.relation      = r.relation
                     AND t.user_relation IS NOT NULL
                UNION ALL
                  -- TTU: rule "R = ts→C" on B + link tuple (B, ts, A) ⇒ (A, C)
                  SELECT t.user_type, t.user_id, m.tupleset_computed
                    FROM authz.models m
                    JOIN authz.tuples t
                      ON t.store_id      = v_store_id
                     AND t.object_type   = r.object_type
                     AND t.object_id     IN (r.object_id, '*')
                     AND t.relation      = m.tupleset_relation
                     AND t.user_relation IS NULL
                   WHERE m.store_id    = v_store_id
                     AND m.object_type = r.object_type
                     AND m.rule_type   = authz._rel_ttu()
                     AND m.relation    = r.relation
                UNION ALL
                  -- userset via a contextual tuple (B, R, A#ur) ⇒ (A, ur)
                  SELECT ct.user_type, ct.user_id, ct.user_relation
                    FROM authz._ctx_tuples() ct
                   WHERE p_has_ctx
                     AND ct.object_type   = r.object_type
                     AND ct.object_id     IN (r.object_id, '*')
                     AND ct.relation      = r.relation
                     AND ct.user_relation IS NOT NULL
                UNION ALL
                  -- TTU via a contextual link tuple (B, ts, A) ⇒ (A, C)
                  SELECT ct.user_type, ct.user_id, m.tupleset_computed
                    FROM authz.models m
                    JOIN authz._ctx_tuples() ct
                      ON ct.object_type   = r.object_type
                     AND ct.object_id     IN (r.object_id, '*')
                     AND ct.relation      = m.tupleset_relation
                     AND ct.user_relation IS NULL
                   WHERE p_has_ctx
                     AND m.store_id    = v_store_id
                     AND m.object_type = r.object_type
                     AND m.rule_type   = authz._rel_ttu()
                     AND m.relation    = r.relation
              ) AS e (object_type, object_id, relation)
        )
        SELECT c.subject_id, c.subject_id = '*'
          FROM (
              -- Concrete subjects of the requested type sitting at any
              -- reached node (object-wildcard grants via object_id = '*'),
              -- stored or contextual.
              SELECT DISTINCT x.subject_id
                FROM (
                    SELECT t.user_id AS subject_id
                      FROM reach r
                      JOIN authz.tuples t
                        ON t.store_id      = v_store_id
                       AND t.object_type   = r.object_type
                       AND t.object_id     IN (r.object_id, '*')
                       AND t.relation      = r.relation
                       AND t.user_type     = v_subject_type
                       AND t.user_relation IS NULL
                       -- keyset cursor: only candidates after the previous page.
                       AND (p_after IS NULL OR t.user_id > p_after)
                  UNION ALL
                    SELECT ct.user_id
                      FROM reach r
                      JOIN authz._ctx_tuples() ct
                        ON ct.object_type   = r.object_type
                       AND ct.object_id     IN (r.object_id, '*')
                       AND ct.relation      = r.relation
                       AND ct.user_type     = v_subject_type
                       AND ct.user_relation IS NULL
                     WHERE p_has_ctx
                       AND (p_after IS NULL OR ct.user_id > p_after)
                ) x
          ) c
         WHERE authz._decide(v_store_id, v_subject_type, c.subject_id, v_relation, v_object_type, p_object_id, context,
                             p_has_ctx_tuples => p_has_ctx, p_gates => v_gates)
         ORDER BY c.subject_id
         -- p_after (keyset) takes precedence over p_offset when supplied.
         OFFSET (CASE WHEN p_after IS NULL THEN p_offset ELSE 0 END)
         LIMIT p_limit;
END;
$$;

CREATE OR REPLACE FUNCTION authz.list_subjects(
    p_store        text,
    p_subject_type text,
    p_relation     text,
    p_object_type  text,
    p_object_id    text,
    context        jsonb DEFAULT NULL,
    p_limit        int DEFAULT NULL,
    p_offset       int DEFAULT 0,
    p_after        text DEFAULT NULL   -- keyset cursor: last subject_id of the previous page
) RETURNS TABLE (subject_id text, is_wildcard boolean)
LANGUAGE plpgsql STABLE AS $$
BEGIN
    RETURN QUERY SELECT * FROM authz._list_subjects(
        p_store, p_subject_type, p_relation, p_object_type, p_object_id, context, p_limit, p_offset, p_after, false);
END;
$$;

------------------------------------------------------------------------
-- list_subjects_with_contextual_tuples_jsonb: list_subjects with ephemeral
-- tuples for this call (see _load_contextual_tuples); authz_contextual_reader.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.list_subjects_with_contextual_tuples_jsonb(
    p_store             text,
    p_subject_type      text,
    p_relation          text,
    p_object_type       text,
    p_object_id         text,
    context             jsonb DEFAULT NULL,
    p_contextual_tuples jsonb DEFAULT NULL,
    p_limit             int DEFAULT NULL,
    p_offset            int DEFAULT 0,
    p_after             text DEFAULT NULL
) RETURNS TABLE (subject_id text, is_wildcard boolean)
LANGUAGE plpgsql AS $$
DECLARE
    v_has_ctx boolean := authz._load_contextual_tuples(authz._s(p_store), p_contextual_tuples);
BEGIN
    RETURN QUERY SELECT * FROM authz._list_subjects(
        p_store, p_subject_type, p_relation, p_object_type, p_object_id, context, p_limit, p_offset, p_after, v_has_ctx);
END;
$$;

------------------------------------------------------------------------
-- list_actions: find all permitted relations for a user on an object.
-- AuthZen Action Search: "What can user X do on object Z?"
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._list_actions(
    p_store       text,
    p_user_type   text,
    p_user_id     text,
    p_object_type text,
    p_object_id   text,
    context       jsonb,
    p_has_ctx     boolean
) RETURNS TABLE (action text)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id    integer := authz._s(p_store);
    v_user_type   integer := authz._t(v_store_id, p_user_type);
    v_object_type integer := authz._t(v_store_id, p_object_type);
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
         WHERE authz._decide(v_store_id, v_user_type, p_user_id, dr.relation, v_object_type, p_object_id, context,
                             p_has_ctx_tuples => p_has_ctx);
END;
$$;

CREATE OR REPLACE FUNCTION authz.list_actions(
    p_store       text,
    p_user_type   text,
    p_user_id     text,
    p_object_type text,
    p_object_id   text,
    context       jsonb DEFAULT NULL
) RETURNS TABLE (action text)
LANGUAGE plpgsql STABLE AS $$
BEGIN
    RETURN QUERY SELECT * FROM authz._list_actions(
        p_store, p_user_type, p_user_id, p_object_type, p_object_id, context, false);
END;
$$;

------------------------------------------------------------------------
-- list_actions_with_contextual_tuples_jsonb: list_actions with ephemeral
-- tuples for this call (see _load_contextual_tuples); authz_contextual_reader.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.list_actions_with_contextual_tuples_jsonb(
    p_store             text,
    p_user_type         text,
    p_user_id           text,
    p_object_type       text,
    p_object_id         text,
    context             jsonb DEFAULT NULL,
    p_contextual_tuples jsonb DEFAULT NULL
) RETURNS TABLE (action text)
LANGUAGE plpgsql AS $$
DECLARE
    v_has_ctx boolean := authz._load_contextual_tuples(authz._s(p_store), p_contextual_tuples);
BEGIN
    RETURN QUERY SELECT * FROM authz._list_actions(
        p_store, p_user_type, p_user_id, p_object_type, p_object_id, context, v_has_ctx);
END;
$$;

-- (find_redundant_tuples and cleanup_redundant_tuples moved to maintenance.sql)

------------------------------------------------------------------------
-- relation_usage: how full is a relation on one object (migration 0025)?
--
-- One row: the live DIRECT assignments on the object (what max_direct caps)
-- and the RESOLVED holder set (direct, usersets, inherited — what
-- max_effective is about), each with the declared cap and the headroom.
--
--   direct_count       active (unexpired) direct tuples on (object, relation),
--                      as written — exact, never bounded, so an object over
--                      a cap declared after the fact shows its real count
--   max_direct         the declared cap, NULL when none
--   direct_headroom    max_direct - direct_count (never below 0), NULL without a cap
--   effective_count    subjects that resolve to the relation on the object;
--                      NULL when unbounded
--   max_effective      the declared advisory cap, NULL when none
--   effective_headroom max_effective - effective_count, NULL without a cap or unbounded
--   unbounded          a wildcard (type:*) resolves to the relation: every
--                      subject of that type holds it, there is no count
--   limit_reached      the resolution stopped at the budget: effective_count
--                      is a lower bound ("at least")
--
-- The budget is p_limit, defaulting to max_effective when declared: finding
-- the Nth holder already says "no room". An application about to add k
-- holders passes max_effective - k + 1 and reads limit_reached as "would
-- exceed". Without a cap and without p_limit the resolution is exhaustive.
-- The resolved set is enumerated lazily per subject type (p_subject_type
-- narrows it to one; NULL walks every type of the store, cheapest first
-- is not knowable, so alphabetical) through the reverse expansion
-- list_subjects uses — the per-candidate check stops at the budget.
-- Contextual tuples are not part of the picture; the request context feeds
-- conditions as in list_subjects. Reader tier; namespace-checked.
--
--   SELECT * FROM authz.relation_usage('docs', 'document', 'plan', 'viewer');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.relation_usage(
    p_store        text,
    p_object_type  text,
    p_object_id    text,
    p_relation     text,
    p_limit        int  DEFAULT NULL,
    p_subject_type text DEFAULT NULL,
    context        jsonb DEFAULT NULL
) RETURNS TABLE (
    direct_count       bigint,
    max_direct         integer,
    direct_headroom    integer,
    effective_count    bigint,
    max_effective      integer,
    effective_headroom integer,
    unbounded          boolean,
    limit_reached      boolean
)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id    integer := authz._s(p_store);
    v_object_type integer := authz._t(v_store_id, p_object_type);
    v_relation    integer := authz._r(v_store_id, p_relation);
    v_budget      integer;
    v_remaining   integer;
    v_type        record;
    v_row         record;
BEGIN
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');
    IF p_limit IS NOT NULL AND p_limit < 1 THEN
        RAISE EXCEPTION 'relation_usage: p_limit must be at least 1, got %', p_limit
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_subject_type IS NOT NULL THEN
        PERFORM authz._t(v_store_id, p_subject_type);  -- raises 'Unknown type'
    END IF;

    SELECT c.max_direct, c.max_effective INTO max_direct, max_effective
      FROM authz.relation_constraints c
     WHERE c.store_id = v_store_id AND c.object_type = v_object_type AND c.relation = v_relation;

    -- Direct: active rows on this object (the wildcard object '*' is not this
    -- object's assignment; a capped relation has none). Exact: one index
    -- range count, never bounded — a cap declared below the current count
    -- must show the violation, and the budget is for the resolution below.
    v_budget := COALESCE(p_limit, max_effective);
    SELECT count(*) INTO direct_count
      FROM authz.tuples t
     WHERE t.store_id = v_store_id AND t.object_type = v_object_type
       AND t.object_id = p_object_id AND t.relation = v_relation
       AND (t.expires_at IS NULL OR t.expires_at > statement_timestamp());
    direct_headroom := CASE WHEN max_direct IS NULL THEN NULL ELSE GREATEST(max_direct - direct_count, 0) END;
    limit_reached := false;

    -- Effective: the reverse expansion per subject type, each call bounded
    -- by what is left of the budget; a wildcard row ends the count.
    effective_count := 0;
    unbounded := false;
    v_remaining := v_budget;
    FOR v_type IN
        SELECT t.name FROM authz.types t
         WHERE t.store_id = v_store_id
           AND (p_subject_type IS NULL OR t.name = p_subject_type)
         ORDER BY t.name
    LOOP
        EXIT WHEN v_remaining IS NOT NULL AND v_remaining <= 0;
        FOR v_row IN
            SELECT s.subject_id, s.is_wildcard
              FROM authz._list_subjects(p_store, v_type.name, p_relation, p_object_type, p_object_id,
                                        context, v_remaining, 0, NULL, false) s
        LOOP
            IF v_row.is_wildcard THEN
                unbounded := true;
                EXIT;
            END IF;
            effective_count := effective_count + 1;
        END LOOP;
        EXIT WHEN unbounded;
        IF v_budget IS NOT NULL THEN
            v_remaining := v_budget - effective_count;
        END IF;
    END LOOP;
    IF unbounded THEN
        effective_count := NULL;
        effective_headroom := NULL;
    ELSE
        IF v_budget IS NOT NULL AND effective_count >= v_budget THEN
            limit_reached := true;
        END IF;
        effective_headroom := CASE WHEN max_effective IS NULL THEN NULL ELSE GREATEST(max_effective - effective_count, 0) END;
    END IF;
    RETURN NEXT;
END;
$$;
