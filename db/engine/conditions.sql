-- Condition evaluation (ABAC): the read-side condition engine.
--
-- The language constants, the per-language dispatch, and the check-time
-- evaluators. These run on the access hot path (every conditional tuple), so
-- they are part of the SUBSTRATE profile — a read-only deployment needs them.
-- Condition MANAGEMENT (create/delete + the write-time validation trigger)
-- lives in conditions_admin.sql (write profile).
--
-- Depends on: schema.sql (authz.conditions), and the authz_eval sandbox role
-- (created in schema.sql). lang='cel' delegates to authz.cel_eval_bool from an
-- optional evaluator extension (extensions/pg-cel), resolved at runtime.

------------------------------------------------------------------------
-- Condition language constants — the `lang` tag on authz.conditions.
-- Use these instead of bare 'sql'/'cel' literals in engine code, the demo,
-- and tests. (The CHECK and DEFAULT on authz.conditions still spell the
-- literals out: they are resolved when schema.sql creates the table, before
-- this file loads — keep them in sync with these helpers.)
------------------------------------------------------------------------

-- SQL: built-in boolean expression over $1 (request) / $2 (stored) context,
-- evaluated in the zero-privilege authz_eval sandbox. The default; no deps.
CREATE OR REPLACE FUNCTION authz._cond_lang_sql() RETURNS text
    LANGUAGE sql IMMUTABLE AS $$ SELECT 'sql'::text $$;

-- CEL: Common Expression Language over request.* / stored.* variables,
-- evaluated by the optional cel_eval_bool extension (extensions/pg-cel).
CREATE OR REPLACE FUNCTION authz._cond_lang_cel() RETURNS text
    LANGUAGE sql IMMUTABLE AS $$ SELECT 'cel'::text $$;

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
-- _eval_condition_expr: single dispatch point for condition languages.
-- Given a condition's language tag, raw expression, and the request /
-- stored context bags, evaluates it to a boolean.
--
-- Today only 'sql' is supported (enforced by the CHECK on
-- authz.conditions.lang), evaluated in the zero-privilege authz_eval
-- sandbox via _exec_condition. Additional languages — cel, cedar, rego,
-- … — are added here as new CASE branches, each delegating to its own
-- executor (typically backed by an optional extension). The 'sql' branch
-- stays dependency-free; this is the one place to extend.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._eval_condition_expr(
    p_lang              text,
    p_expression        text,
    p_request_context   jsonb,
    p_condition_context jsonb
) RETURNS boolean
LANGUAGE plpgsql STABLE AS $$
BEGIN
    CASE p_lang
        WHEN authz._cond_lang_sql() THEN
            RETURN authz._exec_condition(p_expression, p_request_context, p_condition_context);
        WHEN authz._cond_lang_cel() THEN
            -- Delegate to the optional CEL evaluator (cel_eval_bool contract,
            -- e.g. the Rust/pgrx extensions/pg-cel). The two context bags are
            -- exposed to the expression as the CEL variables request.* and
            -- stored.*. A non-boolean / NULL result denies (fail-closed); an
            -- evaluator error propagates and is caught by the callers'
            -- exception handlers (also deny). lang='cel' rows can only exist
            -- when the evaluator was installed at write time.
            RETURN COALESCE(
                authz.cel_eval_bool(
                    p_expression,
                    jsonb_build_object('request', p_request_context,
                                       'stored',  p_condition_context)::text
                ),
                false);
        ELSE
            -- Unreachable while the CHECK permits only known languages; guards
            -- against a future language slipping in without a matching executor.
            RAISE EXCEPTION 'unsupported condition language: %', p_lang
                USING ERRCODE = 'feature_not_supported';
    END CASE;
END;
$$;

------------------------------------------------------------------------
-- _eval_condition: evaluates a condition expression against context.
-- Returns true if no condition (unconditional tuple) or condition passes.
-- Takes condition_id (PK) so no store scoping needed.
--
-- Security: the expression is evaluated via _eval_condition_expr →
-- _exec_condition which runs as authz_eval — a role with zero
-- table/function access. Only pure SQL operators and casts work inside
-- 'sql' expressions.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._eval_condition(
    p_condition_id      integer,
    p_condition_context jsonb,      -- stored with the tuple
    p_request_context   jsonb       -- passed at check time
) RETURNS boolean
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_expr   text;
    v_lang   text;
BEGIN
    -- No condition = unconditional access
    IF p_condition_id IS NULL THEN
        RETURN true;
    END IF;

    -- Optimistic pass (compositional tri-state, set only by
    -- check_access_detailed's second evaluation): a condition that would fail
    -- ONLY because its required context is missing is treated as PASSING, so
    -- the surrounding graph reveals whether supplying that context could flip
    -- the decision. A condition that evaluates to false with COMPLETE context
    -- still denies. Never set on a normal check — contained to the detailed
    -- classifier's transaction-local GUC.
    IF current_setting('authz._assume_missing_ctx', true) = 'on'
       AND array_length(
             authz._condition_missing_keys(p_condition_id, p_condition_context, p_request_context),
             1) > 0 THEN
        RETURN true;
    END IF;

    -- Bound context size (DoS guard, SECURITY-AUDIT F5): a caller-supplied
    -- request context (or a stored one) larger than authz.max_context_bytes
    -- is rejected before it is bound into condition evaluation. Raised with a
    -- dedicated errcode that is re-raised below (a clear error, not a silent
    -- deny). NULL contexts have NULL size, so the guard skips them.
    IF pg_column_size(p_request_context)   > authz._max_context_bytes()
       OR pg_column_size(p_condition_context) > authz._max_context_bytes() THEN
        RAISE EXCEPTION 'condition context exceeds the %-byte limit (authz.max_context_bytes)',
            authz._max_context_bytes()
            USING ERRCODE = 'program_limit_exceeded';
    END IF;

    SELECT expression, lang INTO v_expr, v_lang
      FROM authz.conditions WHERE id = p_condition_id;
    IF v_expr IS NULL THEN
        RETURN false;  -- unknown condition = deny
    END IF;

    RETURN authz._eval_condition_expr(
        v_lang,
        v_expr,
        COALESCE(p_request_context, '{}'::jsonb),
        COALESCE(p_condition_context, '{}'::jsonb)
    );
EXCEPTION
    WHEN query_canceled THEN
        RAISE;         -- statement_timeout / cancel must abort the check (fail
                       -- closed as an error), never be swallowed into a silent
                       -- deny — this is what bounds a runaway condition
    WHEN program_limit_exceeded THEN
        RAISE;         -- the context-size guard (F5) surfaces as a clear error,
                       -- not a silent deny — the input is malformed, not denied
    WHEN OTHERS THEN
        RETURN false;  -- genuine condition evaluation error = deny
END;
$$;

------------------------------------------------------------------------
-- _condition_missing_keys: given a condition and the contexts available
-- at check time, returns the required_context keys that were NOT
-- supplied (prefixed request./stored.). Empty when all required keys
-- are present — i.e. a denial with no missing keys means the condition
-- evaluated to false on the given inputs, not that inputs were absent.
-- Used by explain_access to annotate condition_denied trace steps.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._condition_missing_keys(
    p_condition_id      integer,
    p_condition_context jsonb,
    p_request_context   jsonb
) RETURNS text[]
LANGUAGE sql STABLE AS $$
    SELECT coalesce(array_agg(missing ORDER BY missing), '{}')
      FROM authz.conditions c
      CROSS JOIN LATERAL (
          SELECT 'request.' || k AS missing
            FROM jsonb_array_elements_text(c.required_context->'request') AS k
           WHERE NOT (coalesce(p_request_context, '{}'::jsonb) ? k)
          UNION ALL
          SELECT 'stored.' || k
            FROM jsonb_array_elements_text(c.required_context->'stored') AS k
           WHERE NOT (coalesce(p_condition_context, '{}'::jsonb) ? k)
      ) m
     WHERE c.id = p_condition_id;
$$;
