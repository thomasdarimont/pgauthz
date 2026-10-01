-- Condition management (write API): create / delete named conditions, plus the
-- write-time validation trigger that test-compiles an expression before storing
-- it. Part of the WRITE profile — a read-only deployment omits it (conditions
-- arrive via replication, already validated upstream; replication apply does
-- not fire the validation trigger).
--
-- Depends on: schema.sql (authz.conditions), conditions.sql (authz._exec_condition,
-- authz._cond_lang_sql/_cel), and core_internal.sql (authz._s). lang='cel'
-- validation uses authz.cel_compile_check from the optional pg_cel extension.

-- Reject a condition whose expression cannot compile. A malformed or
-- unresolvable expression (SQLSTATE class 42 — syntax error, unknown
-- function/column/table, type mismatch, or an attempt to touch a table
-- the sandbox can't see) would otherwise insert successfully and then
-- silently fail closed (deny) at every check. We test-compile it once at
-- write time in the same sandbox used at check time: _exec_condition runs
-- as the zero-privilege authz_eval role, so validating an untrusted
-- expression cannot itself do harm. Empty context is passed, so only
-- compile-time errors are caught; data-dependent runtime errors (class 22,
-- e.g. a cast that fails only on certain inputs) are legitimate and remain
-- deny-at-check, not write-time rejections.
--
-- SECURITY DEFINER so the trigger (whoever runs the INSERT) can reach
-- _exec_condition; the expression still executes only as authz_eval.
CREATE OR REPLACE FUNCTION authz._validate_condition_expression() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    -- Validation is language-specific (SQL test-compiles by executing; CEL
    -- parse/type-checks via the evaluator). Dispatch on NEW.lang; the CHECK
    -- constraint restricts lang to the known set, so the ELSE is defensive.
    CASE NEW.lang
        WHEN authz._cond_lang_sql() THEN
            BEGIN
                PERFORM authz._exec_condition(NEW.expression, '{}'::jsonb, '{}'::jsonb);
            EXCEPTION
                WHEN syntax_error_or_access_rule_violation THEN  -- SQLSTATE class 42
                    RAISE EXCEPTION 'condition "%" has an invalid expression: %', NEW.name, SQLERRM
                        USING ERRCODE = 'invalid_parameter_value',
                              HINT = 'Expression must be a valid SQL boolean over $1 (request) and $2 (stored) context.';
            END;
        WHEN authz._cond_lang_cel() THEN
            -- CEL needs the optional evaluator extension (cel_eval_bool /
            -- cel_compile_check contract, e.g. extensions/pg-cel). Refuse to
            -- store a lang='cel' condition that could never be evaluated:
            -- gate on the contract function existing (works for any provider).
            IF to_regprocedure('authz.cel_compile_check(text)') IS NULL THEN
                RAISE EXCEPTION 'condition "%" uses lang=cel but no CEL evaluator is installed', NEW.name
                    USING ERRCODE = 'feature_not_supported',
                          HINT = 'Install a CEL evaluator extension (e.g. pg_cel from extensions/pg-cel) to enable CEL conditions.';
            END IF;
            -- Compile-check the expression up front; the evaluator raises on a
            -- malformed expression, mirroring the 'sql' write-time guard. This
            -- is a PARSE check only — undeclared variables, type mismatches, and
            -- bad value formats (e.g. a Postgres interval where CEL duration()
            -- wants "2h") are not caught here; they surface at evaluation and
            -- deny. Use authz.validate_condition to exercise them with sample
            -- context.
            BEGIN
                PERFORM authz.cel_compile_check(NEW.expression);
            EXCEPTION
                WHEN OTHERS THEN
                    RAISE EXCEPTION 'condition "%" has an invalid CEL expression: %', NEW.name, SQLERRM
                        USING ERRCODE = 'invalid_parameter_value',
                              HINT = 'Expression must be a valid CEL boolean over request.* and stored.*';
            END;
        ELSE
            RAISE EXCEPTION 'condition "%" uses unsupported language "%"', NEW.name, NEW.lang
                USING ERRCODE = 'feature_not_supported',
                      HINT = 'Supported condition languages: sql, cel.';
    END CASE;
    RETURN NEW;
END;
$$;

-- CREATE OR REPLACE so re-running the installer (migrate-then-load) is idempotent.
CREATE OR REPLACE TRIGGER trg_conditions_validate_expression
    BEFORE INSERT OR UPDATE ON authz.conditions
    FOR EACH ROW EXECUTE FUNCTION authz._validate_condition_expression();

------------------------------------------------------------------------
-- create_condition: create or replace a named condition for a store.
--
-- The function API counterpart to a raw INSERT INTO authz.conditions — so
-- callers manage conditions through SECURITY DEFINER (no direct table access),
-- consistent with model_add_rule and friends. Upsert: re-running with the same
-- name updates the expression/lang/required_context (an actual change is
-- versioned in conditions_audit; an identical call is a no-op, so it does not
-- pollute the time-travel history). The validation trigger still runs, so an
-- invalid SQL/CEL expression — or lang='cel' without the evaluator installed —
-- is rejected here too. Returns the condition id.
--
-- Note: that write-time check is parse-only (SQL syntax / CEL compile). Value
-- formats and variable bindings — e.g. a CEL duration() expecting "2h" rather
-- than a Postgres interval "2 hours" — are only caught at evaluation (and deny
-- closed). Dry-run with authz.validate_condition(store, name, stored_context,
-- request_context) to exercise them against representative values.
--
--   SELECT authz.create_condition('demo', 'office_hours',
--       $$extract(hour from ($1->>'current_time')::timestamptz) BETWEEN 8 AND 17$$);
------------------------------------------------------------------------
-- p_time_source (migration 0016): where `current_time` comes from for this
-- condition — 'server' (default: the engine's clock; a caller value is
-- ignored) or 'caller' (the request context; replayable, the caller's
-- assertion — the explicit choice for tests, demos and "as of T" questions).
-- Part of the policy: versioned, exported, rendered.
DROP FUNCTION IF EXISTS authz.create_condition(text, text, text, text, jsonb);
CREATE OR REPLACE FUNCTION authz.create_condition(
    p_store            text,
    p_name             text,
    p_expression       text,
    p_lang             text  DEFAULT authz._cond_lang_sql(),
    p_required_context jsonb DEFAULT NULL,
    p_time_source      text  DEFAULT 'server'
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_id       integer;
BEGIN
    IF p_time_source IS NULL OR p_time_source NOT IN ('caller', 'server') THEN
        RAISE EXCEPTION 'condition "%": time_source must be caller or server (got %)', p_name, COALESCE(p_time_source, 'NULL')
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    INSERT INTO authz.conditions (store_id, name, expression, lang, required_context, time_source)
    VALUES (v_store_id, p_name, p_expression, p_lang, p_required_context, p_time_source)
    ON CONFLICT (store_id, name) DO UPDATE
        SET expression       = EXCLUDED.expression,
            lang             = EXCLUDED.lang,
            required_context = EXCLUDED.required_context,
            time_source      = EXCLUDED.time_source
        -- Skip a no-op rewrite so an unchanged re-run adds no audit version.
        WHERE authz.conditions.expression       IS DISTINCT FROM EXCLUDED.expression
           OR authz.conditions.lang             IS DISTINCT FROM EXCLUDED.lang
           OR authz.conditions.required_context IS DISTINCT FROM EXCLUDED.required_context
           OR authz.conditions.time_source      IS DISTINCT FROM EXCLUDED.time_source
    RETURNING id INTO v_id;

    -- DO UPDATE ... WHERE that matched nothing (identical re-run) returns no
    -- row; fetch the existing id so the call still resolves to the condition.
    IF v_id IS NULL THEN
        SELECT id INTO v_id
          FROM authz.conditions
         WHERE store_id = v_store_id AND name = p_name;
    END IF;

    RETURN v_id;
END;
$$;

------------------------------------------------------------------------
-- create_condition_sql / create_condition_cel: convenience wrappers that
-- fix the language, so callers don't pass the lang argument (and don't
-- spell out a literal). create_condition_sql is create_condition with the
-- default language; create_condition_cel writes a CEL condition (requires
-- the pg_cel evaluator — see extensions/pg-cel). Both delegate to
-- create_condition, so the same validation/audit/upsert behaviour applies.
--
--   SELECT authz.create_condition_cel('demo', 'not_expired',
--       'timestamp(request.now) < timestamp(stored.expires)',
--       '{"request": ["now"], "stored": ["expires"]}');
------------------------------------------------------------------------
DROP FUNCTION IF EXISTS authz.create_condition_sql(text, text, text, jsonb);
CREATE OR REPLACE FUNCTION authz.create_condition_sql(
    p_store            text,
    p_name             text,
    p_expression       text,
    p_required_context jsonb DEFAULT NULL,
    p_time_source      text  DEFAULT 'server'
) RETURNS integer
LANGUAGE sql AS $$
    SELECT authz.create_condition(p_store, p_name, p_expression,
                                  authz._cond_lang_sql(), p_required_context, p_time_source);
$$;

DROP FUNCTION IF EXISTS authz.create_condition_cel(text, text, text, jsonb);
CREATE OR REPLACE FUNCTION authz.create_condition_cel(
    p_store            text,
    p_name             text,
    p_expression       text,
    p_required_context jsonb DEFAULT NULL,
    p_time_source      text  DEFAULT 'server'
) RETURNS integer
LANGUAGE sql AS $$
    SELECT authz.create_condition(p_store, p_name, p_expression,
                                  authz._cond_lang_cel(), p_required_context, p_time_source);
$$;

------------------------------------------------------------------------
-- delete_condition: remove a named condition from a store. Returns true if
-- a condition was deleted, false if it did not exist. The removal is logged
-- to conditions_audit. There is no FK from tuples, so any tuple that still
-- references the deleted condition simply denies at check time (fail closed),
-- which is the safe outcome of revoking a condition definition.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.delete_condition(
    p_store text,
    p_name  text
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_count    int;
    v_refs     int;
BEGIN
    -- A condition bound to type-restriction facets (migration 0015) cannot be
    -- dropped from under them: the facet would silently stop requiring it.
    SELECT count(*) INTO v_refs
      FROM authz.type_restrictions tr
      JOIN authz.conditions c ON c.id = tr.condition_id
     WHERE c.store_id = v_store_id AND c.name = p_name;
    IF v_refs > 0 THEN
        RAISE EXCEPTION 'condition "%" is required by % type restriction facet(s) in store "%" — remove those facets first (model_remove_type_restriction)',
            p_name, v_refs, p_store
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    DELETE FROM authz.conditions
     WHERE store_id = v_store_id
       AND name = p_name;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count > 0;
END;
$$;
