-- Internal access check functions: contextual tuple helpers, direct/TTU
-- evaluation, rule dispatcher, and the recursive _check_access engine.
-- These use integer IDs for performance and are not meant to be called directly.
--
-- Depends on: engine/core_internal.sql (must be loaded first)

------------------------------------------------------------------------
-- Contextual tuple helpers: dynamic SQL against ephemeral temp table.
-- Separated to avoid parse-time errors when the temp table doesn't exist.
-- Not store-scoped — contextual tuples are session-local.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._check_ctx_direct(
    p_user_type   smallint,
    p_user_id     text,
    p_relation    smallint,
    p_object_type smallint,
    p_object_id   text
) RETURNS boolean
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_found boolean;
BEGIN
    EXECUTE '
        SELECT EXISTS (
            SELECT 1 FROM pg_temp.ctx_tuples
             WHERE object_type   = $1
               AND object_id     = $2
               AND relation      = $3
               AND user_type     = $4
               AND user_id       IN ($5, ''*'')
               AND user_relation IS NULL
        )'
    INTO v_found
    USING p_object_type, p_object_id, p_relation, p_user_type, p_user_id;
    RETURN v_found;
END;
$$;

CREATE OR REPLACE FUNCTION authz._check_ctx_usersets(
    p_relation    smallint,
    p_object_type smallint,
    p_object_id   text
) RETURNS TABLE (user_type smallint, user_id text, user_relation smallint)
LANGUAGE plpgsql STABLE AS $$
BEGIN
    RETURN QUERY EXECUTE '
        SELECT user_type, user_id, user_relation
          FROM pg_temp.ctx_tuples
         WHERE object_type   = $1
           AND object_id     = $2
           AND relation      = $3
           AND user_relation IS NOT NULL'
    USING p_object_type, p_object_id, p_relation;
END;
$$;

CREATE OR REPLACE FUNCTION authz._check_ctx_linked(
    p_tupleset_relation smallint,
    p_object_type       smallint,
    p_object_id         text
) RETURNS TABLE (linked_type smallint, linked_id text)
LANGUAGE plpgsql STABLE AS $$
BEGIN
    RETURN QUERY EXECUTE '
        SELECT user_type, user_id
          FROM pg_temp.ctx_tuples
         WHERE object_type   = $1
           AND object_id     = $2
           AND relation      = $3
           AND user_relation IS NULL'
    USING p_object_type, p_object_id, p_tupleset_relation;
END;
$$;

------------------------------------------------------------------------
-- _eval_direct: evaluates a DIRECT model rule — exact tuple match,
-- wildcard match, condition evaluation, contextual tuples, and
-- userset expansion. Writes trace steps when p_trace is true.
--
-- Called by _eval_rule; trace name lookups are done once in the
-- dispatcher and passed in to avoid redundant queries.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._eval_direct(
    p_store_id          smallint,
    p_user_type         smallint,
    p_user_id           text,
    p_relation          smallint,
    p_object_type       smallint,
    p_object_id         text,
    p_request_context   jsonb,
    p_has_ctx_tuples    boolean,
    p_depth             int,
    p_trace             boolean,
    p_user_type_name    text,
    p_relation_name     text,
    p_object_type_name  text,
    p_step_start        timestamptz,
    p_exclude           authz._tuple_key DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    tpl     record;
    v_child boolean;
    v_cond_name text;
    v_skip_direct boolean := false;
BEGIN
    -- If this exact tuple is excluded (used by find_redundant_tuples),
    -- skip the direct match but still check userset/contextual paths.
    v_skip_direct := (
        p_exclude IS NOT NULL
        AND p_user_type   = (p_exclude).user_type
        AND p_user_id     = (p_exclude).user_id
        AND p_relation    = (p_exclude).relation
        AND p_object_type = (p_exclude).object_type
        AND p_object_id   = (p_exclude).object_id
    );

    IF NOT v_skip_direct THEN
    -- Direct tuple check: fast path for unconditional tuples, then conditional
    IF EXISTS (
        SELECT 1 FROM authz.tuples
         WHERE store_id      = p_store_id
           AND object_type   = p_object_type
           AND object_id     = p_object_id
           AND relation      = p_relation
           AND user_type     = p_user_type
           AND user_id       = p_user_id
           AND user_relation IS NULL
           AND condition_id  IS NULL
    ) OR EXISTS (
        SELECT 1 FROM authz.tuples
         WHERE store_id      = p_store_id
           AND object_type   = p_object_type
           AND object_id     = p_object_id
           AND relation      = p_relation
           AND user_type     = p_user_type
           AND user_id       = p_user_id
           AND user_relation IS NULL
           AND condition_id  IS NOT NULL
           AND authz._eval_condition(condition_id, condition_context, p_request_context)
    ) THEN
        IF p_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
            VALUES (p_depth, 'direct', p_user_type_name || ':' || p_user_id,
                    p_relation_name, p_object_type_name || ':' || p_object_id,
                    true, 'tuple found',
                    extract(epoch from clock_timestamp() - p_step_start) * 1000);
        END IF;
        RETURN true;
    END IF;

    -- Wildcard tuple check (user_type:*): fast path then conditional
    IF EXISTS (
        SELECT 1 FROM authz.tuples
         WHERE store_id      = p_store_id
           AND object_type   = p_object_type
           AND object_id     = p_object_id
           AND relation      = p_relation
           AND user_type     = p_user_type
           AND user_id       = '*'
           AND user_relation IS NULL
           AND condition_id  IS NULL
    ) OR EXISTS (
        SELECT 1 FROM authz.tuples
         WHERE store_id      = p_store_id
           AND object_type   = p_object_type
           AND object_id     = p_object_id
           AND relation      = p_relation
           AND user_type     = p_user_type
           AND user_id       = '*'
           AND user_relation IS NULL
           AND condition_id  IS NOT NULL
           AND authz._eval_condition(condition_id, condition_context, p_request_context)
    ) THEN
        IF p_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
            VALUES (p_depth, 'direct', p_user_type_name || ':' || p_user_id,
                    p_relation_name, p_object_type_name || ':' || p_object_id,
                    true, 'wildcard tuple (*)',
                    extract(epoch from clock_timestamp() - p_step_start) * 1000);
        END IF;
        RETURN true;
    END IF;

    -- Trace: tuple exists but condition denied it
    IF p_trace AND EXISTS (
        SELECT 1 FROM authz.tuples
         WHERE store_id      = p_store_id
           AND object_type   = p_object_type
           AND object_id     = p_object_id
           AND relation      = p_relation
           AND user_type     = p_user_type
           AND user_id       IN (p_user_id, '*')
           AND user_relation IS NULL
           AND condition_id  IS NOT NULL
    ) THEN
        SELECT c.name INTO v_cond_name
          FROM authz.tuples t
          JOIN authz.conditions c ON c.id = t.condition_id
         WHERE t.store_id      = p_store_id
           AND t.object_type   = p_object_type
           AND t.object_id     = p_object_id
           AND t.relation      = p_relation
           AND t.user_type     = p_user_type
           AND t.user_id       IN (p_user_id, '*')
           AND t.user_relation IS NULL
         LIMIT 1;
        INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
        VALUES (p_depth, 'direct', p_user_type_name || ':' || p_user_id,
                p_relation_name, p_object_type_name || ':' || p_object_id,
                false, 'tuple found, condition "' || v_cond_name || '" denied',
                extract(epoch from clock_timestamp() - p_step_start) * 1000);
    END IF;
    END IF; -- v_skip_direct

    -- Check contextual tuples (via dynamic SQL to avoid parse-time error)
    IF p_has_ctx_tuples AND authz._check_ctx_direct(
        p_user_type, p_user_id, p_relation, p_object_type, p_object_id
    ) THEN
        IF p_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
            VALUES (p_depth, 'direct', p_user_type_name || ':' || p_user_id,
                    p_relation_name, p_object_type_name || ':' || p_object_id,
                    true, 'contextual tuple',
                    extract(epoch from clock_timestamp() - p_step_start) * 1000);
        END IF;
        RETURN true;
    END IF;

    -- Userset expansion (stored tuples): unconditional first, then conditional
    FOR tpl IN
        SELECT user_type, user_id, user_relation
          FROM authz.tuples
         WHERE store_id      = p_store_id
           AND object_type   = p_object_type
           AND object_id     = p_object_id
           AND relation      = p_relation
           AND user_relation IS NOT NULL
           AND condition_id  IS NULL
    LOOP
        v_child := authz._check_access(
            p_store_id,
            p_user_type, p_user_id,
            tpl.user_relation,
            tpl.user_type, tpl.user_id,
            p_request_context, p_has_ctx_tuples,
            p_depth + 1, p_trace,
            p_exclude
        );
        IF p_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
            VALUES (p_depth, 'userset', p_user_type_name || ':' || p_user_id,
                    p_relation_name, p_object_type_name || ':' || p_object_id,
                    v_child,
                    'expand ' || (SELECT name FROM authz.types WHERE id = tpl.user_type)
                    || ':' || tpl.user_id || '#'
                    || (SELECT name FROM authz.relations WHERE id = tpl.user_relation),
                    extract(epoch from clock_timestamp() - p_step_start) * 1000);
        END IF;
        IF v_child THEN
            RETURN true;
        END IF;
    END LOOP;

    -- Userset expansion (stored conditional tuples)
    FOR tpl IN
        SELECT user_type, user_id, user_relation
          FROM authz.tuples
         WHERE store_id      = p_store_id
           AND object_type   = p_object_type
           AND object_id     = p_object_id
           AND relation      = p_relation
           AND user_relation IS NOT NULL
           AND condition_id  IS NOT NULL
           AND authz._eval_condition(condition_id, condition_context, p_request_context)
    LOOP
        v_child := authz._check_access(
            p_store_id,
            p_user_type, p_user_id,
            tpl.user_relation,
            tpl.user_type, tpl.user_id,
            p_request_context, p_has_ctx_tuples,
            p_depth + 1, p_trace,
            p_exclude
        );
        IF p_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
            VALUES (p_depth, 'userset', p_user_type_name || ':' || p_user_id,
                    p_relation_name, p_object_type_name || ':' || p_object_id,
                    v_child,
                    'expand ' || (SELECT name FROM authz.types WHERE id = tpl.user_type)
                    || ':' || tpl.user_id || '#'
                    || (SELECT name FROM authz.relations WHERE id = tpl.user_relation),
                    extract(epoch from clock_timestamp() - p_step_start) * 1000);
        END IF;
        IF v_child THEN
            RETURN true;
        END IF;
    END LOOP;

    -- Userset expansion (contextual tuples)
    IF p_has_ctx_tuples THEN
        FOR tpl IN
            SELECT * FROM authz._check_ctx_usersets(p_relation, p_object_type, p_object_id)
        LOOP
            v_child := authz._check_access(
                p_store_id,
                p_user_type, p_user_id,
                tpl.user_relation,
                tpl.user_type, tpl.user_id,
                p_request_context, p_has_ctx_tuples,
                p_depth + 1, p_trace,
                p_exclude
            );
            IF p_trace THEN
                INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
                VALUES (p_depth, 'userset', p_user_type_name || ':' || p_user_id,
                        p_relation_name, p_object_type_name || ':' || p_object_id,
                        v_child, 'expand contextual userset',
                        extract(epoch from clock_timestamp() - p_step_start) * 1000);
            END IF;
            IF v_child THEN
                RETURN true;
            END IF;
        END LOOP;
    END IF;

    -- No direct tuple found (trace the miss, unless we already
    -- traced a condition denial above for this same relation)
    IF p_trace AND NOT EXISTS (
        SELECT 1 FROM authz.tuples
         WHERE store_id      = p_store_id
           AND object_type   = p_object_type
           AND object_id     = p_object_id
           AND relation      = p_relation
           AND user_type     = p_user_type
           AND user_id       IN (p_user_id, '*')
           AND user_relation IS NULL
    ) THEN
        INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
        VALUES (p_depth, 'direct', p_user_type_name || ':' || p_user_id,
                p_relation_name, p_object_type_name || ':' || p_object_id,
                false, 'no tuple',
                extract(epoch from clock_timestamp() - p_step_start) * 1000);
    END IF;

    RETURN false;
END;
$$;

------------------------------------------------------------------------
-- _eval_ttu: evaluates a TUPLE-TO-USERSET model rule — follows stored
-- and contextual linked objects via tupleset_relation, then recursively
-- checks tupleset_computed on each linked object.
-- Writes trace steps when p_trace is true.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._eval_ttu(
    p_store_id          smallint,
    p_user_type         smallint,
    p_user_id           text,
    p_relation          smallint,
    p_object_type       smallint,
    p_object_id         text,
    p_tupleset_relation smallint,
    p_tupleset_computed smallint,
    p_request_context   jsonb,
    p_has_ctx_tuples    boolean,
    p_depth             int,
    p_trace             boolean,
    p_user_type_name    text,
    p_relation_name     text,
    p_object_type_name  text,
    p_step_start        timestamptz,
    p_exclude           authz._tuple_key DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    tpl     record;
    v_child boolean;
BEGIN
    -- Follow stored tuples. Conditional link tuples are only followed
    -- when their condition passes — an expired/denied link must not
    -- confer inherited access.
    FOR tpl IN
        SELECT user_type AS linked_type, user_id AS linked_id
          FROM authz.tuples
         WHERE store_id      = p_store_id
           AND object_type   = p_object_type
           AND object_id     = p_object_id
           AND relation      = p_tupleset_relation
           AND user_relation IS NULL
           AND (condition_id IS NULL
                OR authz._eval_condition(condition_id, condition_context, p_request_context))
    LOOP
        v_child := authz._check_access(
            p_store_id,
            p_user_type, p_user_id,
            p_tupleset_computed,
            tpl.linked_type, tpl.linked_id,
            p_request_context, p_has_ctx_tuples,
            p_depth + 1, p_trace,
            p_exclude
        );
        IF p_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
            VALUES (p_depth, 'ttu', p_user_type_name || ':' || p_user_id,
                    p_relation_name, p_object_type_name || ':' || p_object_id,
                    v_child,
                    p_relation_name || ' ← '
                    || (SELECT name FROM authz.relations WHERE id = p_tupleset_computed)
                    || ' on '
                    || (SELECT name FROM authz.types WHERE id = tpl.linked_type)
                    || ':' || tpl.linked_id
                    || ' (via '
                    || (SELECT name FROM authz.relations WHERE id = p_tupleset_relation)
                    || ')',
                    extract(epoch from clock_timestamp() - p_step_start) * 1000);
        END IF;
        IF v_child THEN
            RETURN true;
        END IF;
    END LOOP;

    -- Follow contextual tuples
    IF p_has_ctx_tuples THEN
        FOR tpl IN
            SELECT * FROM authz._check_ctx_linked(p_tupleset_relation, p_object_type, p_object_id)
        LOOP
            v_child := authz._check_access(
                p_store_id,
                p_user_type, p_user_id,
                p_tupleset_computed,
                tpl.linked_type, tpl.linked_id,
                p_request_context, p_has_ctx_tuples,
                p_depth + 1, p_trace,
                p_exclude
            );
            IF p_trace THEN
                INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
                VALUES (p_depth, 'ttu', p_user_type_name || ':' || p_user_id,
                        p_relation_name, p_object_type_name || ':' || p_object_id,
                        v_child,
                        p_relation_name || ' ← '
                        || (SELECT name FROM authz.relations WHERE id = p_tupleset_computed)
                        || ' on ctx:'
                        || tpl.linked_id
                        || ' (via '
                        || (SELECT name FROM authz.relations WHERE id = p_tupleset_relation)
                        || ')',
                        extract(epoch from clock_timestamp() - p_step_start) * 1000);
            END IF;
            IF v_child THEN
                RETURN true;
            END IF;
        END LOOP;
    END IF;

    -- No linked objects found (trace the miss)
    IF p_trace AND NOT EXISTS (
        SELECT 1 FROM authz.tuples
         WHERE store_id      = p_store_id
           AND object_type   = p_object_type
           AND object_id     = p_object_id
           AND relation      = p_tupleset_relation
           AND user_relation IS NULL
    ) THEN
        INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
        VALUES (p_depth, 'ttu', p_user_type_name || ':' || p_user_id,
                p_relation_name, p_object_type_name || ':' || p_object_id,
                false,
                'no ' || (SELECT name FROM authz.relations WHERE id = p_tupleset_relation) || ' link',
                extract(epoch from clock_timestamp() - p_step_start) * 1000);
    END IF;

    RETURN false;
END;
$$;

------------------------------------------------------------------------
-- _eval_rule: thin dispatcher that resolves trace names once, then
-- delegates to _eval_direct, inline COMPUTED, or _eval_ttu.
--
-- Handles all three rule types: direct, computed, tuple-to-userset.
-- Writes trace steps when p_trace is true.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._eval_rule(
    p_store_id          smallint,
    p_user_type         smallint,
    p_user_id           text,
    p_relation          smallint,
    p_object_type       smallint,
    p_object_id         text,
    p_rule_type         smallint,
    p_computed_relation smallint,
    p_tupleset_relation smallint,
    p_tupleset_computed smallint,
    p_request_context   jsonb DEFAULT NULL,
    p_has_ctx_tuples    boolean DEFAULT false,
    p_depth             int DEFAULT 0,
    p_trace             boolean DEFAULT false,
    p_exclude           authz._tuple_key DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_child boolean;

    -- Tracing helpers (resolved once, passed to sub-functions)
    v_user_type_name   text;
    v_relation_name    text;
    v_object_type_name text;
    v_step_start       timestamptz;
BEGIN
    IF p_trace THEN
        SELECT name INTO v_user_type_name   FROM authz.types     WHERE id = p_user_type;
        SELECT name INTO v_relation_name    FROM authz.relations WHERE id = p_relation;
        SELECT name INTO v_object_type_name FROM authz.types     WHERE id = p_object_type;
        v_step_start := clock_timestamp();
    END IF;

    CASE p_rule_type

    WHEN authz._rel_direct() THEN
        RETURN authz._eval_direct(
            p_store_id, p_user_type, p_user_id, p_relation, p_object_type, p_object_id,
            p_request_context, p_has_ctx_tuples, p_depth, p_trace,
            v_user_type_name, v_relation_name, v_object_type_name, v_step_start,
            p_exclude
        );

    WHEN authz._rel_computed() THEN
        v_child := authz._check_access(
            p_store_id,
            p_user_type, p_user_id,
            p_computed_relation,
            p_object_type, p_object_id,
            p_request_context, p_has_ctx_tuples,
            p_depth + 1, p_trace,
            p_exclude
        );
        IF p_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
            VALUES (p_depth, 'computed', v_user_type_name || ':' || p_user_id,
                    v_relation_name, v_object_type_name || ':' || p_object_id,
                    v_child,
                    v_relation_name || ' ← '
                    || (SELECT name FROM authz.relations WHERE id = p_computed_relation),
                    extract(epoch from clock_timestamp() - v_step_start) * 1000);
        END IF;
        RETURN v_child;

    WHEN authz._rel_ttu() THEN
        RETURN authz._eval_ttu(
            p_store_id, p_user_type, p_user_id, p_relation, p_object_type, p_object_id,
            p_tupleset_relation, p_tupleset_computed,
            p_request_context, p_has_ctx_tuples, p_depth, p_trace,
            v_user_type_name, v_relation_name, v_object_type_name, v_step_start,
            p_exclude
        );

    END CASE;

    RETURN false;
END;
$$;

------------------------------------------------------------------------
-- _check_access: internal recursive check using integer IDs.
-- Supports contextual tuples (temp table) and conditions (ABAC).
--
-- Rules are organized into groups (group_id). Within a group:
--   OR (default):  any rule match grants access
--   Intersection:  all rules must match
--   Exclusion:     base rules must match AND negated rules must NOT
-- Groups are OR'd: if any group grants access, the check passes.
--
-- Tracing: when the session variable 'authz.trace' is set to 'on',
-- _check_access writes a step-by-step resolution trace into the temp
-- table pg_temp._access_trace. The caller must create this table first.
--
-- For convenience, use authz.explain_access(...) instead.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._check_access(
    p_store_id        smallint,
    p_user_type       smallint,
    p_user_id         text,
    p_relation        smallint,
    p_object_type     smallint,
    p_object_id       text,
    p_request_context jsonb DEFAULT NULL,
    p_has_ctx_tuples  boolean DEFAULT false,
    p_depth           int DEFAULT 0,
    p_trace           boolean DEFAULT NULL,
    p_exclude         authz._tuple_key DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    rule            record;
    v_trace         boolean := p_trace;
    v_group_pass    boolean;
    v_group_start   timestamptz;

    -- Group boundary tracking
    v_cur_group     smallint := -1;
    v_cur_group_op  smallint;

    -- Name resolution helpers (only used when tracing)
    v_user_type_name   text;
    v_relation_name    text;
    v_object_type_name text;
BEGIN
    IF p_depth > authz._max_depth() THEN
        RETURN false;
    END IF;

    -- At the root call, decide whether to trace based on session variable.
    IF v_trace IS NULL THEN
        v_trace := (current_setting('authz.trace', true) = 'on');
    END IF;

    -- Resolve names once if tracing.
    IF v_trace THEN
        SELECT name INTO v_user_type_name   FROM authz.types     WHERE id = p_user_type;
        SELECT name INTO v_relation_name    FROM authz.relations WHERE id = p_relation;
        SELECT name INTO v_object_type_name FROM authz.types     WHERE id = p_object_type;
    END IF;

    -- Single query: fetch all rules ordered by group, with base rules before negated.
    FOR rule IN
        SELECT rule_type, computed_relation, tupleset_relation, tupleset_computed,
               group_id, group_op, negated
          FROM authz.models
         WHERE store_id    = p_store_id
           AND object_type = p_object_type
           AND relation    = p_relation
         ORDER BY group_id, negated  -- false < true: base rules first
    LOOP
        -- Detect group boundary.
        IF rule.group_id <> v_cur_group THEN
            -- Finalize previous group (intersection/exclusion need end-of-group check).
            IF v_cur_group >= 0 AND v_group_pass AND v_cur_group_op <> authz._combine_or() THEN
                IF v_trace THEN
                    INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
                    VALUES (p_depth,
                            CASE v_cur_group_op WHEN authz._combine_and() THEN 'intersection' ELSE 'exclusion' END,
                            v_user_type_name || ':' || p_user_id,
                            v_relation_name, v_object_type_name || ':' || p_object_id,
                            true,
                            CASE v_cur_group_op WHEN authz._combine_and() THEN 'all rules matched' ELSE 'base matched, not excluded' END,
                            extract(epoch from clock_timestamp() - v_group_start) * 1000);
                END IF;
                RETURN true;
            END IF;
            -- Trace failed intersection/exclusion.
            IF v_trace AND v_cur_group >= 0 AND NOT v_group_pass AND v_cur_group_op <> authz._combine_or() THEN
                INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
                VALUES (p_depth,
                        CASE v_cur_group_op WHEN authz._combine_and() THEN 'intersection' ELSE 'exclusion' END,
                        v_user_type_name || ':' || p_user_id,
                        v_relation_name, v_object_type_name || ':' || p_object_id,
                        false,
                        CASE v_cur_group_op WHEN authz._combine_and() THEN 'not all rules matched' ELSE 'base not matched or excluded' END,
                        extract(epoch from clock_timestamp() - v_group_start) * 1000);
            END IF;

            -- Start new group.
            v_cur_group    := rule.group_id;
            v_cur_group_op := rule.group_op;
            v_group_pass   := true;
            -- Rules are ordered base-before-negated: if an exclusion
            -- group's first rule is negated, it has no base rule and
            -- must fail closed (write-time validation normally prevents
            -- this state).
            IF v_cur_group_op = authz._combine_exclusion() AND rule.negated THEN
                v_group_pass := false;
            END IF;
            IF v_trace THEN
                v_group_start := clock_timestamp();
            END IF;
        END IF;

        -- Skip remaining rules in a failed group.
        IF NOT v_group_pass THEN
            CONTINUE;
        END IF;

        -- Evaluate rule based on group operator.
        CASE v_cur_group_op

        WHEN authz._combine_or() THEN
            IF authz._eval_rule(
                p_store_id, p_user_type, p_user_id,
                p_relation, p_object_type, p_object_id,
                rule.rule_type, rule.computed_relation,
                rule.tupleset_relation, rule.tupleset_computed,
                p_request_context, p_has_ctx_tuples,
                p_depth, v_trace, p_exclude
            ) THEN
                RETURN true;
            END IF;

        WHEN authz._combine_and() THEN
            IF NOT authz._eval_rule(
                p_store_id, p_user_type, p_user_id,
                p_relation, p_object_type, p_object_id,
                rule.rule_type, rule.computed_relation,
                rule.tupleset_relation, rule.tupleset_computed,
                p_request_context, p_has_ctx_tuples,
                p_depth, v_trace, p_exclude
            ) THEN
                v_group_pass := false;
            END IF;

        WHEN authz._combine_exclusion() THEN
            IF NOT rule.negated THEN
                -- Base rule: must match.
                IF NOT authz._eval_rule(
                    p_store_id, p_user_type, p_user_id,
                    p_relation, p_object_type, p_object_id,
                    rule.rule_type, rule.computed_relation,
                    rule.tupleset_relation, rule.tupleset_computed,
                    p_request_context, p_has_ctx_tuples,
                    p_depth, v_trace, p_exclude
                ) THEN
                    v_group_pass := false;
                END IF;
            ELSE
                -- Negated rule: must NOT match.
                IF authz._eval_rule(
                    p_store_id, p_user_type, p_user_id,
                    p_relation, p_object_type, p_object_id,
                    rule.rule_type, rule.computed_relation,
                    rule.tupleset_relation, rule.tupleset_computed,
                    p_request_context, p_has_ctx_tuples,
                    p_depth, v_trace, p_exclude
                ) THEN
                    v_group_pass := false;
                END IF;
            END IF;

        END CASE;
    END LOOP;

    -- Finalize last group.
    IF v_cur_group >= 0 AND v_group_pass AND v_cur_group_op <> authz._combine_or() THEN
        IF v_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
            VALUES (p_depth,
                    CASE v_cur_group_op WHEN authz._combine_and() THEN 'intersection' ELSE 'exclusion' END,
                    v_user_type_name || ':' || p_user_id,
                    v_relation_name, v_object_type_name || ':' || p_object_id,
                    true,
                    CASE v_cur_group_op WHEN authz._combine_and() THEN 'all rules matched' ELSE 'base matched, not excluded' END,
                    extract(epoch from clock_timestamp() - v_group_start) * 1000);
        END IF;
        RETURN true;
    END IF;
    -- Trace failed intersection/exclusion for the last group.
    IF v_trace AND v_cur_group >= 0 AND NOT v_group_pass AND v_cur_group_op <> authz._combine_or() THEN
        INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms)
        VALUES (p_depth,
                CASE v_cur_group_op WHEN authz._combine_and() THEN 'intersection' ELSE 'exclusion' END,
                v_user_type_name || ':' || p_user_id,
                v_relation_name, v_object_type_name || ':' || p_object_id,
                false,
                CASE v_cur_group_op WHEN authz._combine_and() THEN 'not all rules matched' ELSE 'base not matched or excluded' END,
                extract(epoch from clock_timestamp() - v_group_start) * 1000);
    END IF;

    RETURN false;
END;
$$;
