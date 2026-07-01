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
    p_user_type   integer,
    p_user_id     text,
    p_relation    integer,
    p_object_type integer,
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
    p_relation    integer,
    p_object_type integer,
    p_object_id   text
) RETURNS TABLE (user_type integer, user_id text, user_relation integer)
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
    p_tupleset_relation integer,
    p_object_type       integer,
    p_object_id         text
) RETURNS TABLE (linked_type integer, linked_id text)
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
    p_store_id          integer,
    p_user_type         integer,
    p_user_id           text,
    p_relation          integer,
    p_object_type       integer,
    p_object_id         text,
    p_request_context   jsonb,
    p_has_ctx_tuples    boolean,
    p_depth             int,
    p_trace             boolean,
    p_user_type_name    text,
    p_relation_name     text,
    p_object_type_name  text,
    p_step_start        timestamptz,
    p_exclude           authz._tuple_key DEFAULT NULL,
    p_path              text[] DEFAULT '{}',
    p_model_rule_id     integer DEFAULT NULL,
    p_group_id          integer DEFAULT NULL,
    p_group_op          integer DEFAULT NULL,
    p_negated           boolean  DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    tpl     record;
    v_child boolean;
    v_cond_name text;
    v_cond_id   integer;
    v_cond_ctx  jsonb;
    v_skip_direct   boolean := false;
    v_skip_wildcard boolean := false;
BEGIN
    -- If this exact tuple is excluded (used by find_redundant_tuples),
    -- skip its direct match but still check every other path — wildcard,
    -- userset, contextual. The wildcard probe targets a DIFFERENT tuple
    -- (user_id = '*'), so it is only skipped when the exclusion itself
    -- targets the wildcard tuple.
    IF p_exclude IS NOT NULL
       AND p_user_type   = (p_exclude).user_type
       AND p_relation    = (p_exclude).relation
       AND p_object_type = (p_exclude).object_type
       AND p_object_id   = (p_exclude).object_id THEN
        v_skip_direct   := p_user_id = (p_exclude).user_id;
        v_skip_wildcard := (p_exclude).user_id = '*';
    END IF;

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
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated, matched_tuple)
            VALUES (p_depth, 'direct', p_user_type_name || ':' || p_user_id,
                    p_relation_name, p_object_type_name || ':' || p_object_id,
                    true, 'tuple found',
                    extract(epoch from clock_timestamp() - p_step_start) * 1000, p_model_rule_id, p_group_id, p_group_op, p_negated,
                    p_user_type_name || ':' || p_user_id || ' → ' || p_relation_name || ' → ' || p_object_type_name || ':' || p_object_id);
        END IF;
        RETURN true;
    END IF;
    END IF; -- NOT v_skip_direct (exact tuple probe)

    IF NOT v_skip_wildcard THEN
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
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated, matched_tuple)
            VALUES (p_depth, 'direct', p_user_type_name || ':' || p_user_id,
                    p_relation_name, p_object_type_name || ':' || p_object_id,
                    true, 'wildcard tuple (*)',
                    extract(epoch from clock_timestamp() - p_step_start) * 1000, p_model_rule_id, p_group_id, p_group_op, p_negated,
                    p_user_type_name || ':* → ' || p_relation_name || ' → ' || p_object_type_name || ':' || p_object_id);
        END IF;
        RETURN true;
    END IF;
    END IF; -- NOT v_skip_wildcard

    -- Object-wildcard tuple check (object_id = '*'): a privileged grant —
    -- the subject (or a covering subject wildcard) holds the relation on
    -- EVERY object of the type. Not guarded by the exclusion flags: an
    -- excluded concrete tuple is a different tuple, and
    -- find_redundant_tuples never excludes object wildcards (it skips
    -- them as candidates).
    IF EXISTS (
        SELECT 1 FROM authz.tuples
         WHERE store_id      = p_store_id
           AND object_type   = p_object_type
           AND object_id     = '*'
           AND relation      = p_relation
           AND user_type     = p_user_type
           AND user_id       IN (p_user_id, '*')
           AND user_relation IS NULL
           AND condition_id  IS NULL
    ) OR EXISTS (
        SELECT 1 FROM authz.tuples
         WHERE store_id      = p_store_id
           AND object_type   = p_object_type
           AND object_id     = '*'
           AND relation      = p_relation
           AND user_type     = p_user_type
           AND user_id       IN (p_user_id, '*')
           AND user_relation IS NULL
           AND condition_id  IS NOT NULL
           AND authz._eval_condition(condition_id, condition_context, p_request_context)
    ) THEN
        IF p_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated, matched_tuple)
            VALUES (p_depth, 'direct', p_user_type_name || ':' || p_user_id,
                    p_relation_name, p_object_type_name || ':' || p_object_id,
                    true, 'object wildcard tuple (*)',
                    extract(epoch from clock_timestamp() - p_step_start) * 1000, p_model_rule_id, p_group_id, p_group_op, p_negated,
                    -- the stored object-wildcard tuple: subject may be exact or '*'
                    p_user_type_name || ':' ||
                      (SELECT t2.user_id FROM authz.tuples t2
                        WHERE t2.store_id = p_store_id AND t2.object_type = p_object_type AND t2.object_id = '*'
                          AND t2.relation = p_relation AND t2.user_type = p_user_type
                          AND t2.user_id IN (p_user_id, '*') AND t2.user_relation IS NULL
                        ORDER BY (t2.user_id = p_user_id) DESC LIMIT 1)
                      || ' → ' || p_relation_name || ' → ' || p_object_type_name || ':*');
        END IF;
        RETURN true;
    END IF;

    IF NOT v_skip_direct THEN
    -- Trace: tuple exists but condition denied it
    IF p_trace AND EXISTS (
        SELECT 1 FROM authz.tuples
         WHERE store_id      = p_store_id
           AND object_type   = p_object_type
           AND object_id     IN (p_object_id, '*')
           AND relation      = p_relation
           AND user_type     = p_user_type
           AND user_id       IN (p_user_id, '*')
           AND user_relation IS NULL
           AND condition_id  IS NOT NULL
    ) THEN
        SELECT c.name, t.condition_id, t.condition_context
          INTO v_cond_name, v_cond_id, v_cond_ctx
          FROM authz.tuples t
          JOIN authz.conditions c ON c.id = t.condition_id
         WHERE t.store_id      = p_store_id
           AND t.object_type   = p_object_type
           AND t.object_id     IN (p_object_id, '*')
           AND t.relation      = p_relation
           AND t.user_type     = p_user_type
           AND t.user_id       IN (p_user_id, '*')
           AND t.user_relation IS NULL
         LIMIT 1;
        INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated, condition_name, condition_missing_keys)
        VALUES (p_depth, 'direct', p_user_type_name || ':' || p_user_id,
                p_relation_name, p_object_type_name || ':' || p_object_id,
                false, 'tuple found, condition "' || v_cond_name || '" denied',
                extract(epoch from clock_timestamp() - p_step_start) * 1000, p_model_rule_id, p_group_id, p_group_op, p_negated,
                v_cond_name, authz._condition_missing_keys(v_cond_id, v_cond_ctx, p_request_context));
    END IF;
    END IF; -- v_skip_direct

    -- Check contextual tuples (via dynamic SQL to avoid parse-time error)
    IF p_has_ctx_tuples AND authz._check_ctx_direct(
        p_user_type, p_user_id, p_relation, p_object_type, p_object_id
    ) THEN
        IF p_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated)
            VALUES (p_depth, 'direct', p_user_type_name || ':' || p_user_id,
                    p_relation_name, p_object_type_name || ':' || p_object_id,
                    true, 'contextual tuple',
                    extract(epoch from clock_timestamp() - p_step_start) * 1000, p_model_rule_id, p_group_id, p_group_op, p_negated);
        END IF;
        RETURN true;
    END IF;

    -- Userset expansion (stored tuples): unconditional first, then conditional
    FOR tpl IN
        SELECT user_type, user_id, user_relation
          FROM authz.tuples
         WHERE store_id      = p_store_id
           AND object_type   = p_object_type
           AND object_id     IN (p_object_id, '*')
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
            p_exclude, p_path
        );
        IF p_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated)
            VALUES (p_depth, 'userset', p_user_type_name || ':' || p_user_id,
                    p_relation_name, p_object_type_name || ':' || p_object_id,
                    v_child,
                    'expand ' || (SELECT name FROM authz.types WHERE id = tpl.user_type)
                    || ':' || tpl.user_id || '#'
                    || (SELECT name FROM authz.relations WHERE id = tpl.user_relation),
                    extract(epoch from clock_timestamp() - p_step_start) * 1000, p_model_rule_id, p_group_id, p_group_op, p_negated);
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
           AND object_id     IN (p_object_id, '*')
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
            p_exclude, p_path
        );
        IF p_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated)
            VALUES (p_depth, 'userset', p_user_type_name || ':' || p_user_id,
                    p_relation_name, p_object_type_name || ':' || p_object_id,
                    v_child,
                    'expand ' || (SELECT name FROM authz.types WHERE id = tpl.user_type)
                    || ':' || tpl.user_id || '#'
                    || (SELECT name FROM authz.relations WHERE id = tpl.user_relation),
                    extract(epoch from clock_timestamp() - p_step_start) * 1000, p_model_rule_id, p_group_id, p_group_op, p_negated);
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
                p_exclude, p_path
            );
            IF p_trace THEN
                INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated)
                VALUES (p_depth, 'userset', p_user_type_name || ':' || p_user_id,
                        p_relation_name, p_object_type_name || ':' || p_object_id,
                        v_child, 'expand contextual userset',
                        extract(epoch from clock_timestamp() - p_step_start) * 1000, p_model_rule_id, p_group_id, p_group_op, p_negated);
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
           AND object_id     IN (p_object_id, '*')
           AND relation      = p_relation
           AND user_type     = p_user_type
           AND user_id       IN (p_user_id, '*')
           AND user_relation IS NULL
    ) THEN
        INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated)
        VALUES (p_depth, 'direct', p_user_type_name || ':' || p_user_id,
                p_relation_name, p_object_type_name || ':' || p_object_id,
                false, 'no tuple',
                extract(epoch from clock_timestamp() - p_step_start) * 1000, p_model_rule_id, p_group_id, p_group_op, p_negated);
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
    p_store_id          integer,
    p_user_type         integer,
    p_user_id           text,
    p_relation          integer,
    p_object_type       integer,
    p_object_id         text,
    p_tupleset_relation integer,
    p_tupleset_computed integer,
    p_request_context   jsonb,
    p_has_ctx_tuples    boolean,
    p_depth             int,
    p_trace             boolean,
    p_user_type_name    text,
    p_relation_name     text,
    p_object_type_name  text,
    p_step_start        timestamptz,
    p_exclude           authz._tuple_key DEFAULT NULL,
    p_path              text[] DEFAULT '{}',
    p_model_rule_id     integer DEFAULT NULL,
    p_group_id          integer DEFAULT NULL,
    p_group_op          integer DEFAULT NULL,
    p_negated           boolean  DEFAULT NULL
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
            p_exclude, p_path
        );
        IF p_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated)
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
                    extract(epoch from clock_timestamp() - p_step_start) * 1000, p_model_rule_id, p_group_id, p_group_op, p_negated);
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
                p_exclude, p_path
            );
            IF p_trace THEN
                INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated)
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
                        extract(epoch from clock_timestamp() - p_step_start) * 1000, p_model_rule_id, p_group_id, p_group_op, p_negated);
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
        INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated)
        VALUES (p_depth, 'ttu', p_user_type_name || ':' || p_user_id,
                p_relation_name, p_object_type_name || ':' || p_object_id,
                false,
                'no ' || (SELECT name FROM authz.relations WHERE id = p_tupleset_relation) || ' link',
                extract(epoch from clock_timestamp() - p_step_start) * 1000, p_model_rule_id, p_group_id, p_group_op, p_negated);
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
    p_store_id          integer,
    p_user_type         integer,
    p_user_id           text,
    p_relation          integer,
    p_object_type       integer,
    p_object_id         text,
    p_rule_type         integer,
    p_computed_relation integer,
    p_tupleset_relation integer,
    p_tupleset_computed integer,
    p_request_context   jsonb DEFAULT NULL,
    p_has_ctx_tuples    boolean DEFAULT false,
    p_depth             int DEFAULT 0,
    p_trace             boolean DEFAULT false,
    p_exclude           authz._tuple_key DEFAULT NULL,
    p_path              text[] DEFAULT '{}',
    p_model_rule_id     integer DEFAULT NULL,
    p_group_id          integer DEFAULT NULL,
    p_group_op          integer DEFAULT NULL,
    p_negated           boolean  DEFAULT NULL
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
            p_exclude, p_path,
            p_model_rule_id, p_group_id, p_group_op, p_negated
        );

    WHEN authz._rel_computed() THEN
        v_child := authz._check_access(
            p_store_id,
            p_user_type, p_user_id,
            p_computed_relation,
            p_object_type, p_object_id,
            p_request_context, p_has_ctx_tuples,
            p_depth + 1, p_trace,
            p_exclude, p_path
        );
        IF p_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated)
            VALUES (p_depth, 'computed', v_user_type_name || ':' || p_user_id,
                    v_relation_name, v_object_type_name || ':' || p_object_id,
                    v_child,
                    v_relation_name || ' ← '
                    || (SELECT name FROM authz.relations WHERE id = p_computed_relation),
                    extract(epoch from clock_timestamp() - v_step_start) * 1000, p_model_rule_id, p_group_id, p_group_op, p_negated);
        END IF;
        RETURN v_child;

    WHEN authz._rel_ttu() THEN
        RETURN authz._eval_ttu(
            p_store_id, p_user_type, p_user_id, p_relation, p_object_type, p_object_id,
            p_tupleset_relation, p_tupleset_computed,
            p_request_context, p_has_ctx_tuples, p_depth, p_trace,
            v_user_type_name, v_relation_name, v_object_type_name, v_step_start,
            p_exclude, p_path,
            p_model_rule_id, p_group_id, p_group_op, p_negated
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
CREATE OR REPLACE FUNCTION authz._check_access_impl(
    p_store_id        integer,
    p_user_type       integer,
    p_user_id         text,
    p_relation        integer,
    p_object_type     integer,
    p_object_id       text,
    p_request_context jsonb DEFAULT NULL,
    p_has_ctx_tuples  boolean DEFAULT false,
    p_depth           int DEFAULT 0,
    p_trace           boolean DEFAULT NULL,
    p_exclude         authz._tuple_key DEFAULT NULL,
    p_path            text[] DEFAULT '{}'
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    rule            record;
    v_trace         boolean := p_trace;
    v_group_pass    boolean;
    v_group_start   timestamptz;

    -- Group boundary tracking
    v_cur_group     integer := -1;
    v_cur_group_op  integer;

    -- Name resolution helpers (only used when tracing)
    v_user_type_name   text;
    v_relation_name    text;
    v_object_type_name text;

    -- Cycle detection: nodes on the current evaluation path
    v_key  text;
    v_path text[];
BEGIN
    IF p_depth > authz._max_depth() THEN
        RAISE EXCEPTION 'check_access: maximum resolution depth (%) exceeded — relationship chain too deep or relation graph too complex',
            authz._max_depth();
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

    -- Cycle detection: a node already on the current evaluation path
    -- cannot contribute a well-founded grant — prune this edge. This
    -- also guarantees termination on cyclic relationship graphs.
    v_key := p_relation::text || ':' || p_object_type::text || ':' || p_object_id;
    IF v_key = ANY(p_path) THEN
        IF v_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated)
            VALUES (p_depth, 'cycle', v_user_type_name || ':' || p_user_id,
                    v_relation_name, v_object_type_name || ':' || p_object_id,
                    false, 'cycle detected — path pruned', 0, NULL::integer, NULL::integer, NULL::integer, NULL::boolean);
        END IF;
        -- Record the cycle prune so the memoizing wrapper (_check_access) will
        -- NOT cache any node whose subtree depended on this back-edge — only
        -- path-independent (cycle-free) sub-results are cacheable. See the
        -- wrapper below / docs/BENCHMARKS.md.
        PERFORM set_config('authz._memo_prunes',
            (COALESCE(NULLIF(current_setting('authz._memo_prunes', true), '')::bigint, 0) + 1)::text, false);
        RETURN false;
    END IF;
    v_path := p_path || v_key;

    -- Single query: fetch all rules ordered by group, with base rules before negated.
    FOR rule IN
        SELECT id, rule_type, computed_relation, tupleset_relation, tupleset_computed,
               group_id, group_op, negated
          FROM authz.models
         WHERE store_id    = p_store_id
           AND object_type = p_object_type
           AND relation    = p_relation
         -- group_id keeps a group's rules contiguous; negated puts exclusion base
         -- rules before their negations; rule_type then tries the CHEAPEST rules
         -- first (direct=1 O(1) probe < computed=2 recurses same object < ttu=3
         -- follows a tupleset then recurses). Order never changes the result (union
         -- / intersection are order-independent) — it only lets ALLOWs short-circuit
         -- and intersections fail-fast sooner, skipping expensive recursion.
         ORDER BY group_id, negated, rule_type
    LOOP
        -- Detect group boundary.
        IF rule.group_id <> v_cur_group THEN
            -- Finalize previous group (intersection/exclusion need end-of-group check).
            IF v_cur_group >= 0 AND v_group_pass AND v_cur_group_op <> authz._combine_or() THEN
                IF v_trace THEN
                    INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated)
                    VALUES (p_depth,
                            CASE v_cur_group_op WHEN authz._combine_and() THEN 'intersection' ELSE 'exclusion' END,
                            v_user_type_name || ':' || p_user_id,
                            v_relation_name, v_object_type_name || ':' || p_object_id,
                            true,
                            CASE v_cur_group_op WHEN authz._combine_and() THEN 'all rules matched' ELSE 'base matched, not excluded' END,
                            extract(epoch from clock_timestamp() - v_group_start) * 1000, NULL::integer, v_cur_group, v_cur_group_op, NULL::boolean);
                END IF;
                RETURN true;
            END IF;
            -- Trace failed intersection/exclusion.
            IF v_trace AND v_cur_group >= 0 AND NOT v_group_pass AND v_cur_group_op <> authz._combine_or() THEN
                INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated)
                VALUES (p_depth,
                        CASE v_cur_group_op WHEN authz._combine_and() THEN 'intersection' ELSE 'exclusion' END,
                        v_user_type_name || ':' || p_user_id,
                        v_relation_name, v_object_type_name || ':' || p_object_id,
                        false,
                        CASE v_cur_group_op WHEN authz._combine_and() THEN 'not all rules matched' ELSE 'base not matched or excluded' END,
                        extract(epoch from clock_timestamp() - v_group_start) * 1000, NULL::integer, v_cur_group, v_cur_group_op, NULL::boolean);
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
                p_depth, v_trace, p_exclude, v_path,
                rule.id, rule.group_id, rule.group_op, rule.negated
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
                p_depth, v_trace, p_exclude, v_path,
                rule.id, rule.group_id, rule.group_op, rule.negated
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
                    p_depth, v_trace, p_exclude, v_path,
                rule.id, rule.group_id, rule.group_op, rule.negated
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
                    p_depth, v_trace, p_exclude, v_path,
                rule.id, rule.group_id, rule.group_op, rule.negated
                ) THEN
                    v_group_pass := false;
                END IF;
            END IF;

        END CASE;
    END LOOP;

    -- Finalize last group.
    IF v_cur_group >= 0 AND v_group_pass AND v_cur_group_op <> authz._combine_or() THEN
        IF v_trace THEN
            INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated)
            VALUES (p_depth,
                    CASE v_cur_group_op WHEN authz._combine_and() THEN 'intersection' ELSE 'exclusion' END,
                    v_user_type_name || ':' || p_user_id,
                    v_relation_name, v_object_type_name || ':' || p_object_id,
                    true,
                    CASE v_cur_group_op WHEN authz._combine_and() THEN 'all rules matched' ELSE 'base matched, not excluded' END,
                    extract(epoch from clock_timestamp() - v_group_start) * 1000, NULL::integer, v_cur_group, v_cur_group_op, NULL::boolean);
        END IF;
        RETURN true;
    END IF;
    -- Trace failed intersection/exclusion for the last group.
    IF v_trace AND v_cur_group >= 0 AND NOT v_group_pass AND v_cur_group_op <> authz._combine_or() THEN
        INSERT INTO _access_trace (depth, rule_type, subject, relation, object, result, detail, duration_ms, model_rule_id, group_id, group_op, negated)
        VALUES (p_depth,
                CASE v_cur_group_op WHEN authz._combine_and() THEN 'intersection' ELSE 'exclusion' END,
                v_user_type_name || ':' || p_user_id,
                v_relation_name, v_object_type_name || ':' || p_object_id,
                false,
                CASE v_cur_group_op WHEN authz._combine_and() THEN 'not all rules matched' ELSE 'base not matched or excluded' END,
                extract(epoch from clock_timestamp() - v_group_start) * 1000, NULL::integer, v_cur_group, v_cur_group_op, NULL::boolean);
    END IF;

    RETURN false;
END;
$$;

------------------------------------------------------------------------
-- _check_access: memoizing wrapper over _check_access_impl.
--
-- All recursion (computed / TTU / userset) re-enters through this function, so
-- caching here covers the whole resolution tree. It caches each (relation,
-- object) sub-result WITHIN one root check, so a node reachable via many
-- distinct paths is evaluated once — collapsing diamond / converging graphs
-- from O(2^depth) to ~linear (see bench/suites/adversarial.sql).
--
-- Correctness with cycles: _check_access_impl prunes cycles using the current
-- PATH, so a node's result can be path-dependent IFF a cycle in its subtree
-- pointed back above it. We cache a result ONLY when its subtree triggered NO
-- cycle prune (the authz._memo_prunes counter, bumped by _impl's cycle check,
-- is unchanged across the sub-evaluation) — a zero-prune subtree is provably
-- path-independent. Anything touched by a cycle is recomputed, never cached,
-- so the exact path-based decision is preserved (verified by the cyclic-graph
-- tests). On acyclic data (the realistic case, and every diamond) NO prunes
-- ever fire, so everything caches and the speedup is full.
--
-- Scope: the memo is reset at the root (p_depth = 0); within one check the
-- subject, request context, contextual tuples and exclude are all constant, so
-- (relation, object) is a complete key. Shallow nodes (p_depth < 2) skip the
-- cache so trivial checks pay nothing, and tracing disables it so
-- explain_access still records the fully unfolded tree.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._check_access(
    p_store_id        integer,
    p_user_type       integer,
    p_user_id         text,
    p_relation        integer,
    p_object_type     integer,
    p_object_id       text,
    p_request_context jsonb DEFAULT NULL,
    p_has_ctx_tuples  boolean DEFAULT false,
    p_depth           int DEFAULT 0,
    p_trace           boolean DEFAULT NULL,
    p_exclude         authz._tuple_key DEFAULT NULL,
    p_path            text[] DEFAULT '{}'
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    -- The per-check memo collapses converging/diamond graphs from O(2^depth) to
    -- ~linear. It has two backends, chosen at the root by transaction read-only
    -- state (see below) and recorded in authz._memo_mode:
    --   'temp' — a session temp table (fast, O(1) probes); writable txn / primary
    --   'guc'  — a jsonb map in a session GUC (O(memo) probes; the only mutable
    --            scratch a hot standby allows — temp tables can't be created in a
    --            read-only txn). Slower than 'temp' but still polynomial, so the
    --            read path stays protected on replicas. set_config is session-
    --            local, so both backends are concurrency-safe (no cross-session
    --            sharing; one backend runs one statement at a time).
    --   'off'  — disabled via the authz.memoize kill-switch (tests diff on/off).
    v_mode   text := COALESCE(current_setting('authz._memo_mode', true), 'off');
    v_use    boolean := (p_depth >= 2) AND v_mode <> 'off';
    v_key    text;
    v_memo   jsonb;
    v_cached boolean;
    v_p0     bigint;
    v_result boolean;
    v_cap    int;
    v_cnt    bigint;
BEGIN
    -- ── Root frame: pick the backend, run the check, ALWAYS clean up ─────────
    -- The 'guc' backend holds this check's visited (object, decision) pairs in a
    -- session GUC; clear it before returning (success OR error) so it never
    -- lingers in the session — both to release the memory and to avoid leaving a
    -- readable record of intermediate object ids/decisions behind for a direct
    -- SQL caller (see docs/BENCHMARKS.md "Read replicas"). The exception block
    -- is only at the root, so it costs one subtransaction per top-level check,
    -- not one per recursive call.
    IF p_depth = 0 THEN
        IF COALESCE(current_setting('authz.memoize', true), 'on') = 'off' THEN
            v_mode := 'off';
        ELSIF current_setting('transaction_read_only') = 'off' THEN
            CREATE TEMP TABLE IF NOT EXISTS _check_memo
                (relation integer, object_type integer, object_id text, result boolean,
                 PRIMARY KEY (relation, object_type, object_id));
            TRUNCATE _check_memo;
            v_mode := 'temp';
        ELSE
            PERFORM set_config('authz._memo_data', '{}', false);
            PERFORM set_config('authz._memo_count', '0', false);
            v_mode := 'guc';
        END IF;
        PERFORM set_config('authz._memo_mode', v_mode, false);
        PERFORM set_config('authz._memo_prunes', '0', false);

        BEGIN
            v_result := authz._check_access_impl(
                p_store_id, p_user_type, p_user_id, p_relation, p_object_type, p_object_id,
                p_request_context, p_has_ctx_tuples, 0, p_trace, p_exclude, p_path);
        EXCEPTION WHEN OTHERS THEN
            PERFORM set_config('authz._memo_data', '{}', false);   -- drop the payload on error too
            RAISE;
        END;
        -- Drop the visited (object, decision) payload; keep _memo_mode / _memo_count
        -- (non-sensitive scalars) for observability. The next root check re-inits them.
        PERFORM set_config('authz._memo_data', '{}', false);
        RETURN v_result;
    END IF;

    -- ── Depth > 0: memoized resolution (no exception block / subtransaction) ──
    -- Disable the cache while tracing so explain_access sees every step.
    IF v_use AND p_trace IS NOT TRUE
              AND COALESCE(current_setting('authz.trace', true), 'off') <> 'on' THEN
        IF v_mode = 'temp' THEN
            SELECT result INTO v_cached FROM _check_memo
             WHERE relation = p_relation AND object_type = p_object_type AND object_id = p_object_id;
            IF FOUND THEN
                RETURN v_cached;
            END IF;
        ELSE  -- 'guc'
            v_key  := p_relation::text || ':' || p_object_type::text || ':' || p_object_id;
            v_memo := COALESCE(current_setting('authz._memo_data', true), '{}')::jsonb;
            IF v_memo ? v_key THEN
                RETURN (v_memo ->> v_key)::boolean;
            END IF;
        END IF;
    ELSE
        v_use := false;
    END IF;

    v_p0 := COALESCE(NULLIF(current_setting('authz._memo_prunes', true), '')::bigint, 0);

    v_result := authz._check_access_impl(
        p_store_id, p_user_type, p_user_id, p_relation, p_object_type, p_object_id,
        p_request_context, p_has_ctx_tuples, p_depth, p_trace, p_exclude, p_path);

    -- Cache only a path-independent (cycle-free) sub-result.
    IF v_use AND COALESCE(NULLIF(current_setting('authz._memo_prunes', true), '')::bigint, 0) = v_p0 THEN
        IF v_mode = 'temp' THEN
            INSERT INTO _check_memo VALUES (p_relation, p_object_type, p_object_id, v_result)
            ON CONFLICT (relation, object_type, object_id) DO NOTHING;
        ELSE  -- 'guc': read-modify-write the jsonb map back into the GUC.
            -- The GUC backend re-parses/serializes the whole map per probe, so a
            -- check with thousands of DISTINCT subproblems degrades (~quadratic)
            -- on a replica. authz.memo_max_entries caps the map size; when a check
            -- would exceed it we FAIL FAST with a distinct error rather than
            -- silently continuing un-memoized — silent degradation would
            -- reintroduce the exact pathological re-work the memo prevents. The
            -- caller should catch 'memo_limit_exceeded' (SQLSTATE 53400) and
            -- retry on the PRIMARY (writable → temp-table backend, O(entries),
            -- uncapped). 0 = unlimited (legacy: no cap, no abort). _memo_count
            -- tracks the size in a GUC for an O(1) cap check (and observability).
            v_cap := COALESCE(NULLIF(current_setting('authz.memo_max_entries', true), '')::int, 5000);
            v_cnt := COALESCE(NULLIF(current_setting('authz._memo_count', true), '')::bigint, 0);
            IF v_cap > 0 AND v_cnt >= v_cap THEN
                RAISE EXCEPTION 'memo_limit_exceeded: this check needs more than % distinct subproblems memoized on a read-only/replica connection', v_cap
                    USING ERRCODE = '53400',  -- configuration_limit_exceeded
                          HINT = 'Retry on the primary (a writable connection uses the uncapped temp-table memo), or raise authz.memo_max_entries (0 = unlimited).';
            END IF;
            v_key := COALESCE(v_key, p_relation::text || ':' || p_object_type::text || ':' || p_object_id);
            PERFORM set_config('authz._memo_data',
                (COALESCE(current_setting('authz._memo_data', true), '{}')::jsonb
                 || jsonb_build_object(v_key, v_result))::text, false);
            PERFORM set_config('authz._memo_count', (v_cnt + 1)::text, false);
        END IF;
    END IF;

    RETURN v_result;
END;
$$;
