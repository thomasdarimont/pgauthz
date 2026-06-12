-- Internal audit/snapshot functions: point-in-time evaluation against
-- pg_temp._snapshot_tuples for audit_check_access.
-- These use integer IDs for performance and are not meant to be called directly.
--
-- Depends on: engine/core_internal.sql, engine/access_internal.sql

------------------------------------------------------------------------
-- _eval_direct_snapshot: evaluates a DIRECT rule against the
-- pg_temp._snapshot_tuples temp table (for point-in-time checks).
-- No tracing, no contextual tuples.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._eval_direct_snapshot(
    p_store_id        smallint,
    p_user_type       smallint,
    p_user_id         text,
    p_relation        smallint,
    p_object_type     smallint,
    p_object_id       text,
    p_request_context jsonb,
    p_depth           int,
    p_path            text[] DEFAULT '{}'
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    tpl     record;
    v_found boolean;
BEGIN
    -- Fast path: unconditional tuples
    EXECUTE '
        SELECT EXISTS (
            SELECT 1 FROM _snapshot_tuples
             WHERE store_id      = $1
               AND object_type   = $2
               AND object_id     = $3
               AND relation      = $4
               AND user_type     = $5
               AND user_id       IN ($6, ''*'')
               AND user_relation IS NULL
               AND condition_id  IS NULL
        )'
    INTO v_found
    USING p_store_id, p_object_type, p_object_id, p_relation,
          p_user_type, p_user_id;

    IF v_found THEN
        RETURN true;
    END IF;

    -- Slow path: conditional tuples only
    EXECUTE '
        SELECT EXISTS (
            SELECT 1 FROM _snapshot_tuples
             WHERE store_id      = $1
               AND object_type   = $2
               AND object_id     = $3
               AND relation      = $4
               AND user_type     = $5
               AND user_id       IN ($6, ''*'')
               AND user_relation IS NULL
               AND condition_id  IS NOT NULL
               AND authz._eval_condition(condition_id, condition_context, $7)
        )'
    INTO v_found
    USING p_store_id, p_object_type, p_object_id, p_relation,
          p_user_type, p_user_id, p_request_context;

    IF v_found THEN
        RETURN true;
    END IF;

    -- Userset expansion from snapshot: unconditional first
    FOR tpl IN
        EXECUTE '
            SELECT user_type, user_id, user_relation
              FROM _snapshot_tuples
             WHERE store_id      = $1
               AND object_type   = $2
               AND object_id     = $3
               AND relation      = $4
               AND user_relation IS NOT NULL
               AND condition_id  IS NULL'
        USING p_store_id, p_object_type, p_object_id, p_relation
    LOOP
        IF authz._check_access_snapshot(
            p_store_id,
            p_user_type, p_user_id,
            tpl.user_relation,
            tpl.user_type, tpl.user_id,
            p_request_context,
            p_depth + 1, p_path
        ) THEN
            RETURN true;
        END IF;
    END LOOP;

    -- Userset expansion from snapshot: conditional
    FOR tpl IN
        EXECUTE '
            SELECT user_type, user_id, user_relation
              FROM _snapshot_tuples
             WHERE store_id      = $1
               AND object_type   = $2
               AND object_id     = $3
               AND relation      = $4
               AND user_relation IS NOT NULL
               AND condition_id  IS NOT NULL
               AND authz._eval_condition(condition_id, condition_context, $5)'
        USING p_store_id, p_object_type, p_object_id, p_relation, p_request_context
    LOOP
        IF authz._check_access_snapshot(
            p_store_id,
            p_user_type, p_user_id,
            tpl.user_relation,
            tpl.user_type, tpl.user_id,
            p_request_context,
            p_depth + 1, p_path
        ) THEN
            RETURN true;
        END IF;
    END LOOP;

    RETURN false;
END;
$$;

------------------------------------------------------------------------
-- _eval_ttu_snapshot: evaluates a TTU rule against the
-- pg_temp._snapshot_tuples temp table (for point-in-time checks).
-- No tracing, no contextual tuples.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._eval_ttu_snapshot(
    p_store_id          smallint,
    p_user_type         smallint,
    p_user_id           text,
    p_relation          smallint,
    p_object_type       smallint,
    p_object_id         text,
    p_tupleset_relation smallint,
    p_tupleset_computed smallint,
    p_request_context   jsonb,
    p_depth             int,
    p_path              text[] DEFAULT '{}'
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    tpl record;
BEGIN
    -- Conditional link tuples are only followed when their condition
    -- passes — mirrors _eval_ttu in the live engine.
    FOR tpl IN
        EXECUTE '
            SELECT user_type AS linked_type, user_id AS linked_id
              FROM _snapshot_tuples
             WHERE store_id      = $1
               AND object_type   = $2
               AND object_id     = $3
               AND relation      = $4
               AND user_relation IS NULL
               AND (condition_id IS NULL
                    OR authz._eval_condition(condition_id, condition_context, $5))'
        USING p_store_id, p_object_type, p_object_id, p_tupleset_relation, p_request_context
    LOOP
        IF authz._check_access_snapshot(
            p_store_id,
            p_user_type, p_user_id,
            p_tupleset_computed,
            tpl.linked_type, tpl.linked_id,
            p_request_context,
            p_depth + 1, p_path
        ) THEN
            RETURN true;
        END IF;
    END LOOP;

    RETURN false;
END;
$$;

------------------------------------------------------------------------
-- _eval_rule_snapshot: thin dispatcher for snapshot rule evaluation.
-- Delegates to _eval_direct_snapshot, inline COMPUTED, or
-- _eval_ttu_snapshot.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._eval_rule_snapshot(
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
    p_depth             int DEFAULT 0,
    p_path              text[] DEFAULT '{}'
) RETURNS boolean
LANGUAGE plpgsql AS $$
BEGIN
    CASE p_rule_type

    WHEN authz._rel_direct() THEN
        RETURN authz._eval_direct_snapshot(
            p_store_id, p_user_type, p_user_id, p_relation, p_object_type, p_object_id,
            p_request_context, p_depth, p_path
        );

    WHEN authz._rel_computed() THEN
        RETURN authz._check_access_snapshot(
            p_store_id,
            p_user_type, p_user_id,
            p_computed_relation,
            p_object_type, p_object_id,
            p_request_context,
            p_depth + 1, p_path
        );

    WHEN authz._rel_ttu() THEN
        RETURN authz._eval_ttu_snapshot(
            p_store_id, p_user_type, p_user_id, p_relation, p_object_type, p_object_id,
            p_tupleset_relation, p_tupleset_computed,
            p_request_context, p_depth, p_path
        );

    END CASE;

    RETURN false;
END;
$$;

------------------------------------------------------------------------
-- _check_access_snapshot: like _check_access but reads from the
-- pg_temp._snapshot_tuples temp table instead of authz.tuples.
-- Used by audit_check_access for point-in-time permission checks.
-- Supports grouped rules (intersection / exclusion).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._check_access_snapshot(
    p_store_id        smallint,
    p_user_type       smallint,
    p_user_id         text,
    p_relation        smallint,
    p_object_type     smallint,
    p_object_id       text,
    p_request_context jsonb DEFAULT NULL,
    p_depth           int DEFAULT 0,
    p_path            text[] DEFAULT '{}'
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    rule           record;
    v_group_pass   boolean;
    v_cur_group    smallint := -1;
    v_cur_group_op smallint;
    v_key          text;
    v_path         text[];
BEGIN
    IF p_depth > authz._max_depth() THEN
        RAISE EXCEPTION 'audit_check_access: maximum resolution depth (%) exceeded — relationship chain too deep or relation graph too complex',
            authz._max_depth();
    END IF;

    -- Cycle detection (mirrors _check_access): prune edges that revisit
    -- a node on the current evaluation path.
    v_key := p_relation::text || ':' || p_object_type::text || ':' || p_object_id;
    IF v_key = ANY(p_path) THEN
        RETURN false;
    END IF;
    v_path := p_path || v_key;

    -- Single query: all rules ordered by group_id, negated (false first)
    FOR rule IN
        SELECT rule_type, computed_relation, tupleset_relation, tupleset_computed,
               group_id, group_op, negated
          FROM authz.models
         WHERE store_id    = p_store_id
           AND object_type = p_object_type
           AND relation    = p_relation
         ORDER BY group_id, negated
    LOOP
        -- Detect group boundary
        IF rule.group_id <> v_cur_group THEN
            -- Finalize previous group: intersection/exclusion pass means access granted
            IF v_cur_group >= 0 AND v_group_pass AND v_cur_group_op <> authz._combine_or() THEN
                RETURN true;
            END IF;
            v_cur_group    := rule.group_id;
            v_cur_group_op := rule.group_op;
            v_group_pass   := true;
            -- Negated-only exclusion group: no base rule, fail closed
            -- (mirrors _check_access).
            IF v_cur_group_op = authz._combine_exclusion() AND rule.negated THEN
                v_group_pass := false;
            END IF;
        END IF;

        -- Skip remaining rules in a failed group
        IF NOT v_group_pass THEN CONTINUE; END IF;

        CASE v_cur_group_op
        WHEN authz._combine_or() THEN
            IF authz._eval_rule_snapshot(
                p_store_id, p_user_type, p_user_id,
                p_relation, p_object_type, p_object_id,
                rule.rule_type, rule.computed_relation,
                rule.tupleset_relation, rule.tupleset_computed,
                p_request_context, p_depth, v_path
            ) THEN
                RETURN true;
            END IF;

        WHEN authz._combine_and() THEN
            IF NOT authz._eval_rule_snapshot(
                p_store_id, p_user_type, p_user_id,
                p_relation, p_object_type, p_object_id,
                rule.rule_type, rule.computed_relation,
                rule.tupleset_relation, rule.tupleset_computed,
                p_request_context, p_depth, v_path
            ) THEN
                v_group_pass := false;
            END IF;

        WHEN authz._combine_exclusion() THEN
            IF NOT rule.negated THEN
                IF NOT authz._eval_rule_snapshot(
                    p_store_id, p_user_type, p_user_id,
                    p_relation, p_object_type, p_object_id,
                    rule.rule_type, rule.computed_relation,
                    rule.tupleset_relation, rule.tupleset_computed,
                    p_request_context, p_depth, v_path
                ) THEN
                    v_group_pass := false;
                END IF;
            ELSE
                IF authz._eval_rule_snapshot(
                    p_store_id, p_user_type, p_user_id,
                    p_relation, p_object_type, p_object_id,
                    rule.rule_type, rule.computed_relation,
                    rule.tupleset_relation, rule.tupleset_computed,
                    p_request_context, p_depth, v_path
                ) THEN
                    v_group_pass := false;
                END IF;
            END IF;

        END CASE;
    END LOOP;

    -- Finalize last group
    IF v_cur_group >= 0 AND v_group_pass AND v_cur_group_op <> authz._combine_or() THEN
        RETURN true;
    END IF;

    RETURN false;
END;
$$;
