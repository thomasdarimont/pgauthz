-- Internal audit/snapshot functions: point-in-time evaluation against
-- pg_temp._snapshot_tuples for audit_check_access.
-- These use integer IDs for performance and are not meant to be called directly.
--
-- Depends on: engine/core_internal.sql, engine/access_internal.sql

------------------------------------------------------------------------
-- _build_audit_snapshot: (re)builds pg_temp._snapshot_tuples with the
-- tuple state of a store as of p_at by replaying the audit log: the
-- last event per tuple wins (ties on performed_at broken by seq), and
-- only tuples whose last event was an INSERT exist in the snapshot.
-- Shared by audit_check_access and audit_list_actions, which builds
-- the snapshot once and evaluates every relation against it.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._build_audit_snapshot(
    p_store_id integer,
    p_at       timestamptz
) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    CREATE TEMP TABLE IF NOT EXISTS _snapshot_tuples (
        store_id          integer,
        user_type         integer,
        user_id           text,
        user_relation     integer,
        relation          integer,
        object_type       integer,
        object_id         text,
        condition_id      integer,
        condition_context jsonb
    ) ON COMMIT DROP;

    TRUNCATE _snapshot_tuples;

    INSERT INTO _snapshot_tuples
    SELECT sub.store_id, sub.user_type, sub.user_id, sub.user_relation,
           sub.relation, sub.object_type, sub.object_id,
           sub.condition_id, sub.condition_context
      FROM (
        SELECT DISTINCT ON (
            a.store_id, a.user_type, a.user_id, COALESCE(a.user_relation, 0),
            a.relation, a.object_type, a.object_id
        )
            a.*
          FROM authz.tuples_audit a
         WHERE a.store_id = p_store_id
           AND a.performed_at <= p_at
         ORDER BY
            a.store_id, a.user_type, a.user_id, COALESCE(a.user_relation, 0),
            a.relation, a.object_type, a.object_id,
            a.performed_at DESC, a.seq DESC
      ) sub
     WHERE sub.action = 'INSERT';
END;
$$;

------------------------------------------------------------------------
-- _build_model_snapshot: (re)builds pg_temp._snapshot_models with the
-- MODEL rule set of a store as of p_at by replaying authz.models_audit:
-- the last event per rule wins (a rule's identity is its idx_models_unique
-- business key; ties on performed_at broken by seq), and only rules whose
-- last event was an INSERT exist in the snapshot. This is what makes
-- time-travel resolve against the model as it was, not the current model.
-- Shared by audit_check_access and audit_list_actions.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._build_model_snapshot(
    p_store_id integer,
    p_at       timestamptz
) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    CREATE TEMP TABLE IF NOT EXISTS _snapshot_models (
        store_id          integer,
        object_type       integer,
        relation          integer,
        rule_type         integer,
        computed_relation integer,
        tupleset_relation integer,
        tupleset_computed integer,
        group_id          integer,
        group_op          integer,
        negated           boolean,
        allow_object_wildcard boolean,
        model_id          integer
    ) ON COMMIT DROP;

    TRUNCATE _snapshot_models;

    INSERT INTO _snapshot_models
    SELECT sub.store_id, sub.object_type, sub.relation, sub.rule_type,
           sub.computed_relation, sub.tupleset_relation, sub.tupleset_computed,
           sub.group_id, sub.group_op, sub.negated, sub.allow_object_wildcard, sub.model_id
      FROM (
        SELECT DISTINCT ON (
            a.store_id, a.object_type, a.relation, a.rule_type,
            COALESCE(a.computed_relation, -1),
            COALESCE(a.tupleset_relation, -1),
            COALESCE(a.tupleset_computed, -1),
            a.group_id, a.negated
        )
            a.*
          FROM authz.models_audit a
         WHERE a.store_id = p_store_id
           AND a.performed_at <= p_at
         ORDER BY
            a.store_id, a.object_type, a.relation, a.rule_type,
            COALESCE(a.computed_relation, -1),
            COALESCE(a.tupleset_relation, -1),
            COALESCE(a.tupleset_computed, -1),
            a.group_id, a.negated,
            a.performed_at DESC, a.seq DESC
      ) sub
     WHERE sub.action = 'INSERT';
END;
$$;

------------------------------------------------------------------------
-- _build_condition_snapshot: (re)builds pg_temp._snapshot_conditions with
-- each condition's EXPRESSION as of p_at by replaying conditions_audit
-- (last event per condition id wins, ties broken by seq, INSERT survives).
-- This makes time-travel evaluate conditional grants against the
-- expression in effect at p_at, not an expression edited in place later.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._build_condition_snapshot(
    p_store_id integer,
    p_at       timestamptz
) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    CREATE TEMP TABLE IF NOT EXISTS _snapshot_conditions (
        id         integer,
        expression text,
        lang       text
    ) ON COMMIT DROP;

    TRUNCATE _snapshot_conditions;

    INSERT INTO _snapshot_conditions
    SELECT sub.condition_id, sub.expression, sub.lang
      FROM (
        SELECT DISTINCT ON (a.condition_id) a.*
          FROM authz.conditions_audit a
         WHERE a.store_id = p_store_id
           AND a.performed_at <= p_at
         ORDER BY a.condition_id, a.performed_at DESC, a.seq DESC
      ) sub
     WHERE sub.action = 'INSERT';
END;
$$;

------------------------------------------------------------------------
-- _eval_condition_snapshot: like _eval_condition, but resolves the
-- expression and lang from pg_temp._snapshot_conditions (the as-of-p_at
-- version) instead of the current authz.conditions, then dispatches via
-- _eval_condition_expr (so 'sql' still runs in the authz_eval sandbox).
-- Dynamic SQL because the temp table is per-session.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._eval_condition_snapshot(
    p_condition_id      integer,
    p_condition_context jsonb,
    p_request_context   jsonb
) RETURNS boolean
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_expr text;
    v_lang text;
BEGIN
    IF p_condition_id IS NULL THEN
        RETURN true;   -- unconditional
    END IF;

    EXECUTE 'SELECT expression, lang FROM _snapshot_conditions WHERE id = $1'
       INTO v_expr, v_lang USING p_condition_id;
    IF v_expr IS NULL THEN
        RETURN false;  -- condition did not exist as of p_at = deny
    END IF;

    RETURN authz._eval_condition_expr(
        v_lang,
        v_expr,
        COALESCE(p_request_context, '{}'::jsonb),
        COALESCE(p_condition_context, '{}'::jsonb)
    );
EXCEPTION
    WHEN query_canceled THEN
        RAISE;         -- statement_timeout / cancel must abort, never deny-swallow
    WHEN OTHERS THEN
        RETURN false;  -- genuine evaluation error = deny
END;
$$;

------------------------------------------------------------------------
-- _eval_direct_snapshot: evaluates a DIRECT rule against the
-- pg_temp._snapshot_tuples temp table (for point-in-time checks).
-- No tracing, no contextual tuples.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._eval_direct_snapshot(
    p_store_id        integer,
    p_user_type       integer,
    p_user_id         text,
    p_relation        integer,
    p_object_type     integer,
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
               AND object_id     IN ($3, ''*'')
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
               AND object_id     IN ($3, ''*'')
               AND relation      = $4
               AND user_type     = $5
               AND user_id       IN ($6, ''*'')
               AND user_relation IS NULL
               AND condition_id  IS NOT NULL
               AND authz._eval_condition_snapshot(condition_id, condition_context, $7)
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
               AND object_id     IN ($3, ''*'')
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
               AND object_id     IN ($3, ''*'')
               AND relation      = $4
               AND user_relation IS NOT NULL
               AND condition_id  IS NOT NULL
               AND authz._eval_condition_snapshot(condition_id, condition_context, $5)'
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
    p_store_id          integer,
    p_user_type         integer,
    p_user_id           text,
    p_relation          integer,
    p_object_type       integer,
    p_object_id         text,
    p_tupleset_relation integer,
    p_tupleset_computed integer,
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
                    OR authz._eval_condition_snapshot(condition_id, condition_context, $5))'
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
-- _check_access_snapshot_impl: like _check_access_impl but reads from the
-- pg_temp._snapshot_tuples / _snapshot_models temp tables instead of
-- authz.tuples / authz.models. The point-in-time core; the memoizing
-- wrapper _check_access_snapshot (below) is what all recursion re-enters
-- through. Supports grouped rules (intersection / exclusion).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._check_access_snapshot_impl(
    p_store_id        integer,
    p_user_type       integer,
    p_user_id         text,
    p_relation        integer,
    p_object_type     integer,
    p_object_id       text,
    p_request_context jsonb DEFAULT NULL,
    p_depth           int DEFAULT 0,
    p_path            text[] DEFAULT '{}'
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    rule           record;
    v_group_pass   boolean;
    v_cur_group    integer := -1;
    v_cur_group_op integer;
    v_key          text;
    v_path         text[];
BEGIN
    IF p_depth > authz._max_depth() THEN
        RAISE EXCEPTION 'audit_check_access: maximum resolution depth (%) exceeded — relationship chain too deep or relation graph too complex',
            authz._max_depth();
    END IF;

    -- Cycle detection (mirrors _check_access_impl): prune edges that revisit
    -- a node on the current evaluation path.
    v_key := p_relation::text || ':' || p_object_type::text || ':' || p_object_id;
    IF v_key = ANY(p_path) THEN
        -- Record the cycle prune so the memoizing wrapper
        -- (_check_access_snapshot) will NOT cache any node whose subtree
        -- depended on this back-edge (its result would be path-dependent).
        PERFORM set_config('authz._memo_prunes_snap',
            (COALESCE(NULLIF(current_setting('authz._memo_prunes_snap', true), '')::bigint, 0) + 1)::text, false);
        RETURN false;
    END IF;
    v_path := p_path || v_key;

    -- Single query: all rules ordered by group_id, negated (false first).
    -- Reads the point-in-time model snapshot (pg_temp._snapshot_models),
    -- not authz.models, so the check resolves against the model as it was
    -- at p_at. Dynamic SQL because the temp table is per-session (mirrors
    -- the _snapshot_tuples reads above).
    FOR rule IN
        EXECUTE '
            SELECT rule_type, computed_relation, tupleset_relation, tupleset_computed,
                   group_id, group_op, negated
              FROM _snapshot_models
             WHERE store_id    = $1
               AND object_type = $2
               AND relation    = $3
             ORDER BY group_id, negated'
        USING p_store_id, p_object_type, p_relation
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

------------------------------------------------------------------------
-- _check_access_snapshot: memoizing wrapper over _check_access_snapshot_impl.
-- The point-in-time twin of _check_access's wrapper (see access_internal.sql
-- for the full rationale). All snapshot recursion (computed / TTU / userset)
-- re-enters here, so caching here covers the whole point-in-time resolution
-- tree, collapsing diamond / converging graphs from O(2^depth) to ~linear.
--
-- Within one audit_check_access the subject, request context AND the entire
-- _snapshot_* state are constant, so (relation, object) is a complete key.
-- Correctness with cycles is identical to the live path: a result is cached
-- ONLY when its subtree triggered no cycle prune (the authz._memo_prunes_snap
-- counter, bumped by _impl's cycle check, is unchanged across the
-- sub-evaluation) — a zero-prune subtree is provably path-independent, so the
-- exact path-based decision is preserved. A separate temp table and counter
-- (suffix _snap) keep this wholly independent of the live memo.
--
-- Reset at the root (p_depth = 0); shallow nodes (p_depth < 2) skip the cache;
-- disablable via SET authz.memoize='off' (shared kill-switch). No tracing path
-- exists for snapshots, so there is no trace guard.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._check_access_snapshot(
    p_store_id        integer,
    p_user_type       integer,
    p_user_id         text,
    p_relation        integer,
    p_object_type     integer,
    p_object_id       text,
    p_request_context jsonb DEFAULT NULL,
    p_depth           int DEFAULT 0,
    p_path            text[] DEFAULT '{}'
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_use    boolean := (p_depth >= 2)
                        AND COALESCE(current_setting('authz.memoize', true), 'on') <> 'off'
                        AND COALESCE(current_setting('authz._memo_active_snap', true), 'off') = 'on';
    v_cached boolean;
    v_p0     bigint;
    v_result boolean;
BEGIN
    -- Root: (re)initialize the per-check snapshot memo. As with the live memo,
    -- the temp table cannot be created in a read-only transaction, so the memo
    -- is disabled there (the snapshot build itself already needs a writable txn,
    -- but this keeps the wrapper from being the failure point and stays
    -- symmetric with _check_access).
    IF p_depth = 0 THEN
        IF current_setting('transaction_read_only') = 'off' THEN
            CREATE TEMP TABLE IF NOT EXISTS _check_memo_snap
                (relation integer, object_type integer, object_id text, result boolean,
                 PRIMARY KEY (relation, object_type, object_id)) ON COMMIT DROP;
            TRUNCATE _check_memo_snap;
            PERFORM set_config('authz._memo_active_snap', 'on', false);
        ELSE
            PERFORM set_config('authz._memo_active_snap', 'off', false);
        END IF;
        PERFORM set_config('authz._memo_prunes_snap', '0', false);
    END IF;

    IF v_use THEN
        SELECT result INTO v_cached FROM _check_memo_snap
         WHERE relation = p_relation AND object_type = p_object_type AND object_id = p_object_id;
        IF FOUND THEN
            RETURN v_cached;
        END IF;
    END IF;

    v_p0 := COALESCE(NULLIF(current_setting('authz._memo_prunes_snap', true), '')::bigint, 0);

    v_result := authz._check_access_snapshot_impl(
        p_store_id, p_user_type, p_user_id, p_relation, p_object_type, p_object_id,
        p_request_context, p_depth, p_path);

    -- Cache only a path-independent (cycle-free) sub-result.
    IF v_use AND COALESCE(NULLIF(current_setting('authz._memo_prunes_snap', true), '')::bigint, 0) = v_p0 THEN
        INSERT INTO _check_memo_snap VALUES (p_relation, p_object_type, p_object_id, v_result)
        ON CONFLICT (relation, object_type, object_id) DO NOTHING;
    END IF;

    RETURN v_result;
END;
$$;
