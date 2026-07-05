-- Decision explanation API: explain_access and its helpers.
-- Returns a structured "why" (decision + typed reason codes), a flat
-- evaluation trace, and the same steps as a nested resolution tree, with
-- an optional redacted safety mode.
--
-- Depends on: engine/core_internal.sql, engine/access_internal.sql

------------------------------------------------------------------------
-- _explain_reason: maps a trace step (rule_type + result + detail) to a
-- stable, typed reason code for the structured explain_access output.
-- Keeping the mapping in one place keeps the JSON contract stable.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._explain_reason(
    p_rule_type text, p_result boolean, p_detail text
) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE p_rule_type
        WHEN 'cycle'        THEN 'cycle_pruned'
        WHEN 'computed'     THEN 'computed'
        WHEN 'ttu'          THEN 'ttu'
        WHEN 'userset'      THEN 'userset'
        WHEN 'intersection' THEN CASE WHEN p_result THEN 'intersection_satisfied'
                                                    ELSE 'intersection_unsatisfied' END
        WHEN 'exclusion'    THEN CASE WHEN p_result THEN 'exclusion_satisfied'
                                                    ELSE 'exclusion_failed' END
        WHEN 'direct'       THEN CASE
            WHEN p_detail = 'tuple found'               THEN 'direct_tuple'
            WHEN p_detail = 'object wildcard tuple (*)' THEN 'object_wildcard_tuple'
            WHEN p_detail = 'wildcard tuple (*)'        THEN 'wildcard_tuple'
            WHEN p_detail = 'contextual tuple'          THEN 'contextual_tuple'
            WHEN p_detail LIKE '%condition%denied%'     THEN 'condition_denied'
            WHEN p_detail = 'no tuple'                  THEN 'no_direct_tuple'
            ELSE 'direct'
        END
        ELSE p_rule_type
    END
$$;

------------------------------------------------------------------------
-- _explain_tree: reconstructs the nested resolution tree from the flat,
-- evaluation-ordered trace steps. Steps are emitted children-before-
-- parent (post-order), and each step's `depth` is its recursion depth,
-- so when a step is processed all of its descendants are already on the
-- stack at a greater depth. Returns an array of root-level step nodes
-- (each with a recursive `children` array); explain_access wraps these
-- under a synthetic root carrying the overall decision.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._explain_tree(p_steps jsonb)
RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    v_stack    jsonb := '[]'::jsonb;   -- of { "depth": int, "node": {..} }
    s          jsonb;
    v_depth    int;
    v_children jsonb;
    v_node     jsonb;
BEGIN
    FOR s IN
        SELECT elem FROM jsonb_array_elements(p_steps) WITH ORDINALITY AS a(elem, ord)
         ORDER BY ord
    LOOP
        v_depth    := (s->>'depth')::int;
        v_children := '[]'::jsonb;
        -- Pop this step's children: the deeper pending subtrees on top of
        -- the stack. Prepend each to restore left-to-right order.
        WHILE jsonb_array_length(v_stack) > 0
              AND ((v_stack -> -1) ->> 'depth')::int > v_depth LOOP
            v_children := jsonb_build_array((v_stack -> -1) -> 'node') || v_children;
            v_stack := v_stack - -1;   -- pop last
        END LOOP;
        v_node  := s || jsonb_build_object('children', v_children);
        v_stack := v_stack || jsonb_build_array(jsonb_build_object('depth', v_depth, 'node', v_node));
    END LOOP;

    -- Remaining entries are the shallowest (root-level) steps, in order.
    SELECT coalesce(jsonb_agg(a.elem -> 'node' ORDER BY a.ord), '[]'::jsonb)
      INTO v_children
      FROM jsonb_array_elements(v_stack) WITH ORDINALITY AS a(elem, ord);
    RETURN v_children;
END;
$$;

------------------------------------------------------------------------
-- explain_access: like check_access, but returns a structured decision
-- explanation:
--
--   {
--     "result":   bool,                  -- alias of decision.allowed
--     "decision": { "allowed": bool,
--                   "reason":  <typed reason code> },
--     "summary":  text,                  -- human-readable resolution tree
--     "trace":    [ { step, depth, rule_type, reason, subject, relation,
--                     object, result, detail, duration_ms,
--                     model_rule_id, group_id, group_op, negated,
--                     condition_name, condition_missing_keys }, ... ],
--     "tree":     { subject, relation, object, allowed, reason,
--                   children: [ <trace step + nested children>, ... ] }
--   }
--
-- `trace` is the flat, evaluation-ordered step list. `tree` is the same
-- steps reshaped into the nested resolution tree (a synthetic root with
-- the decision, the recursion nested underneath) for direct rendering.
--
-- decision.reason is the minimal cause: for ALLOW, the shallowest
-- granting step's reason (e.g. direct_tuple, wildcard_tuple, computed,
-- intersection_satisfied); for DENY, one of excluded /
-- intersection_unsatisfied / condition_denied / no_matching_rule.
--
-- p_redact: safety mode for surfacing explanations to untrusted UIs —
-- strips subject/object identifiers and free-text detail, keeping only
-- the typed structure (types, relations, reasons, results).
--
-- Examples:
--   SELECT authz.explain_access('demo',
--       'internal_user', 'alice', 'can_read', 'document', 'doc_payroll_001');
--   SELECT authz.explain_access('demo', ..., p_redact => true);
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.explain_access(
    p_store           text,
    p_user_type       text,
    p_user_id         text,
    p_relation        text,
    p_object_type     text,
    p_object_id       text,
    context           jsonb DEFAULT NULL,
    p_successful_only boolean DEFAULT false,
    p_redact          boolean DEFAULT false
) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id    integer := authz._s(p_store);
    v_user_type   integer := authz._t(v_store_id, p_user_type);
    v_relation    integer := authz._r(v_store_id, p_relation);
    v_object_type integer := authz._t(v_store_id, p_object_type);
    v_result          boolean;
    v_trace           jsonb;
    v_tree            jsonb;
    v_summary         text;
    v_decision_reason text;
    t         record;
    v_indent  text;
    v_icon    text;
    v_line    text;
BEGIN
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');

    -- Reuse trace table within the session; ON COMMIT DROP cleans up.
    CREATE TEMP TABLE IF NOT EXISTS _access_trace (
        step          serial,
        depth         int,
        rule_type     text,
        subject       text,
        relation      text,
        object        text,
        result        boolean,
        detail        text,
        duration_ms   double precision,
        -- model rule references (NULL for cycle/group-verdict steps)
        model_rule_id integer,
        group_id      integer,
        group_op      integer,
        negated       boolean,
        -- condition explain (set only on condition_denied steps)
        condition_name        text,
        condition_missing_keys text[],
        -- the exact stored tuple that granted this step, in `subject → relation →
        -- object` form with * wildcards (NULL for non-tuple / denied steps).
        matched_tuple text
    ) ON COMMIT DROP;
    TRUNCATE _access_trace RESTART IDENTITY;
    PERFORM set_config('authz.trace', 'on', true);

    v_result := authz._check_access(
        v_store_id,
        v_user_type,
        p_user_id,
        v_relation,
        v_object_type,
        p_object_id,
        context
    );
    PERFORM set_config('authz.trace', 'off', true);

    -- Decision reason: minimal cause of the outcome.
    IF v_result THEN
        SELECT authz._explain_reason(s.rule_type, s.result, s.detail)
          INTO v_decision_reason
          FROM _access_trace s
         WHERE s.result
         ORDER BY s.depth ASC, s.step DESC
         LIMIT 1;
        v_decision_reason := COALESCE(v_decision_reason, 'allowed');
    ELSE
        v_decision_reason := CASE
            WHEN EXISTS (SELECT 1 FROM _access_trace s
                          WHERE NOT s.result AND s.rule_type = 'exclusion')      THEN 'excluded'
            WHEN EXISTS (SELECT 1 FROM _access_trace s
                          WHERE NOT s.result AND s.rule_type = 'intersection')   THEN 'intersection_unsatisfied'
            WHEN EXISTS (SELECT 1 FROM _access_trace s
                          WHERE authz._explain_reason(s.rule_type, s.result, s.detail) = 'condition_denied')
                                                                                 THEN 'condition_denied'
            ELSE 'no_matching_rule'
        END;
    END IF;

    -- Build the trace JSON (redaction strips ids and free-text detail).
    SELECT coalesce(jsonb_agg(
        jsonb_build_object(
            'step',      s.step,
            'depth',     s.depth,
            'rule_type', s.rule_type,
            'reason',    authz._explain_reason(s.rule_type, s.result, s.detail),
            'subject',   CASE WHEN p_redact THEN split_part(s.subject, ':', 1) || ':***' ELSE s.subject END,
            'relation',  s.relation,
            'object',    CASE WHEN p_redact THEN split_part(s.object, ':', 1) || ':***' ELSE s.object END,
            'result',    s.result,
            'detail',    CASE WHEN p_redact THEN NULL ELSE s.detail END,
            -- model rule references (structural, not redacted)
            'model_rule_id', s.model_rule_id,
            'group_id',  s.group_id,
            'group_op',  CASE s.group_op WHEN 0 THEN 'or' WHEN 1 THEN 'intersection'
                                         WHEN 2 THEN 'exclusion' END,
            'negated',   s.negated,
            -- condition explain: which condition denied and which
            -- required context keys were missing (null on non-condition steps)
            'condition_name',         s.condition_name,
            'condition_missing_keys', to_jsonb(s.condition_missing_keys),
            -- exact stored tuple that granted this step (null on non-tuple steps);
            -- redacted along with other identifiers.
            'matched_tuple', CASE WHEN p_redact THEN NULL ELSE s.matched_tuple END,
            'duration_ms', round(s.duration_ms::numeric, 3)
        ) ORDER BY s.step
    ), '[]'::jsonb)
    INTO v_trace
    FROM _access_trace s
    WHERE (NOT p_successful_only OR s.result);

    -- Build human-readable summary.
    IF p_redact THEN
        v_summary := p_user_type || ' → ' || p_relation || ' → ' || p_object_type
                  || ' = ' || CASE WHEN v_result THEN 'ALLOWED' ELSE 'DENIED' END
                  || ' (' || v_decision_reason || ')';
    ELSE
        v_summary := p_user_type || ':' || p_user_id || ' → ' || p_relation
                  || ' → ' || p_object_type || ':' || p_object_id
                  || ' = ' || CASE WHEN v_result THEN 'ALLOWED' ELSE 'DENIED' END
                  || ' (' || v_decision_reason || ')' || E'\n';

        FOR t IN SELECT * FROM _access_trace at
                  WHERE (NOT p_successful_only OR at.result)
                  ORDER BY at.step
        LOOP
            v_indent := repeat('  ', t.depth);
            v_icon   := CASE WHEN t.result THEN '✓' ELSE '✗' END;
            v_line   := v_indent
                     || v_icon || ' '
                     || '[' || authz._explain_reason(t.rule_type, t.result, t.detail) || '] '
                     || t.relation || ' on ' || t.object
                     || ' — ' || t.detail
                     || ' (' || round(t.duration_ms::numeric, 3) || ' ms)';
            v_summary := v_summary || v_line || E'\n';
        END LOOP;
    END IF;

    -- Nested resolution tree: the same steps as `trace`, reshaped under a
    -- synthetic root that carries the overall decision.
    v_tree := jsonb_build_object(
        'subject',  CASE WHEN p_redact THEN p_user_type   || ':***'
                         ELSE p_user_type   || ':' || p_user_id END,
        'relation', p_relation,
        'object',   CASE WHEN p_redact THEN p_object_type || ':***'
                         ELSE p_object_type || ':' || p_object_id END,
        'allowed',  v_result,
        'reason',   v_decision_reason,
        'children', authz._explain_tree(v_trace)
    );

    RETURN jsonb_build_object(
        'result',   v_result,
        'decision', jsonb_build_object('allowed', v_result, 'reason', v_decision_reason),
        'summary',  v_summary,
        'trace',    v_trace,
        'tree',     v_tree
    );
END;
$$;

------------------------------------------------------------------------
-- check_access_detailed: a check that says WHICH KIND of "no" (and "yes").
--
-- The boolean API deliberately collapses "a condition would have granted
-- but its required context was missing" into deny (fail closed — correct
-- default). This opt-in variant surfaces the distinction the engine
-- already tracks (explain_access's condition_missing_keys), so callers
-- can react to CONDITIONAL denials (e.g. AuthZEN step-up: supply the
-- missing context and re-check) instead of treating them as final.
--
--   {
--     "decision": false,
--     "state":    "allow" | "deny" | "conditional",
--     "reason":   <explain decision reason, e.g. no_match | excluded>,
--     "missing_context": ["current_time", ...],   -- union over the trace
--     "conditions":      ["biz_hours", ...],      -- conditions lacking input
--     "model": {"name": ..., "version": ...} | null,  -- registry-managed stores
--     "store": <store>
--   }
--
-- state=conditional ⇒ decision=false AND at least one condition failed
-- ONLY for lack of required context. Errors raise (unchanged); the HTTP
-- tiers map them to their own error envelope. Cost: this runs the full
-- explain machinery — per-decision opt-in, not a hot-path default.
--
-- `state` is COMPOSITIONAL. A denied decision is `conditional` only when
-- supplying the missing context could actually flip it — proven by a second,
-- OPTIMISTIC evaluation (authz._assume_missing_ctx) that treats conditions
-- failing solely for missing context as passing. If that optimistic pass still
-- denies, a structural deny remains (e.g. `A AND B` with A conditional and B a
-- hard deny) → `deny`. `allow` fires only on the real boolean decision, so no
-- authorization is ever wrong. Cost: two evaluations on the opt-in detailed
-- path (only when the first denies AND missing keys exist).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.check_access_detailed(
    p_store       text,
    p_user_type   text,
    p_user_id     text,
    p_relation    text,
    p_object_type text,
    p_object_id   text,
    context       jsonb DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v_explain jsonb;
    v_allowed boolean;
    v_missing jsonb;
    v_conds   jsonb;
    v_model   jsonb;
    v_state   text;
BEGIN
    v_explain := authz.explain_access(p_store, p_user_type, p_user_id,
                                      p_relation, p_object_type, p_object_id,
                                      context);
    v_allowed := (v_explain->'decision'->>'allowed')::boolean;

    SELECT COALESCE(jsonb_agg(DISTINCT k ORDER BY k), '[]'::jsonb)
      INTO v_missing
      FROM jsonb_array_elements(v_explain->'trace') AS t(e)
      CROSS JOIN LATERAL jsonb_array_elements_text(t.e->'condition_missing_keys') AS m(k)
     WHERE jsonb_typeof(t.e->'condition_missing_keys') = 'array';

    SELECT COALESCE(jsonb_agg(DISTINCT t.e->>'condition_name'
                              ORDER BY t.e->>'condition_name'), '[]'::jsonb)
      INTO v_conds
      FROM jsonb_array_elements(v_explain->'trace') AS t(e)
     WHERE jsonb_typeof(t.e->'condition_missing_keys') = 'array'
       AND jsonb_array_length(t.e->'condition_missing_keys') > 0
       AND t.e->>'condition_name' IS NOT NULL;

    SELECT jsonb_build_object('name', s.model_name, 'version', s.model_version)
      INTO v_model
      FROM authz.store_model_state s
     WHERE s.store_id = authz._s(p_store);

    -- Compositional classification. A denied decision is `conditional` only
    -- if supplying the missing context COULD flip it — verified by a second,
    -- OPTIMISTIC evaluation that treats conditions failing solely for missing
    -- context as passing (authz._assume_missing_ctx). If that optimistic check
    -- ALSO denies, there is a structural deny the context cannot repair (e.g.
    -- `A AND B` with A conditional-on-missing and B a hard deny) → `deny`, not
    -- `conditional`. This never over-reports `allow` (that stays the real
    -- boolean) and no longer over-reports `conditional`.
    IF v_allowed THEN
        v_state := 'allow';
    ELSIF jsonb_array_length(v_missing) > 0 THEN
        PERFORM set_config('authz._assume_missing_ctx', 'on', true);
        IF authz.check_access_with_context(p_store, p_user_type, p_user_id,
                                           p_relation, p_object_type, p_object_id, context) THEN
            v_state := 'conditional';
        ELSE
            v_state := 'deny';
        END IF;
        PERFORM set_config('authz._assume_missing_ctx', '', true);
    ELSE
        v_state := 'deny';
    END IF;

    RETURN jsonb_build_object(
        'decision',        v_allowed,
        'state',           v_state,
        'reason',          v_explain->'decision'->>'reason',
        'missing_context', v_missing,
        'conditions',      v_conds,
        'model',           v_model,
        'store',           p_store);
END;
$$;
