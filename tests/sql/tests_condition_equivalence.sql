-- Property tests: SQL ≡ CEL condition equivalence.
--
-- The engine has two condition evaluators (the built-in 'sql' and the optional
-- 'cel'). For a set of expression PAIRS that are meant to be semantically
-- equivalent, this asserts the two evaluators agree on EVERY context in a
-- boundary-covering grid — a divergence is a real correctness bug in one
-- evaluator. The comparison runs through the dispatch chokepoint
-- authz._eval_condition_expr(lang, expr, request_ctx, stored_ctx).
--
-- 'sql' references context as $1->>'k' (request) / $2->>'k' (stored); 'cel' as
-- request.k / stored.k (the dispatcher wraps both bags as {request, stored}).
--
-- The whole suite is GATED on the CEL evaluator being installed — without
-- pg_cel it skips cleanly so the default stack stays green (run the CEL stack
-- with PGAUTHZ_CEL=1 ./bootstrap.sh).

SELECT _test_reset();

-- Agreement predicate: do the two evaluators return the same result?
-- IS NOT DISTINCT FROM so a NULL-vs-false divergence also counts as a mismatch.
CREATE FUNCTION pg_temp._csa(p_sql text, p_cel text, p_req jsonb, p_stored jsonb)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT authz._eval_condition_expr('sql', p_sql, p_req, p_stored)
           IS NOT DISTINCT FROM
           authz._eval_condition_expr('cel', p_cel, p_req, p_stored)
$$;

DO $$
BEGIN
    -- Skip cleanly when the optional CEL evaluator is absent.
    IF to_regprocedure('authz.cel_eval_bool(text, text)') IS NULL THEN
        PERFORM _test_assert_true('eq_00_cel_absent_skipped', true,
            'pg_cel not installed; SQL≡CEL equivalence checks skipped');
        RETURN;
    END IF;

    -- 1) boolean passthrough: request.ok
    PERFORM _test_assert('eq_01_bool_passthrough',
        (SELECT count(*) FILTER (WHERE NOT pg_temp._csa(
            '($1->>''ok'')::boolean', 'request.ok',
            jsonb_build_object('ok', ok), '{}'::jsonb))
         FROM unnest(ARRAY[true, false]) ok)::text, '0');

    -- 2) integer >= comparison across a boundary grid
    PERFORM _test_assert('eq_02_int_gte',
        (SELECT count(*) FILTER (WHERE NOT pg_temp._csa(
            '($1->>''a'')::int >= ($2->>''b'')::int', 'int(request.a) >= int(stored.b)',
            jsonb_build_object('a', a), jsonb_build_object('b', b)))
         FROM generate_series(-4, 4) a, generate_series(-4, 4) b)::text, '0');

    -- 3) integer equality
    PERFORM _test_assert('eq_03_int_eq',
        (SELECT count(*) FILTER (WHERE NOT pg_temp._csa(
            '($1->>''a'')::int = ($2->>''b'')::int', 'int(request.a) == int(stored.b)',
            jsonb_build_object('a', a), jsonb_build_object('b', b)))
         FROM generate_series(-4, 4) a, generate_series(-4, 4) b)::text, '0');

    -- 4) boolean AND / NOT over all combinations
    PERFORM _test_assert('eq_04_bool_and_not',
        (SELECT count(*) FILTER (WHERE NOT pg_temp._csa(
            '($1->>''p'')::boolean AND NOT ($2->>''q'')::boolean', 'request.p && !stored.q',
            jsonb_build_object('p', p), jsonb_build_object('q', q)))
         FROM unnest(ARRAY[true, false]) p, unnest(ARRAY[true, false]) q)::text, '0');

    -- 5) string equality
    PERFORM _test_assert('eq_05_string_eq',
        (SELECT count(*) FILTER (WHERE NOT pg_temp._csa(
            '($1->>''x'') = ($2->>''y'')', 'request.x == stored.y',
            jsonb_build_object('x', x), jsonb_build_object('y', y)))
         FROM unnest(ARRAY['a','b','c']) x, unnest(ARRAY['a','b','c']) y)::text, '0');

    -- 6) set membership (CEL `in` ≡ SQL `= ANY`)
    PERFORM _test_assert('eq_06_string_membership',
        (SELECT count(*) FILTER (WHERE NOT pg_temp._csa(
            '($1->>''role'') = ANY(ARRAY[''admin'',''editor''])',
            'request.role in ["admin", "editor"]',
            jsonb_build_object('role', role), '{}'::jsonb))
         FROM unnest(ARRAY['admin','editor','viewer','guest']) role)::text, '0');

    -- 7) timestamp ordering (RFC3339 UTC): the canonical time-window primitive
    PERFORM _test_assert('eq_07_timestamp_lt',
        (SELECT count(*) FILTER (WHERE NOT pg_temp._csa(
            '($1->>''now'')::timestamptz < ($2->>''until'')::timestamptz',
            'timestamp(request.now) < timestamp(stored.until)',
            jsonb_build_object('now', now_v), jsonb_build_object('until', until_v)))
         FROM unnest(ARRAY['2026-01-01T00:00:00Z','2026-06-01T12:00:00Z','2027-01-01T00:00:00Z']) now_v,
              unnest(ARRAY['2026-01-01T00:00:00Z','2026-06-01T12:00:00Z','2027-01-01T00:00:00Z']) until_v
        )::text, '0');
END;
$$;

SELECT _test_report('checks');
