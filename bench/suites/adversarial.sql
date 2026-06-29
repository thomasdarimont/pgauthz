-- Benchmark suite: ADVERSARIAL graph shapes — worst case for an evaluator that
-- does not memoize sub-results across branches.
--
-- Requires the harness (bench/lib/harness.sql) in the same psql session.
-- Uses its own 'bench_adv' store.
--
-- The engine prunes CYCLES (a path array stops a node already on the current
-- path) but does NOT cache a completed sub-result, so a node reachable via many
-- distinct (acyclic) paths is re-evaluated once per path. Two shapes expose it:
--
--   1. DIAMOND CHAIN — each link is doubled (node_i has BOTH parent_a and
--      parent_b pointing to node_{i+1}). check_access at the root reaches
--      node_i via 2^i paths, so a DENY (no grant anywhere) explores 2^depth
--      sub-evaluations: time should ~QUADRUPLE per +2 depth. This is the
--      headline worst case.
--   2. WIDE FAN-OUT — one root with N parent edges all converging on a single
--      dead-end child: the child is re-evaluated N times (linear redundancy).
--
-- A per-call memo (cache completed (relation,object) sub-results within one
-- check) would collapse both to roughly linear. See docs/BENCHMARKS.md.

SELECT pg_temp._bench_title('Adversarial: diamond / converging graphs (no cross-branch memoization)');

-- ── Schema: model ───────────────────────────────────────────────────
DO $$ BEGIN PERFORM authz.delete_store('bench_adv', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END $$;
SELECT authz.create_store('bench_adv');

SELECT authz.model_register_type('bench_adv', t) FROM unnest(ARRAY['user','node']) t;
SELECT authz.model_register_relation('bench_adv', r)
  FROM unnest(ARRAY['parent_a','parent_b','viewer','can_view']) r;

-- node.can_view = viewer OR parent_a->can_view OR parent_b->can_view
SELECT authz.model_add_rule('bench_adv','node','can_view','computed', p_computed_relation=>'viewer');
SELECT authz.model_add_rule('bench_adv','node','can_view','ttu', p_tupleset_relation=>'parent_a', p_tupleset_computed=>'can_view');
SELECT authz.model_add_rule('bench_adv','node','can_view','ttu', p_tupleset_relation=>'parent_b', p_tupleset_computed=>'can_view');

-- ── Data generation ─────────────────────────────────────────────────
DO $$
DECLARE
    -- tunables
    fanout int := 500;            -- wide-convergence width

    s    int := authz._s('bench_adv');
    tn   int := authz._t(s,'node');
    pa   int := authz._r(s,'parent_a');
    pb   int := authz._r(s,'parent_b');
    t0   timestamptz := clock_timestamp();
    d    int;
BEGIN
    -- Diamond chains at three depths. Chain "d<D>": d<D>_0 .. d<D>_D, every
    -- link doubled (parent_a AND parent_b both point to the next node), so the
    -- root d<D>_0 reaches the leaf via 2^D acyclic paths. No viewer anywhere →
    -- check_access is a DENY that must explore every path.
    FOREACH d IN ARRAY ARRAY[6, 9, 12] LOOP
        INSERT INTO authz.tuples(store_id,object_type,object_id,relation,user_type,user_id)
        SELECT s, tn, 'd'||d||'_'||(lvl-1), pa, tn, 'd'||d||'_'||lvl FROM generate_series(1, d) lvl;
        INSERT INTO authz.tuples(store_id,object_type,object_id,relation,user_type,user_id)
        SELECT s, tn, 'd'||d||'_'||(lvl-1), pb, tn, 'd'||d||'_'||lvl FROM generate_series(1, d) lvl;
    END LOOP;

    -- Wide convergence: 'wroot' fans out to `fanout` distinct intermediates,
    -- each of which points at the single dead-end 'wleaf' → wleaf is
    -- re-evaluated `fanout` times (linear redundancy, no grant anywhere).
    INSERT INTO authz.tuples(store_id,object_type,object_id,relation,user_type,user_id)
    SELECT s, tn, 'wroot', pa, tn, 'wi'||k FROM generate_series(1, fanout) k;
    INSERT INTO authz.tuples(store_id,object_type,object_id,relation,user_type,user_id)
    SELECT s, tn, 'wi'||k, pa, tn, 'wleaf' FROM generate_series(1, fanout) k;

    ANALYZE authz.tuples;
    RAISE INFO 'data loaded in % ms (diamond depths 6/9/12, fan-out %); % tuples',
        round(extract(epoch from clock_timestamp()-t0)*1000), fanout,
        (SELECT count(*) FROM authz.tuples WHERE store_id = s);
END $$;

-- ── Scenarios ───────────────────────────────────────────────────────
-- Exponential blow-up: each +3 depth should ~×8 the time (2^depth paths).
SELECT pg_temp._bench('check_access DENY  diamond depth 6   (2^6 = 64 paths)',
    $$ SELECT authz.check_access('bench_adv','user','nobody','can_view','node','d6_0') $$, 50);

SELECT pg_temp._bench('check_access DENY  diamond depth 9   (2^9 = 512 paths)',
    $$ SELECT authz.check_access('bench_adv','user','nobody','can_view','node','d9_0') $$, 15);

SELECT pg_temp._bench('check_access DENY  diamond depth 12  (2^12 = 4096 paths)',
    $$ SELECT authz.check_access('bench_adv','user','nobody','can_view','node','d12_0') $$, 5);

-- Linear redundancy: one root, 500 parents converging on one dead-end child.
SELECT pg_temp._bench('check_access DENY  wide fan-out (500 converging parents)',
    $$ SELECT authz.check_access('bench_adv','user','nobody','can_view','node','wroot') $$, 30);

-- Tidy up (idempotent; the suite also resets at the top).
DO $$ BEGIN PERFORM authz.delete_store('bench_adv', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END $$;
