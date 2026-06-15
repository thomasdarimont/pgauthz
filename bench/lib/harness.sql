-- Benchmark harness: shared setup + timing helper.
--
-- bench/run.sh loads this in the same psql session before each suite, so suite
-- files can call pg_temp._bench(...) and pg_temp._bench_title(...). Keep suites
-- free of timing/printing mechanics — they just build a model + data and call
-- these helpers.

-- Quiet the engine's per-iteration "CREATE TEMP TABLE IF NOT EXISTS ... skipping"
-- NOTICEs; results use RAISE INFO, which ignores client_min_messages.
SET client_min_messages = warning;

-- _bench(label, sql, iters): run `sql` `iters` times (after a warm-up
-- iteration) and print milliseconds per call.
CREATE OR REPLACE FUNCTION pg_temp._bench(p_label text, p_sql text, p_iters int) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE i int; t0 timestamptz; ms numeric;
BEGIN
    -- Warm up plan + buffer cache (steady-state numbers; a single iteration is
    -- not enough for queries that touch many pages, e.g. list_objects).
    FOR i IN 1..5 LOOP EXECUTE p_sql; END LOOP;
    t0 := clock_timestamp();
    FOR i IN 1..p_iters LOOP EXECUTE p_sql; END LOOP;
    ms := extract(epoch from clock_timestamp()-t0)*1000 / p_iters;
    RAISE INFO '% : % ms/op (% iters)', rpad(p_label, 50), to_char(ms, 'FM999990.000'), p_iters;
END $$;

-- _bench_title(text): a labelled section header in the output.
CREATE OR REPLACE FUNCTION pg_temp._bench_title(p_title text) RETURNS void
LANGUAGE plpgsql AS $$ BEGIN RAISE INFO '== % ==', p_title; END $$;
