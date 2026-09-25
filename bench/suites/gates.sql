-- Benchmark suite: the action log + temporal gates (ADR 0012).
--
-- Requires the harness (bench/lib/harness.sql) in the same psql session —
-- bench/run.sh does that. Uses its own 'bench_gates' store. Tunables are the
-- constants in the data-generation block.
--
-- What it isolates: the cost a gate adds to a check (one gate lookup + one
-- window query per clause) as a function of how many of the principal's
-- events fall inside the window (0 / 100 / 10,000), containment matching on
-- the payload, the traced (explain) and two-pass (detailed) paths, gated
-- enumeration (list_subjects evaluates per candidate), recording, and the
-- strict tier (reserve_event = decision + record under a per-subject lock).
-- The ungated relation on the same store is the baseline.

SELECT pg_temp._bench_title('Gates: action log + temporal gates over it');

-- ── Schema: model ───────────────────────────────────────────────────
DO $$ BEGIN PERFORM authz.delete_store('bench_gates', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END $$;
SELECT authz.create_store('bench_gates');

SELECT authz.model_register_type('bench_gates', t) FROM unnest(ARRAY['user','account']) t;
SELECT authz.model_register_relation('bench_gates', r)
  FROM unnest(ARRAY['transfer','pay','withdraw','approve_sale']) r;
SELECT authz.model_add_rule('bench_gates','account', r, 'direct')
  FROM unnest(ARRAY['transfer','pay','withdraw']) r;

-- pay: a velocity gate (count + sum, the sum keyed on the request context)
SELECT authz.add_gate('bench_gates','account','pay','velocity', '{
  "all_of": [
    {"count_within": {"window": "1h", "max": 1000000, "plus": 1}},
    {"sum_within":   {"window": "1h", "field": "input.amount",
                      "plus": "$request.amount", "max": 1000000000}}
  ]}');
-- withdraw: prior approval within the hour, matched on the payload
SELECT authz.add_gate('bench_gates','account','withdraw','four_eyes', '{
  "all_of": [{"formerly_within": {"window": "1h", "action": "approve_sale", "kind": "response",
                                  "match": {"input.stock": "$request.stock", "output.approved": true},
                                  "recorded_by": ["svc:approvals"]}}]}');

-- ── Data generation ─────────────────────────────────────────────────
DO $$
DECLARE
    -- tunables
    n_users     int := 2000;      -- subjects with a tuple on acc-1 (list_subjects candidates)
    n_noise     int := 200000;    -- background events of other principals (index selectivity)
    n_heavy     int := 10000;     -- events of the 'heavy' principal inside the window
    n_mid       int := 100;

    s          smallint := authz._s('bench_gates');
    t_user     smallint := authz._t(s,'user');
    t_acc      smallint := authz._t(s,'account');
    r_transfer smallint := authz._r(s,'transfer');
    r_pay      smallint := authz._r(s,'pay');
    r_withdraw smallint := authz._r(s,'withdraw');
    r_approve  smallint := authz._r(s,'approve_sale');
    t0         timestamptz := clock_timestamp();
BEGIN
    -- Tuples: every user may transfer / pay / withdraw on acc-1.
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_acc, 'acc-1', r, t_user, 'u'||g
      FROM generate_series(1, n_users) g CROSS JOIN unnest(ARRAY[r_transfer, r_pay, r_withdraw]) r;
    INSERT INTO authz.tuples (store_id, object_type, object_id, relation, user_type, user_id)
    SELECT s, t_acc, 'acc-1', r, t_user, u
      FROM unnest(ARRAY['light','mid','heavy','reserver']) u CROSS JOIN unnest(ARRAY[r_transfer, r_pay, r_withdraw]) r;

    -- Events: bulk-loaded straight into the log (the API path is timed below).
    -- Background: n_noise pay events spread over the last day across the users.
    INSERT INTO authz.events (store_id, subject_type, subject_id, action, object_type, object_id,
                              kind, payload, occurred_at, recorded_at, recorded_by)
    SELECT s, t_user, 'u'||(1 + g % n_users), r_pay, t_acc, 'acc-1',
           authz._event_kind_request(), jsonb_build_object('input', jsonb_build_object('amount', g % 500)),
           now() - (g % 86400) * interval '1 second', now(), 'bench'
      FROM generate_series(1, n_noise) g;
    -- 'heavy': n_heavy pay events inside the hour; 'mid': n_mid.
    INSERT INTO authz.events (store_id, subject_type, subject_id, action, object_type, object_id,
                              kind, payload, occurred_at, recorded_at, recorded_by)
    SELECT s, t_user, 'heavy', r_pay, t_acc, 'acc-1',
           authz._event_kind_request(), jsonb_build_object('input', jsonb_build_object('amount', g % 500)),
           now() - (g % 3500) * interval '1 second', now(), 'bench'
      FROM generate_series(1, n_heavy) g;
    INSERT INTO authz.events (store_id, subject_type, subject_id, action, object_type, object_id,
                              kind, payload, occurred_at, recorded_at, recorded_by)
    SELECT s, t_user, 'mid', r_pay, t_acc, 'acc-1',
           authz._event_kind_request(), jsonb_build_object('input', jsonb_build_object('amount', g % 500)),
           now() - (g % 3500) * interval '1 second', now(), 'bench'
      FROM generate_series(1, n_mid) g;
    -- 'heavy' also has n_heavy approve_sale responses for various stocks (one
    -- matching stock among many — containment must scan the window).
    INSERT INTO authz.events (store_id, subject_type, subject_id, action, object_type, object_id,
                              kind, payload, occurred_at, recorded_at, recorded_by)
    SELECT s, t_user, 'heavy', r_approve, NULL, NULL,
           authz._event_kind_response(),
           jsonb_build_object('input', jsonb_build_object('stock', 'S'||(g % 5000)), 'output', jsonb_build_object('approved', g % 2 = 0)),
           now() - (g % 3500) * interval '1 second', now(), 'svc:approvals'
      FROM generate_series(1, n_heavy) g;

    ANALYZE authz.events;
    ANALYZE authz.tuples;
    RAISE INFO 'data loaded in % ms (% users, % noise events, heavy=% mid=%); % events',
        round(extract(epoch from clock_timestamp()-t0)*1000), n_users, n_noise, n_heavy, n_mid,
        (SELECT count(*) FROM authz.events WHERE store_id = s);
END $$;

-- ── Scenarios ───────────────────────────────────────────────────────
SELECT pg_temp._bench('check_access  ungated relation (baseline)',
    $$ SELECT authz.check_access('bench_gates','user','heavy','transfer','account','acc-1') $$, 500);

SELECT pg_temp._bench('check_access  gated, 0 events in window',
    $$ SELECT authz.check_access_with_context('bench_gates','user','light','pay','account','acc-1','{"amount": 1}') $$, 500);

SELECT pg_temp._bench('check_access  gated, 100 events in window',
    $$ SELECT authz.check_access_with_context('bench_gates','user','mid','pay','account','acc-1','{"amount": 1}') $$, 500);

SELECT pg_temp._bench('check_access  gated, 10k events in window (count+sum)',
    $$ SELECT authz.check_access_with_context('bench_gates','user','heavy','pay','account','acc-1','{"amount": 1}') $$, 200);

SELECT pg_temp._bench('check_access  formerly_within + match over 10k events',
    $$ SELECT authz.check_access_with_context('bench_gates','user','heavy','withdraw','account','acc-1','{"stock": "S42"}') $$, 200);

SELECT pg_temp._bench('check_access  gated DENY on missing $request key',
    $$ SELECT authz.check_access('bench_gates','user','mid','pay','account','acc-1') $$, 500);

SELECT pg_temp._bench('explain_access  gated (traced, 2 clauses)',
    $$ SELECT authz.explain_access('bench_gates','user','mid','pay','account','acc-1','{"amount": 1}') $$, 200);

SELECT pg_temp._bench('check_access_detailed  conditional (2 passes)',
    $$ SELECT authz.check_access_detailed('bench_gates','user','mid','withdraw','account','acc-1') $$, 200);

SELECT pg_temp._bench('list_subjects ungated (2k candidates)',
    $$ SELECT count(*) FROM authz.list_subjects('bench_gates','user','transfer','account','acc-1') $$, 10);

SELECT pg_temp._bench('list_subjects gated (2k candidates, window each)',
    $$ SELECT count(*) FROM authz.list_subjects('bench_gates','user','pay','account','acc-1','{"amount": 1}') $$, 10);

SELECT pg_temp._bench('list_objects  gated (evaluated once up front)',
    $$ SELECT count(*) FROM authz.list_objects('bench_gates','user','heavy','pay','account','{"amount": 1}') $$, 100);

SELECT pg_temp._bench('list_actions  (3 relations, 2 gated)',
    $$ SELECT count(*) FROM authz.list_actions('bench_gates','user','mid','account','acc-1','{"amount": 1, "stock": "S42"}') $$, 200);

SELECT pg_temp._bench('audit_check_access  gated (time-travel)',
    $$ SELECT authz.audit_check_access('bench_gates','user','mid','pay','account','acc-1', now(), '{"amount": 1}') $$, 50);

SELECT pg_temp._bench('record_event  single',
    $$ SELECT authz.record_event('bench_gates','user','u1','pay','account','acc-1','request','{"input": {"amount": 1}}') $$, 500);

SELECT pg_temp._bench('record_events_jsonb  batch of 100',
    $$ SELECT authz.record_events_jsonb('bench_gates', (SELECT jsonb_agg(jsonb_build_object(
           'subject_type','user','subject_id','u'||g,'action','pay','object_type','account','object_id','acc-1',
           'payload', jsonb_build_object('input', jsonb_build_object('amount', 1)))) FROM generate_series(1,100) g)) $$, 50);

SELECT pg_temp._bench('reserve_event  (decision + record under lock)',
    $$ SELECT authz.reserve_event('bench_gates','user','reserver','pay','account','acc-1','{"input": {"amount": 1}}','{"amount": 1}') $$, 300);

SELECT pg_temp._bench('list_events  page of 100 (auditor)',
    $$ SELECT count(*) FROM authz.list_events('bench_gates', p_subject_type => 'user', p_subject_id => 'heavy', p_limit => 100) $$, 200);

-- Tidy up (idempotent; the suite also resets at the top).
DO $$ BEGIN PERFORM authz.delete_store('bench_gates', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END $$;
