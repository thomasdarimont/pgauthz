-- Action log (authz.events) — the WRITE side: recording events and partition
-- maintenance/retention. Part of the WRITE profile (a read-only install has
-- the table and list_events but cannot record). ADR 0012.
--
-- Three ways in, one SQL chokepoint: SQL callers use record_event /
-- record_events_jsonb directly; pgauthzd's POST /pgauthz/v1/events calls
-- record_events_jsonb; a queue consumer POSTs to pgauthzd. Both functions are
-- the ONLY path that inserts into authz.events (no role holds INSERT; the
-- append-only trigger in audit_triggers.sql blocks UPDATE/DELETE).
--
-- Depends on: core_internal.sql (_s/_t/_r, _check_namespace_access,
-- _max_context_bytes, _ensure_month_partition), events.sql (kinds, bounds).

------------------------------------------------------------------------
-- _check_recorder_action: per-recorder action allowlists (migration 0013).
-- Mirrors _check_namespace_access: if the store has allowlist rows for any
-- role the effective role is a member of, the action must be among them;
-- roles without rows are unrestricted. Raises like the namespace check
-- ("Permission denied: ..."), which pgauthzd maps to 403.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._check_recorder_action(
    p_store_id integer,
    p_action   integer
) RETURNS void
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_role text := authz._effective_role();
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM authz.recorder_actions ra
         WHERE ra.store_id = p_store_id
           AND pg_has_role(v_role, ra.db_role, 'MEMBER')
    ) THEN
        RETURN;   -- no allowlist applies to this role: unrestricted
    END IF;
    IF EXISTS (
        SELECT 1 FROM authz.recorder_actions ra
         WHERE ra.store_id = p_store_id
           AND ra.action   = p_action
           AND pg_has_role(v_role, ra.db_role, 'MEMBER')
    ) THEN
        RETURN;
    END IF;
    RAISE EXCEPTION 'Permission denied: role "%" may not record action "%" in store "%" (not in its recorder allowlist)',
        v_role,
        (SELECT r.name FROM authz.relations r WHERE r.id = p_action),
        (SELECT st.name FROM authz.stores st WHERE st.id = p_store_id);
END;
$$;

------------------------------------------------------------------------
-- record_event: record that p_subject ACTUALLY performed p_action (on
-- p_object, if any). Returns the event's seq, or NULL when p_event_id was
-- already recorded for this store (idempotent re-delivery: no second row).
--
-- Trust model: the recorder is trusted for its assertion exactly as a tuple
-- writer is trusted for its tuples. What the engine enforces:
--   - the action must be a declared relation of the store (the model is the
--     action vocabulary — a typo fails loud here, not silently later);
--   - the subject is a concrete principal (no wildcard, no userset);
--   - the action must be in the caller's recorder allowlist when the store
--     has one for a role it is a member of (grant_recorder_actions);
--   - object-scoped events respect namespace isolation: recording about an
--     object type in a namespace needs the same can_write grant tuple
--     writes need (an app records what it may manage);
--   - payload is an object bounded by authz.max_context_bytes (F5);
--   - occurred_at is bounded: not beyond authz.event_max_future_skew ahead
--     of, nor beyond authz.event_max_backdate behind, the database clock.
--     Absent, it is the database clock (= recorded_at).
--   - recorded_by: the caller's assertion (pgauthzd passes the verified
--     subject), falling back to the effective DB role — the performed_by
--     convention of the write API.
--
-- Errors use invalid_parameter_value (22023) for caller mistakes so the
-- HTTP layer can map them to 4xx; name-resolution failures raise from
-- _t/_r as usual.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.record_event(
    p_store        text,
    p_subject_type text,
    p_subject_id   text,
    p_action       text,
    p_object_type  text        DEFAULT NULL,
    p_object_id    text        DEFAULT NULL,
    p_kind         text        DEFAULT 'request',
    p_payload      jsonb       DEFAULT '{}',
    p_occurred_at  timestamptz DEFAULT NULL,
    p_event_id     text        DEFAULT NULL,
    p_recorded_by  text        DEFAULT NULL
) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id     integer := authz._s(p_store);
    v_subject_type integer := authz._t(v_store_id, p_subject_type);
    v_action       integer := authz._r(v_store_id, p_action);
    v_object_type  integer;
    v_kind         smallint := authz._event_kind(COALESCE(p_kind, 'request'));
    -- clock_timestamp(): the actual instant of the insert. statement_timestamp()
    -- would be the statement's START — for reserve_event that predates the wait
    -- for its lock, which both misfiles occurred_at behind events recorded
    -- meanwhile and could flag a genuinely-now occurred_at as future skew.
    v_now          timestamptz := clock_timestamp();
    v_occurred_at  timestamptz := COALESCE(p_occurred_at, v_now);   -- same instant as recorded_at
    v_payload      jsonb := COALESCE(p_payload, '{}'::jsonb);
    v_seq          bigint;
BEGIN
    IF p_subject_id IS NULL OR p_subject_id = '' THEN
        RAISE EXCEPTION 'subject_id is required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_subject_id = '*' THEN
        RAISE EXCEPTION 'events are recorded for concrete principals, not the wildcard subject (*)'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_object_id IS NOT NULL AND p_object_type IS NULL THEN
        RAISE EXCEPTION 'object_id requires object_type' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A recorder records the actions it is allowed to (per-recorder allowlist,
    -- migration 0013; unrestricted when none applies to its role).
    PERFORM authz._check_recorder_action(v_store_id, v_action);
    IF p_object_type IS NOT NULL THEN
        v_object_type := authz._t(v_store_id, p_object_type);
        -- An app records about the objects it may manage (namespace isolation).
        PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_write');
    END IF;

    IF jsonb_typeof(v_payload) <> 'object' THEN
        RAISE EXCEPTION 'payload must be a JSON object (got %)', jsonb_typeof(v_payload)
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF pg_column_size(v_payload) > authz._max_context_bytes() THEN
        RAISE EXCEPTION 'event payload exceeds the %-byte limit (authz.max_context_bytes)',
            authz._max_context_bytes()
            USING ERRCODE = 'program_limit_exceeded';
    END IF;

    IF v_occurred_at > v_now + authz._event_max_future_skew() THEN
        RAISE EXCEPTION 'occurred_at (%) is more than % in the future (authz.event_max_future_skew)',
            v_occurred_at, authz._event_max_future_skew()
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF v_occurred_at < v_now - authz._event_max_backdate() THEN
        RAISE EXCEPTION 'occurred_at (%) is more than % in the past (authz.event_max_backdate)',
            v_occurred_at, authz._event_max_backdate()
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    IF p_event_id = '' THEN
        RAISE EXCEPTION 'event_id must not be empty (omit it for no idempotency key)'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- The idempotency index is (store_id, event_id, occurred_at): the partition
    -- key must be part of every unique index on a partitioned table. A retry
    -- that let occurred_at default to the (new) database clock would therefore
    -- slip past it and count twice — so an idempotency key must come with the
    -- message's own timestamp. Fail loud rather than silently non-idempotent.
    IF p_event_id IS NOT NULL AND p_occurred_at IS NULL THEN
        RAISE EXCEPTION 'event_id requires occurred_at (the idempotency key is stable only with the message''s own timestamp)'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    INSERT INTO authz.events (
        store_id, event_id, subject_type, subject_id, action, object_type, object_id,
        kind, payload, occurred_at, recorded_at, recorded_by
    ) VALUES (
        v_store_id, p_event_id, v_subject_type, p_subject_id, v_action, v_object_type, p_object_id,
        v_kind, v_payload, v_occurred_at, v_now,
        COALESCE(NULLIF(p_recorded_by, ''), authz._effective_role())
    )
    ON CONFLICT (store_id, event_id, occurred_at) WHERE event_id IS NOT NULL DO NOTHING
    RETURNING seq INTO v_seq;

    RETURN v_seq;   -- NULL: duplicate delivery, nothing inserted
END;
$$;

------------------------------------------------------------------------
-- record_events_jsonb: the batch form pgauthzd uses. p_events is a JSONB
-- array of objects in the flat write_tuples_jsonb style:
--   {"subject_type": "user", "subject_id": "alice", "action": "transfer",
--    "object_type": "account", "object_id": "acc-1",          -- optional
--    "kind": "request",                                        -- optional, default request
--    "payload": {"input": {"amount": 1200}},                   -- optional
--    "occurred_at": "2026-09-17T10:15:02.113Z",                -- optional; required with event_id
--    "event_id": "req-7f3a/request"}                           -- optional idempotency key
-- Atomic: the batch is one transaction, so any invalid element raises and
-- nothing is recorded (same contract as write_tuples_jsonb). Returns
--   {"recorded": n, "duplicates": n, "seqs": [seq | null, ...]}
-- where seqs is positional (null = that element was a duplicate).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.record_events_jsonb(
    p_store       text,
    p_events      jsonb,
    p_recorded_by text DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    e            jsonb;
    v_idx        int := 0;
    v_seq        bigint;
    v_recorded   int := 0;
    v_duplicates int := 0;
    v_seqs       jsonb := '[]'::jsonb;
    v_key        text;
BEGIN
    IF p_events IS NULL OR jsonb_typeof(p_events) <> 'array' THEN
        RAISE EXCEPTION 'events must be a JSON array' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    FOR e IN SELECT * FROM jsonb_array_elements(p_events) LOOP
        IF jsonb_typeof(e) <> 'object' THEN
            RAISE EXCEPTION 'events[%] must be an object', v_idx USING ERRCODE = 'invalid_parameter_value';
        END IF;
        FOREACH v_key IN ARRAY ARRAY['subject_type', 'subject_id', 'action'] LOOP
            IF NOT (e ? v_key) OR jsonb_typeof(e -> v_key) <> 'string' THEN
                RAISE EXCEPTION 'events[%] is missing required string key "%"', v_idx, v_key
                    USING ERRCODE = 'invalid_parameter_value';
            END IF;
        END LOOP;
        FOR v_key IN SELECT jsonb_object_keys(e) LOOP
            IF v_key NOT IN ('subject_type', 'subject_id', 'action', 'object_type', 'object_id',
                             'kind', 'payload', 'occurred_at', 'event_id') THEN
                RAISE EXCEPTION 'events[%] has unknown key "%"', v_idx, v_key
                    USING ERRCODE = 'invalid_parameter_value';
            END IF;
        END LOOP;

        v_seq := authz.record_event(
            p_store,
            e ->> 'subject_type', e ->> 'subject_id', e ->> 'action',
            e ->> 'object_type', e ->> 'object_id',
            COALESCE(e ->> 'kind', 'request'),
            COALESCE(e -> 'payload', '{}'::jsonb),
            (e ->> 'occurred_at')::timestamptz,
            e ->> 'event_id',
            p_recorded_by);

        IF v_seq IS NULL THEN
            v_duplicates := v_duplicates + 1;
        ELSE
            v_recorded := v_recorded + 1;
        END IF;
        v_seqs := v_seqs || jsonb_build_array(v_seq);   -- [null] for a duplicate
        v_idx := v_idx + 1;
    END LOOP;

    RETURN jsonb_build_object('recorded', v_recorded, 'duplicates', v_duplicates, 'seqs', v_seqs);
END;
$$;

------------------------------------------------------------------------
-- Partition maintenance — mirrors ensure_audit_partitions (audit.sql) over
-- the shared _ensure_month_partition worker — and retention: fleet-wide by
-- partition drop (drop_event_partitions_before), per-store by row delete
-- (purge_events).
------------------------------------------------------------------------

-- _ensure_event_partition: create authz.events_YYYY_MM (idempotent; moves
-- that month's rows out of events_default). Returns true when created.
CREATE OR REPLACE FUNCTION authz._ensure_event_partition(
    p_year  int,
    p_month int
) RETURNS boolean
LANGUAGE plpgsql AS $$
BEGIN
    RETURN authz._ensure_month_partition('events', 'occurred_at', p_year, p_month);
END;
$$;

-- ensure_event_partitions: current month + p_months_ahead following months.
-- Schedule it alongside ensure_audit_partitions (init.sh and the migration
-- runner call both once at install). Returns the number created.
CREATE OR REPLACE FUNCTION authz.ensure_event_partitions(
    p_months_ahead int DEFAULT 1
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_created int := 0;
    v_month   date;
    i         int;
BEGIN
    IF p_months_ahead < 0 THEN
        RAISE EXCEPTION 'p_months_ahead must be >= 0';
    END IF;

    FOR i IN 0 .. p_months_ahead LOOP
        v_month := (date_trunc('month', now()) + make_interval(months => i))::date;
        IF authz._ensure_event_partition(
               extract(year  from v_month)::int,
               extract(month from v_month)::int) THEN
            v_created := v_created + 1;
        END IF;
    END LOOP;

    RETURN v_created;
END;
$$;

-- drop_event_partitions_before: retention. Drops every monthly events
-- partition whose month ends on or before p_before (all its rows are
-- older). Returns the number dropped. GUARDED: a cutoff inside any store's
-- live gate window is refused (check_violation) unless p_force — a dropped
-- month under-counts, which can only relax a cap, never tighten one. Keep
-- retention >= audit retention too if time-travel over gates is to stay exact.
CREATE OR REPLACE FUNCTION authz.drop_event_partitions_before(
    p_before date,
    p_force  boolean DEFAULT false
) RETURNS integer
LANGUAGE plpgsql AS $$
BEGIN
    -- Fleet-wide: every store's live gates must survive the cutoff.
    PERFORM authz._event_check_retention_cutoff(NULL, p_before::timestamptz, p_force);
    RETURN authz._drop_month_partitions_before('events', p_before);
END;
$$;

-- _event_check_retention_cutoff: the retention guard. Refuses (check_violation)
-- a cutoff that would remove events a LIVE gate still counts — i.e.
-- p_before > now() - max_gate_window(store) — unless p_force. Retention
-- shorter than a gate window under-counts and can only relax a cap, so this
-- is enforced where the damage would happen rather than left to the runbook.
-- Time-travel over a FORMER gate definition inside a purged range still
-- under-counts; that needs audit-aligned retention and stays a documented
-- caveat. NULL p_store = every store (the fleet-wide partition drop).
CREATE OR REPLACE FUNCTION authz._event_check_retention_cutoff(
    p_store  text,
    p_before timestamptz,
    p_force  boolean
) RETURNS void
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_max   interval := authz.max_gate_window(p_store);
    v_worst record;
BEGIN
    IF p_force OR v_max IS NULL OR p_before <= clock_timestamp() - v_max THEN
        RETURN;
    END IF;
    SELECT w.store, w.gate, w.object_type, w.relation, w."window" INTO v_worst
      FROM authz.gate_windows(p_store) w
     ORDER BY w."window" DESC LIMIT 1;
    RAISE EXCEPTION 'retention cutoff % is inside a live gate window: gate "%" on %#% (store "%") counts events from the last %; the earliest safe cutoff is % (pass p_force => true to relax the cap deliberately)',
        p_before, v_worst.gate, v_worst.object_type, v_worst.relation, v_worst.store, v_max,
        (clock_timestamp() - v_max)::timestamptz(0)
        USING ERRCODE = 'check_violation',
              HINT = 'Event retention must be >= the longest gate window (SELECT authz.max_gate_window()).';
END;
$$;

-- purge_events: PER-STORE retention — delete one store's events with
-- occurred_at before p_before. Row-wise (O(rows), audited by nothing: the
-- log is append-only and this is sanctioned maintenance under the same
-- authz.audit_maintenance window the partition mover and delete_store use),
-- unlike drop_event_partitions_before, which is DDL and O(partitions) but
-- fleet-wide. Use it for a tenant whose retention is shorter than the
-- fleet's, or for a tenant's erasure request short of delete_store. Returns
-- the number of rows deleted. Admin-only. Guarded like the partition drop:
-- a cutoff inside a live gate window is refused unless p_force. Time-travel
-- over gates for an instant inside the purged range still under-counts,
-- which can only RELAX a cap.
CREATE OR REPLACE FUNCTION authz.purge_events(
    p_store  text,
    p_before timestamptz,
    p_force  boolean DEFAULT false
) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store, true);   -- retired stores can be purged too
    v_count    bigint;
BEGIN
    IF p_before IS NULL THEN
        RAISE EXCEPTION 'p_before is required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- This store's live gates must survive the cutoff (see the guard above).
    PERFORM authz._event_check_retention_cutoff(p_store, p_before, p_force);
    PERFORM set_config('authz.audit_maintenance', 'on', true);
    DELETE FROM authz.events e
     WHERE e.store_id = v_store_id
       AND e.occurred_at < p_before;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    PERFORM set_config('authz.audit_maintenance', '', true);
    RETURN v_count;
END;
$$;

------------------------------------------------------------------------
-- reserve_event: the STRICT tier (ADR 0012, phase 3). A gate bounds
-- RECORDED actions: two concurrent checks can both see count = 4 and both
-- allow a 6th transfer. A PEP that needs a hard bound calls reserve_event
-- BECAUSE it is about to act — never as a side effect of asking:
--
--   advisory lock on (store, subject)  →  full decision (graph + gates, as
--   check_access would decide)  →  allowed: insert the `request` event in
--   the same transaction; refused: insert a `denied` event (the reserve IS
--   the PEP's attempt — a denied reserve on record is what kind = denied is
--   for) unless p_record_denied is false  →  return the outcome.
--
-- The PEP then performs the action and records the `response` (or failure)
-- as usual. Serialization is per (store, subject) — the unit every gate
-- counts — so N parallel reserves against a cap of K yield exactly K
-- allows. Nothing else takes this lock (tuple writes lock
-- store:object_type:object_id, a different keyspace).
--
-- Consequence to know: a SLIDING-window lockout gate (count_within over
-- kind = denied) is extended by every refused reserve — the usual
-- login-lockout behaviour; pass p_record_denied => false if attempts during
-- a lockout must not count. Calendar windows are unaffected.
--
-- Idempotency follows record_event: p_event_id requires p_occurred_at, and
-- a re-delivered key (the same attempt) is reported as seq = null while the
-- decision is still returned. p_occurred_at defaults to the database clock.
-- Object type and id are required — a reserve is a decision, and gates hang
-- on (object_type, action).
--
-- Returns:
--   {"allowed": bool, "seq": n | null, "kind": "request" | "denied" | null,
--    "reason": "allowed" | "gate_denied" | "graph_denied",
--    "gates": [{"gate", "clause", "result", "reason", "observed", "threshold",
--               "missing_keys"}, ...]}     -- per-clause outcomes, no payloads
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.reserve_event(
    p_store           text,
    p_subject_type    text,
    p_subject_id      text,
    p_action          text,
    p_object_type     text,
    p_object_id       text,
    p_payload         jsonb       DEFAULT '{}',
    p_request_context jsonb       DEFAULT NULL,
    p_event_id        text        DEFAULT NULL,
    p_occurred_at     timestamptz DEFAULT NULL,
    p_recorded_by     text        DEFAULT NULL,
    p_record_denied   boolean     DEFAULT true
) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id     integer := authz._s(p_store);
    v_subject_type integer := authz._t(v_store_id, p_subject_type);
    v_action       integer := authz._r(v_store_id, p_action);
    v_object_type  integer;
    v_allowed      boolean;
    v_gates        jsonb;
    v_reason       text;
    v_seq          bigint;
    v_kind         text;
BEGIN
    IF p_object_type IS NULL OR p_object_id IS NULL THEN
        RAISE EXCEPTION 'reserve_event requires object_type and object_id (a reserve is a decision)'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_event_id IS NOT NULL AND p_occurred_at IS NULL THEN
        RAISE EXCEPTION 'event_id requires occurred_at (the idempotency key is stable only with the attempt''s own timestamp)'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    v_object_type := authz._t(v_store_id, p_object_type);
    -- A reserve both decides (read) and records (write) about the object.
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_write');

    -- Serialize per (store, subject): every gate counts this principal's
    -- actions, so this is the unit that must not race. hashtextextended, as
    -- write_tuples_checked.
    PERFORM pg_advisory_xact_lock(
        hashtextextended(p_store || ':' || p_subject_type || ':' || p_subject_id, 0));

    -- The full decision, traced so the gate clauses' outcomes can be reported.
    PERFORM authz._trace_begin();
    v_allowed := authz._decide(v_store_id, v_subject_type, p_subject_id, v_action,
                               v_object_type, p_object_id, p_request_context);
    PERFORM authz._trace_end();

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
               'gate',         t.gate_name,
               'clause',       t.gate_clause,
               'result',       t.result,
               'reason',       t.gate_reason,
               'observed',     t.gate_observed,
               'threshold',    t.gate_threshold,
               'scope',        t.gate_scope,
               'shadow',       COALESCE(t.gate_shadow, false),
               'missing_keys', to_jsonb(t.condition_missing_keys)
           ) ORDER BY t.step), '[]'::jsonb)
      INTO v_gates
      FROM _access_trace t
     WHERE t.rule_type = 'temporal_gate';

    v_reason := CASE
        WHEN v_allowed THEN 'allowed'
        WHEN EXISTS (SELECT 1 FROM _access_trace t WHERE t.rule_type = 'temporal_gate' AND NOT t.result
                        AND NOT COALESCE(t.gate_shadow, false))
             THEN 'gate_denied'
        ELSE 'graph_denied'
    END;

    IF v_allowed THEN
        v_seq  := authz.record_event(p_store, p_subject_type, p_subject_id, p_action,
                                     p_object_type, p_object_id, 'request', p_payload,
                                     COALESCE(p_occurred_at, clock_timestamp()), p_event_id, p_recorded_by);
        v_kind := 'request';
    ELSIF p_record_denied THEN
        v_seq  := authz.record_event(p_store, p_subject_type, p_subject_id, p_action,
                                     p_object_type, p_object_id, 'denied', p_payload,
                                     COALESCE(p_occurred_at, clock_timestamp()), p_event_id, p_recorded_by);
        v_kind := 'denied';
    END IF;

    RETURN jsonb_build_object(
        'allowed', v_allowed,
        'seq',     v_seq,
        'kind',    v_kind,
        'reason',  v_reason,
        'gates',   v_gates);
END;
$$;

------------------------------------------------------------------------
-- Per-recorder action allowlists (admin). grant adds actions to a role's
-- allowlist for a store (creating it — from then on the role is restricted
-- to the list); revoke removes actions, or the whole list when p_actions is
-- NULL (the role is unrestricted again). Both return the number of rows
-- changed. Membership is what counts: a list granted to authz_recorder
-- restricts every writer too, since roles.sql grants authz_recorder to
-- authz_writer — grant per-app roles, as with namespaces.
--
--   SELECT authz.grant_recorder_actions('bank', 'svc_approvals', ARRAY['approve_sale']);
--   SELECT authz.revoke_recorder_actions('bank', 'svc_approvals');   -- lift the list
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.grant_recorder_actions(
    p_store   text,
    p_db_role text,
    p_actions text[]
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_count    integer;
BEGIN
    IF p_db_role IS NULL OR p_db_role = '' THEN
        RAISE EXCEPTION 'db_role is required' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_actions IS NULL OR array_length(p_actions, 1) IS NULL THEN
        RAISE EXCEPTION 'actions must be a non-empty array of relation names' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO authz.recorder_actions (store_id, db_role, action)
    SELECT v_store_id, p_db_role, authz._r(v_store_id, a)   -- _r raises on an undeclared action
      FROM unnest(p_actions) a
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

CREATE OR REPLACE FUNCTION authz.revoke_recorder_actions(
    p_store   text,
    p_db_role text,
    p_actions text[] DEFAULT NULL    -- NULL: remove the role's whole allowlist
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_count    integer;
BEGIN
    DELETE FROM authz.recorder_actions ra
     WHERE ra.store_id = v_store_id
       AND ra.db_role  = p_db_role
       AND (p_actions IS NULL
            OR ra.action IN (SELECT authz._r(v_store_id, a) FROM unnest(p_actions) a));
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;
