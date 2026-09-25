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
-- record_event: record that p_subject ACTUALLY performed p_action (on
-- p_object, if any). Returns the event's seq, or NULL when p_event_id was
-- already recorded for this store (idempotent re-delivery: no second row).
--
-- Trust model: the recorder is trusted for its assertion exactly as a tuple
-- writer is trusted for its tuples. What the engine enforces:
--   - the action must be a declared relation of the store (the model is the
--     action vocabulary — a typo fails loud here, not silently later);
--   - the subject is a concrete principal (no wildcard, no userset);
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
    v_now          timestamptz := statement_timestamp();
    v_occurred_at  timestamptz := COALESCE(p_occurred_at, statement_timestamp());
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
-- the shared _ensure_month_partition worker.
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
-- older). Returns the number dropped. Keep event retention >= the longest
-- gate window (phase 2) — a dropped month under-counts, which can only
-- relax a cap, never tighten one; and >= audit retention if time-travel
-- over gates is to stay exact.
CREATE OR REPLACE FUNCTION authz.drop_event_partitions_before(
    p_before date
) RETURNS integer
LANGUAGE plpgsql AS $$
BEGIN
    RETURN authz._drop_month_partitions_before('events', p_before);
END;
$$;
