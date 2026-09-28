-- Temporal gates (ADR 0012, phase 2) — the READ side: the spec validator,
-- the four window primitives over authz.events, and the gate evaluator that
-- every public decision entry point calls through authz._decide
-- (access_internal.sql). Gate MANAGEMENT (add_gate / drop_gate + the write-time
-- trigger) lives in gates_admin.sql (write profile); gate HISTORY (audit
-- trigger, snapshot builder) in the audit profile.
--
-- Gates run OUTSIDE the graph walk and OUTSIDE the authz_eval sandbox: they
-- are engine code (owner: authz_owner), evaluated once per top-level check
-- after the graph says yes, for the checked principal only. A gate on
-- `group#member` never fires while resolving `doc#viewer` through that
-- userset — gates answer the question asked, not the sub-questions.
--
-- Spec grammar (validated + normalized by _event_validate_gate_spec):
--
--   {"description": "...",                       -- optional
--    "all_of": [                                  -- 1..16 clauses, AND
--      {"count_within":          {"window": "1h", "kind": "request", "max": 5}},
--      {"sum_within":            {"window": "1h", "kind": "response", "field": "input.amount",
--                                 "plus": "$request.input.amount", "max": 5000}},
--      {"formerly_within":       {"window": "1h", "action": "approve_sale", "kind": "response",
--                                 "match": {"input.stock": "$request.input.stock",
--                                           "output.approved": true},
--                                 "recorded_by": ["svc:approvals"]}},
--      {"count_distinct_within": {"calendar": "day", "tz": "UTC", "key": "object_id", "max": 50}}
--    ]}
--
--   Clause keys: window (fixed-length interval text) XOR calendar
--   (hour|day|week|month|year, requires tz); scope (subject, the default:
--   the principal's events on any object; object: only on the checked
--   object); action (relation name, default: the gate's own relation); kind
--   (request|response|denied, default request);
--   match ({dotted.path: JSON literal | "$request.<path>"} — containment on
--   the payload); recorded_by (allowlist); key (count_distinct_within:
--   object_id | object_type | payload.<path>); field (sum_within: payload
--   path); plus (added to the count/sum before comparing — "plus: 1" counts
--   the request being decided); max/min (number | "$request.<path>";
--   thresholds inclusive).
--   A literal string that must start with "$" is written "$$literal".
--   Unknown keys are rejected (a typo must not silently weaken a gate).
--
-- Failure semantics (fail closed, mirrors _eval_condition): a missing
-- $request key fails the clause (gate_missing_context — may become
-- `conditional` in check_access_detailed); a present-but-non-numeric
-- threshold value (gate_bad_request_value), a matched event whose sum field
-- is missing/non-numeric (gate_payload_not_numeric) and any other evaluation
-- error (gate_error) are hard denies; query_canceled / program_limit_exceeded
-- re-raise.
--
-- Depends on: core_internal.sql (_r, _max_context_bytes), events.sql
-- (_event_kind_*), migration 0011 (authz.model_gates). Loads before
-- access_internal.sql (whose _decide calls _event_check_gates).

------------------------------------------------------------------------
-- Grammar helpers
------------------------------------------------------------------------

-- Dotted payload path: object keys only, no array indexing, no wildcards.
CREATE OR REPLACE FUNCTION authz._event_path_ok(p_path text) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS
    $$ SELECT p_path ~ '^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$' $$;

-- Classify a clause value: a "$request.<path>" reference, a "$$literal"
-- (one sigil stripped), or a plain JSON literal. Any other "$"-prefixed
-- string is malformed.
CREATE OR REPLACE FUNCTION authz._event_ref(
    p_val   jsonb,
    OUT kind  text,     -- 'ref' | 'literal'
    OUT value jsonb,    -- the literal (kind = literal)
    OUT path  text[]    -- the context path (kind = ref)
) RETURNS record
LANGUAGE plpgsql IMMUTABLE AS $fn$
DECLARE
    s text;
BEGIN
    kind := 'literal'; value := p_val; path := NULL;
    IF jsonb_typeof(p_val) <> 'string' THEN
        RETURN;
    END IF;
    s := p_val #>> '{}';
    IF s LIKE '$request.%' THEN
        IF NOT authz._event_path_ok(substr(s, 10)) THEN
            RAISE EXCEPTION 'malformed reference "%": expected $request.<dotted.path>', s
                USING ERRCODE = 'check_violation';
        END IF;
        kind := 'ref'; value := NULL; path := string_to_array(substr(s, 10), '.');
    ELSIF s LIKE '$$%' THEN
        value := to_jsonb(substr(s, 2));
    ELSIF s LIKE '$%' THEN
        RAISE EXCEPTION 'malformed reference "%": only $request.<path> references are allowed (write "$$" for a literal "$")', s
            USING ERRCODE = 'check_violation';
    END IF;
END;
$fn$;

-- Resolve a clause value against the request context, keeping the JSON
-- type. missing is set (the "request.<first segment>" key) when a reference
-- is absent or JSON null in the context.
CREATE OR REPLACE FUNCTION authz._event_resolve(
    p_val     jsonb,
    p_context jsonb,
    OUT value   jsonb,
    OUT missing text
) RETURNS record
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    r record;
BEGIN
    r := authz._event_ref(p_val);
    missing := NULL;
    IF r.kind = 'literal' THEN
        value := r.value;
        RETURN;
    END IF;
    value := COALESCE(p_context, '{}'::jsonb) #> r.path;
    IF value IS NULL OR jsonb_typeof(value) = 'null' THEN
        value := NULL;
        missing := 'request.' || r.path[1];
    END IF;
END;
$$;

-- Build the nested containment fragment for one match entry:
-- ('input.stock', "ACME") → {"input": {"stock": "ACME"}}.
CREATE OR REPLACE FUNCTION authz._event_nest(p_path text, p_value jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    v_segs text[] := string_to_array(p_path, '.');
    v_out  jsonb  := p_value;
    i      int;
BEGIN
    FOR i IN REVERSE array_length(v_segs, 1) .. 1 LOOP
        v_out := jsonb_build_object(v_segs[i], v_out);
    END LOOP;
    RETURN v_out;
END;
$$;

------------------------------------------------------------------------
-- _event_validate_gate_spec: validate a gate spec against the grammar and
-- return its NORMALIZED form (windows as canonical interval text, a derived
-- required_context {"request": [...]}). Raises check_violation naming the
-- clause index. Idempotent: normalizing a normalized spec is a no-op, which
-- apply_model's post-apply checksum relies on.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._event_validate_gate_spec(
    p_store_id integer,
    p_spec     jsonb
) RETURNS jsonb
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_clauses  jsonb;
    v_out      jsonb := '[]'::jsonb;
    v_clause   jsonb;
    v_body     jsonb;
    v_nbody    jsonb;
    v_prim     text;
    v_key      text;
    v_val      jsonb;
    v_iv       interval;
    v_req      text[] := '{}';
    v_allowed  text[];
    v_lit_max  numeric;
    v_lit_min  numeric;
    r          record;
    i          int := 0;
    v_prefix   text;
    v_n        int;
BEGIN
    IF p_spec IS NULL OR jsonb_typeof(p_spec) <> 'object' THEN
        RAISE EXCEPTION 'gate spec must be a JSON object' USING ERRCODE = 'check_violation';
    END IF;
    IF pg_column_size(p_spec) > authz._max_context_bytes() THEN
        RAISE EXCEPTION 'gate spec exceeds the %-byte limit (authz.max_context_bytes)', authz._max_context_bytes()
            USING ERRCODE = 'check_violation';
    END IF;
    FOR v_key IN SELECT jsonb_object_keys(p_spec) LOOP
        IF v_key NOT IN ('all_of', 'description', 'mode', 'required_context') THEN
            RAISE EXCEPTION 'gate spec has unknown key "%"', v_key USING ERRCODE = 'check_violation';
        END IF;
    END LOOP;
    IF p_spec ? 'description' AND jsonb_typeof(p_spec -> 'description') <> 'string' THEN
        RAISE EXCEPTION 'gate description must be a string' USING ERRCODE = 'check_violation';
    END IF;
    -- mode: enforce (default) denies on a failing clause; shadow evaluates and
    -- reports (explain, detailed, reserve, server log) but never denies — the
    -- way to introduce a gate on a live relation without interrupting authz;
    -- off keeps the definition (and its history) but skips the gate entirely.
    IF p_spec ? 'mode' AND (jsonb_typeof(p_spec -> 'mode') <> 'string'
                            OR (p_spec ->> 'mode') NOT IN ('enforce', 'shadow', 'off')) THEN
        RAISE EXCEPTION 'gate mode must be enforce | shadow | off' USING ERRCODE = 'check_violation';
    END IF;
    v_clauses := p_spec -> 'all_of';
    IF v_clauses IS NULL OR jsonb_typeof(v_clauses) <> 'array' THEN
        RAISE EXCEPTION 'gate spec requires an "all_of" array' USING ERRCODE = 'check_violation';
    END IF;
    v_n := jsonb_array_length(v_clauses);
    IF v_n < 1 OR v_n > 16 THEN
        RAISE EXCEPTION 'gate all_of must have 1..16 clauses (got %)', v_n USING ERRCODE = 'check_violation';
    END IF;

    FOR v_clause IN SELECT * FROM jsonb_array_elements(v_clauses) LOOP
        v_prefix := 'gate clause [' || i || ']';
        IF jsonb_typeof(v_clause) <> 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(v_clause)) <> 1 THEN
            RAISE EXCEPTION '%: a clause is an object with exactly one key (the primitive name)', v_prefix
                USING ERRCODE = 'check_violation';
        END IF;
        SELECT k INTO v_prim FROM jsonb_object_keys(v_clause) k;
        IF v_prim NOT IN ('formerly_within', 'count_within', 'count_distinct_within', 'sum_within') THEN
            RAISE EXCEPTION '%: unknown primitive "%"', v_prefix, v_prim USING ERRCODE = 'check_violation';
        END IF;
        v_body := v_clause -> v_prim;
        IF jsonb_typeof(v_body) <> 'object' THEN
            RAISE EXCEPTION '%: % takes an object', v_prefix, v_prim USING ERRCODE = 'check_violation';
        END IF;

        v_allowed := ARRAY['window', 'calendar', 'tz', 'scope', 'action', 'kind', 'match', 'recorded_by'];
        IF v_prim = 'count_distinct_within' THEN v_allowed := v_allowed || ARRAY['key', 'plus', 'max', 'min'];
        ELSIF v_prim = 'sum_within'         THEN v_allowed := v_allowed || ARRAY['field', 'plus', 'max', 'min'];
        ELSIF v_prim = 'count_within'       THEN v_allowed := v_allowed || ARRAY['plus', 'max', 'min'];
        END IF;
        FOR v_key IN SELECT jsonb_object_keys(v_body) LOOP
            IF NOT (v_key = ANY (v_allowed)) THEN
                RAISE EXCEPTION '%: key "%" is not allowed for %', v_prefix, v_key, v_prim
                    USING ERRCODE = 'check_violation';
            END IF;
        END LOOP;
        v_nbody := v_body;

        -- window XOR calendar
        IF (v_body ? 'window') = (v_body ? 'calendar') THEN
            RAISE EXCEPTION '%: exactly one of "window" or "calendar" is required', v_prefix
                USING ERRCODE = 'check_violation';
        END IF;
        IF v_body ? 'window' THEN
            IF jsonb_typeof(v_body -> 'window') <> 'string' THEN
                RAISE EXCEPTION '%: window must be an interval string', v_prefix USING ERRCODE = 'check_violation';
            END IF;
            -- Fixed-length units only: months/years belong in "calendar" (and a
            -- bare "m" reads as minutes in PostgreSQL — removing the ambiguity).
            -- Accepted: unit text (1h, 10m, 2w …), ISO-8601 (PT30M, P2D …), and
            -- PostgreSQL's own canonical output ('01:00:00', '7 days …') so a
            -- normalized spec re-validates unchanged (the trigger runs on every
            -- write, including apply_model's replay of an exported spec).
            IF NOT ((v_body ->> 'window') ~* '^\s*(\d+\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|week|weeks)\s*)+$'
                    OR (v_body ->> 'window') ~ '^P(\d+W)?(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?$'
                    OR (v_body ->> 'window') ~ '^(\d+ days?)?\s*(\d{2}:\d{2}:\d{2}(\.\d+)?)?$') THEN
                RAISE EXCEPTION '%: window "%" must use fixed-length units (s/m/h/d/w or ISO-8601 PT…/P…D/P…W); calendar-length units go in "calendar"',
                    v_prefix, v_body ->> 'window' USING ERRCODE = 'check_violation';
            END IF;
            BEGIN
                v_iv := (v_body ->> 'window')::interval;
            EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION '%: window "%" is not a valid interval', v_prefix, v_body ->> 'window'
                    USING ERRCODE = 'check_violation';
            END;
            IF date_part('month', v_iv) <> 0 OR date_part('year', v_iv) <> 0 OR v_iv <= interval '0' THEN
                RAISE EXCEPTION '%: window "%" must be a positive fixed-length interval', v_prefix, v_body ->> 'window'
                    USING ERRCODE = 'check_violation';
            END IF;
            v_nbody := jsonb_set(v_nbody, '{window}', to_jsonb(v_iv::text));
            IF v_body ? 'tz' THEN
                RAISE EXCEPTION '%: "tz" is only allowed with "calendar"', v_prefix USING ERRCODE = 'check_violation';
            END IF;
        ELSE
            IF jsonb_typeof(v_body -> 'calendar') <> 'string'
               OR (v_body ->> 'calendar') NOT IN ('hour', 'day', 'week', 'month', 'year') THEN
                RAISE EXCEPTION '%: calendar must be one of hour | day | week | month | year', v_prefix
                    USING ERRCODE = 'check_violation';
            END IF;
            IF NOT (v_body ? 'tz') OR jsonb_typeof(v_body -> 'tz') <> 'string' THEN
                RAISE EXCEPTION '%: "calendar" requires a "tz" (IANA zone name)', v_prefix USING ERRCODE = 'check_violation';
            END IF;
            BEGIN
                PERFORM now() AT TIME ZONE (v_body ->> 'tz');
            EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION '%: unknown time zone "%"', v_prefix, v_body ->> 'tz' USING ERRCODE = 'check_violation';
            END;
        END IF;

        -- action: a declared relation of the store
        IF v_body ? 'action' THEN
            IF jsonb_typeof(v_body -> 'action') <> 'string' THEN
                RAISE EXCEPTION '%: action must be a relation name', v_prefix USING ERRCODE = 'check_violation';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM authz.relations rl
                            WHERE rl.store_id = p_store_id AND rl.name = v_body ->> 'action') THEN
                RAISE EXCEPTION '%: action "%" is not a relation of the store (declare it with model_register_relation)',
                    v_prefix, v_body ->> 'action' USING ERRCODE = 'check_violation';
            END IF;
        END IF;
        IF v_body ? 'kind' AND (jsonb_typeof(v_body -> 'kind') <> 'string'
                                OR (v_body ->> 'kind') NOT IN ('request', 'response', 'denied')) THEN
            RAISE EXCEPTION '%: kind must be one of request | response | denied', v_prefix USING ERRCODE = 'check_violation';
        END IF;
        -- scope: subject (default) counts the principal's events on any object;
        -- object narrows them to the checked object ("3 downloads of THIS file",
        -- "the submitter of THIS object may not approve it").
        IF v_body ? 'scope' AND (jsonb_typeof(v_body -> 'scope') <> 'string'
                                 OR (v_body ->> 'scope') NOT IN ('subject', 'object')) THEN
            RAISE EXCEPTION '%: scope must be subject | object', v_prefix USING ERRCODE = 'check_violation';
        END IF;

        -- match: non-empty {path: literal | $request.<path>}
        IF v_body ? 'match' THEN
            IF jsonb_typeof(v_body -> 'match') <> 'object'
               OR (SELECT count(*) FROM jsonb_object_keys(v_body -> 'match')) = 0 THEN
                RAISE EXCEPTION '%: match must be a non-empty object', v_prefix USING ERRCODE = 'check_violation';
            END IF;
            FOR v_key, v_val IN SELECT * FROM jsonb_each(v_body -> 'match') LOOP
                IF NOT authz._event_path_ok(v_key) THEN
                    RAISE EXCEPTION '%: match key "%" is not a dotted path', v_prefix, v_key USING ERRCODE = 'check_violation';
                END IF;
                BEGIN
                    SELECT * INTO r FROM authz._event_ref(v_val);
                EXCEPTION WHEN check_violation THEN
                    RAISE EXCEPTION '%: %', v_prefix, SQLERRM USING ERRCODE = 'check_violation';
                END;
                IF r.kind = 'ref' THEN v_req := v_req || r.path[1]; END IF;
            END LOOP;
        END IF;

        IF v_body ? 'recorded_by' THEN
            IF jsonb_typeof(v_body -> 'recorded_by') <> 'array' OR jsonb_array_length(v_body -> 'recorded_by') = 0
               OR EXISTS (SELECT 1 FROM jsonb_array_elements(v_body -> 'recorded_by') e WHERE jsonb_typeof(e) <> 'string') THEN
                RAISE EXCEPTION '%: recorded_by must be a non-empty array of strings', v_prefix USING ERRCODE = 'check_violation';
            END IF;
        END IF;

        -- primitive-specific
        IF v_prim = 'count_distinct_within' THEN
            IF NOT (v_body ? 'key') OR jsonb_typeof(v_body -> 'key') <> 'string'
               OR NOT ((v_body ->> 'key') IN ('object_id', 'object_type')
                       OR ((v_body ->> 'key') LIKE 'payload.%' AND authz._event_path_ok(substr(v_body ->> 'key', 9)))) THEN
                RAISE EXCEPTION '%: key must be object_id | object_type | payload.<path>', v_prefix USING ERRCODE = 'check_violation';
            END IF;
        END IF;
        IF v_prim = 'sum_within' THEN
            IF NOT (v_body ? 'field') OR jsonb_typeof(v_body -> 'field') <> 'string'
               OR NOT authz._event_path_ok(v_body ->> 'field') THEN
                RAISE EXCEPTION '%: sum_within requires a "field" payload path', v_prefix USING ERRCODE = 'check_violation';
            END IF;
        END IF;
        IF v_prim IN ('count_within', 'count_distinct_within', 'sum_within') THEN
            IF NOT (v_body ? 'max') AND NOT (v_body ? 'min') THEN
                RAISE EXCEPTION '%: % requires "max" and/or "min"', v_prefix, v_prim USING ERRCODE = 'check_violation';
            END IF;
            v_lit_max := NULL; v_lit_min := NULL;
            FOREACH v_key IN ARRAY ARRAY['max', 'min', 'plus'] LOOP
                IF v_body ? v_key THEN
                    v_val := v_body -> v_key;
                    IF jsonb_typeof(v_val) = 'number' THEN
                        IF v_key = 'max' THEN v_lit_max := (v_val #>> '{}')::numeric; END IF;
                        IF v_key = 'min' THEN v_lit_min := (v_val #>> '{}')::numeric; END IF;
                    ELSIF jsonb_typeof(v_val) = 'string' THEN
                        BEGIN
                            SELECT * INTO r FROM authz._event_ref(v_val);
                        EXCEPTION WHEN check_violation THEN
                            RAISE EXCEPTION '%: %', v_prefix, SQLERRM USING ERRCODE = 'check_violation';
                        END;
                        IF r.kind <> 'ref' THEN
                            RAISE EXCEPTION '%: % must be a number or a $request.<path> reference', v_prefix, v_key
                                USING ERRCODE = 'check_violation';
                        END IF;
                        v_req := v_req || r.path[1];
                    ELSE
                        RAISE EXCEPTION '%: % must be a number or a $request.<path> reference', v_prefix, v_key
                            USING ERRCODE = 'check_violation';
                    END IF;
                END IF;
            END LOOP;
            IF v_lit_min IS NOT NULL AND v_lit_max IS NOT NULL AND v_lit_min > v_lit_max THEN
                RAISE EXCEPTION '%: min (%) exceeds max (%)', v_prefix, v_lit_min, v_lit_max USING ERRCODE = 'check_violation';
            END IF;
        END IF;

        v_out := v_out || jsonb_build_array(jsonb_build_object(v_prim, v_nbody));
        i := i + 1;
    END LOOP;

    RETURN jsonb_strip_nulls(jsonb_build_object(
        'description', p_spec -> 'description',
        'mode', p_spec -> 'mode',
        'all_of', v_out,
        'required_context', jsonb_build_object(
            'request', (SELECT COALESCE(jsonb_agg(DISTINCT k ORDER BY k), '[]'::jsonb) FROM unnest(v_req) k))));
END;
$$;

------------------------------------------------------------------------
-- Window primitives: plain SQL over authz.events, internal.
--
-- VOLATILE, deliberately (the whole path from _event_resolve_gates down to
-- the window queries): reserve_event takes its per-subject advisory lock
-- INSIDE the statement that then evaluates the gates, and a STABLE function
-- runs on the snapshot established when its calling query started — i.e.
-- from BEFORE the lock was granted — so it would not see the event the
-- previous lock holder just committed and the strict tier would over-admit
-- (reproduced: 4 allows against a cap of 3 under 8 parallel reserves).
-- VOLATILE functions take a fresh snapshot per query, which is exactly the
-- read-after-lock the strict tier needs. The cost is only lost inlining of
-- _event_matching into the aggregates; the queries themselves are unchanged.
-- Subject and store are explicit parameters — the evaluator always passes
-- the CHECKED principal, so a gate can only ask about the subject being
-- checked, never about arbitrary subjects.
------------------------------------------------------------------------

-- The events a clause selects. p_from is exclusive for sliding windows
-- (an event exactly `window` ago is outside) and inclusive for calendar
-- windows ([bucket start, now]); p_to (= now_ref) is always inclusive.
-- p_as_of (time-travel) additionally bounds recorded_at: what the engine
-- could have KNOWN at that instant, not what we now believe happened.
CREATE OR REPLACE FUNCTION authz._event_matching(
    p_store_id       integer,
    p_subject_type   integer,
    p_subject_id     text,
    p_action         integer,
    p_kind           smallint,
    p_object_type    integer,      -- object scope: NULL = any object
    p_object_id      text,
    p_from           timestamptz,
    p_from_inclusive boolean,
    p_to             timestamptz,
    p_match          jsonb[],
    p_recorded_by    text[],
    p_as_of          timestamptz
) RETURNS SETOF authz.events
LANGUAGE sql VOLATILE AS $$
    SELECT e.*
      FROM authz.events e
     WHERE e.store_id     = p_store_id
       AND e.subject_type = p_subject_type
       AND e.subject_id   = p_subject_id
       AND e.action       = p_action
       AND e.kind         = p_kind
       AND (p_object_type IS NULL OR e.object_type = p_object_type)
       AND (p_object_id   IS NULL OR e.object_id   = p_object_id)
       AND (e.occurred_at > p_from OR (p_from_inclusive AND e.occurred_at = p_from))
       AND e.occurred_at <= p_to
       AND (p_as_of IS NULL OR e.recorded_at <= p_as_of)
       AND (p_match IS NULL OR e.payload @> ALL (p_match))
       AND (p_recorded_by IS NULL OR e.recorded_by = ANY (p_recorded_by))
$$;

CREATE OR REPLACE FUNCTION authz._event_formerly_within(
    p_store_id integer, p_subject_type integer, p_subject_id text, p_action integer, p_kind smallint,
    p_object_type integer, p_object_id text,
    p_from timestamptz, p_from_inclusive boolean, p_to timestamptz,
    p_match jsonb[], p_recorded_by text[], p_as_of timestamptz
) RETURNS boolean
LANGUAGE sql VOLATILE AS $$
    SELECT EXISTS (SELECT 1 FROM authz._event_matching(
        p_store_id, p_subject_type, p_subject_id, p_action, p_kind, p_object_type, p_object_id,
        p_from, p_from_inclusive, p_to, p_match, p_recorded_by, p_as_of))
$$;

CREATE OR REPLACE FUNCTION authz._event_count_within(
    p_store_id integer, p_subject_type integer, p_subject_id text, p_action integer, p_kind smallint,
    p_object_type integer, p_object_id text,
    p_from timestamptz, p_from_inclusive boolean, p_to timestamptz,
    p_match jsonb[], p_recorded_by text[], p_as_of timestamptz
) RETURNS bigint
LANGUAGE sql VOLATILE AS $$
    SELECT count(*) FROM authz._event_matching(
        p_store_id, p_subject_type, p_subject_id, p_action, p_kind, p_object_type, p_object_id,
        p_from, p_from_inclusive, p_to, p_match, p_recorded_by, p_as_of)
$$;

-- p_key: 'object_id' | 'object_type' | 'payload.<path>'. Rows where the key
-- is absent are not counted (DISTINCT ignores NULL).
CREATE OR REPLACE FUNCTION authz._event_count_distinct_within(
    p_store_id integer, p_subject_type integer, p_subject_id text, p_action integer, p_kind smallint,
    p_object_type integer, p_object_id text,
    p_from timestamptz, p_from_inclusive boolean, p_to timestamptz,
    p_match jsonb[], p_recorded_by text[], p_as_of timestamptz,
    p_key text
) RETURNS bigint
LANGUAGE sql VOLATILE AS $$
    SELECT count(DISTINCT CASE p_key
                              WHEN 'object_id'   THEN m.object_id
                              WHEN 'object_type' THEN m.object_type::text
                              ELSE m.payload #>> string_to_array(substr(p_key, 9), '.')
                          END)
      FROM authz._event_matching(
        p_store_id, p_subject_type, p_subject_id, p_action, p_kind, p_object_type, p_object_id,
        p_from, p_from_inclusive, p_to, p_match, p_recorded_by, p_as_of) m
$$;

-- Returns the sum and whether EVERY matched event carried a JSON number at
-- p_field. A missing or non-numeric field is reported, not skipped — silently
-- ignoring rows would let a malformed recorder relax a cap.
CREATE OR REPLACE FUNCTION authz._event_sum_within(
    p_store_id integer, p_subject_type integer, p_subject_id text, p_action integer, p_kind smallint,
    p_object_type integer, p_object_id text,
    p_from timestamptz, p_from_inclusive boolean, p_to timestamptz,
    p_match jsonb[], p_recorded_by text[], p_as_of timestamptz,
    p_field text,
    OUT total numeric, OUT all_numeric boolean
) RETURNS record
LANGUAGE sql VOLATILE AS $$
    SELECT COALESCE(sum((m.payload #>> string_to_array(p_field, '.'))::numeric)
                        FILTER (WHERE jsonb_typeof(m.payload #> string_to_array(p_field, '.')) = 'number'), 0),
           COALESCE(bool_and(jsonb_typeof(m.payload #> string_to_array(p_field, '.')) = 'number'), true)
      FROM authz._event_matching(
        p_store_id, p_subject_type, p_subject_id, p_action, p_kind, p_object_type, p_object_id,
        p_from, p_from_inclusive, p_to, p_match, p_recorded_by, p_as_of) m
$$;

------------------------------------------------------------------------
-- _event_resolve_gates: the gate list for (store, object_type, relation) —
-- [{"name": ..., "spec": ...}] ordered by name — from authz.model_gates or,
-- for time-travel, from the pg_temp._snapshot_gates the audit profile builds.
-- One probe on the UNIQUE (store_id, object_type, relation, name) index;
-- relations without gates pay nothing measurable.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._event_resolve_gates(
    p_store_id      integer,
    p_object_type   integer,
    p_relation      integer,
    p_from_snapshot boolean DEFAULT false
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    v_out jsonb;
BEGIN
    IF p_from_snapshot THEN
        EXECUTE 'SELECT COALESCE(jsonb_agg(jsonb_build_object(''name'', g.name, ''spec'', g.spec) ORDER BY g.name), ''[]''::jsonb)
                   FROM _snapshot_gates g
                  WHERE g.object_type = $1 AND g.relation = $2'
           INTO v_out USING p_object_type, p_relation;
    ELSE
        SELECT COALESCE(jsonb_agg(jsonb_build_object('name', g.name, 'spec', g.spec) ORDER BY g.name), '[]'::jsonb)
          INTO v_out
          FROM authz.model_gates g
         WHERE g.store_id = p_store_id AND g.object_type = p_object_type AND g.relation = p_relation;
    END IF;
    RETURN v_out;
END;
$$;

------------------------------------------------------------------------
-- _event_gates_object_scoped: does any clause in a resolved gate list use
-- scope = object? list_objects decides with it whether the gates can be
-- settled ONCE for the subject (fast path) or must be evaluated per
-- candidate object.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._event_gates_object_scoped(p_gates jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
    SELECT EXISTS (
        SELECT 1
          FROM jsonb_array_elements(COALESCE(p_gates, '[]'::jsonb)) g
          CROSS JOIN LATERAL jsonb_array_elements(g -> 'spec' -> 'all_of') c
          CROSS JOIN LATERAL jsonb_each(c) kv
         WHERE kv.value ->> 'scope' = 'object')
$$;

------------------------------------------------------------------------
-- _event_eval_clause: evaluate one clause for the checked principal.
-- Returns the outcome record the evaluator traces: passed, a reason code
-- (gate_passed | gate_denied | gate_missing_context | gate_bad_request_value
-- | gate_payload_not_numeric | gate_error), the observed value and
-- threshold (counts and sums only — never matched payloads or object ids,
-- so a formerly_within on another stock's approval cannot leak through
-- explain), the missing request keys, and the normalized window text.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._event_eval_clause(
    p_store_id     integer,
    p_subject_type integer,
    p_subject_id   text,
    p_relation     integer,
    p_object_type  integer,       -- the checked object (used when scope = object)
    p_object_id    text,
    p_clause       jsonb,
    p_context      jsonb,
    p_now          timestamptz,
    p_as_of        timestamptz,
    p_assume       boolean,
    OUT passed        boolean,
    OUT reason        text,
    OUT observed      numeric,
    OUT threshold     numeric,
    OUT missing_keys  text[],
    OUT window_text   text,
    OUT scope         text,       -- 'subject' | 'object'
    OUT detail        text
) RETURNS record
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    v_prim        text;
    v_body        jsonb;
    v_action      integer;
    v_kind        smallint;
    v_from        timestamptz;
    v_from_incl   boolean := false;
    v_match       jsonb[];
    v_recorded_by text[];
    v_obj_type    integer;        -- object scope filters, NULL = any
    v_obj_id      text;
    v_key         text;
    v_val         jsonb;
    v_max         numeric;
    v_min         numeric;
    v_plus        numeric := 0;
    v_missing     text[] := '{}';
    v_bad         boolean := false;
    v_sum         record;
    r             record;
    v_tz          text;
BEGIN
    passed := false; reason := 'gate_error'; observed := NULL; threshold := NULL;
    missing_keys := NULL; window_text := NULL; detail := NULL;

    SELECT k INTO v_prim FROM jsonb_object_keys(p_clause) k LIMIT 1;
    v_body := p_clause -> v_prim;
    scope  := COALESCE(v_body ->> 'scope', 'subject');
    IF scope = 'object' THEN
        v_obj_type := p_object_type;
        v_obj_id   := p_object_id;
    END IF;

    -- Window
    IF v_body ? 'window' THEN
        v_from      := p_now - (v_body ->> 'window')::interval;
        window_text := v_body ->> 'window';
    ELSE
        v_tz        := v_body ->> 'tz';
        v_from      := date_trunc(v_body ->> 'calendar', p_now AT TIME ZONE v_tz) AT TIME ZONE v_tz;
        v_from_incl := true;
        window_text := (v_body ->> 'calendar') || '/' || v_tz;
    END IF;

    -- Names → ids, once per clause (no lookups inside the window queries).
    IF v_body ? 'action' THEN
        SELECT rl.id INTO v_action FROM authz.relations rl
         WHERE rl.store_id = p_store_id AND rl.name = v_body ->> 'action';
        IF v_action IS NULL THEN
            detail := 'action "' || (v_body ->> 'action') || '" does not resolve';
            RETURN;   -- gate_error: cannot happen after validation; guards drift
        END IF;
    ELSE
        v_action := p_relation;
    END IF;
    v_kind := authz._event_kind(COALESCE(v_body ->> 'kind', 'request'));

    -- match → nested containment fragments (references resolved, type kept)
    IF v_body ? 'match' THEN
        v_match := '{}';
        FOR v_key, v_val IN SELECT * FROM jsonb_each(v_body -> 'match') LOOP
            SELECT * INTO r FROM authz._event_resolve(v_val, p_context);
            IF r.missing IS NOT NULL THEN
                v_missing := v_missing || r.missing;
            ELSE
                v_match := v_match || authz._event_nest(v_key, r.value);
            END IF;
        END LOOP;
    END IF;
    IF v_body ? 'recorded_by' THEN
        v_recorded_by := ARRAY(SELECT jsonb_array_elements_text(v_body -> 'recorded_by'));
    END IF;

    -- Thresholds (references resolved; non-numeric = hard deny)
    FOREACH v_key IN ARRAY ARRAY['max', 'min', 'plus'] LOOP
        IF v_body ? v_key THEN
            SELECT * INTO r FROM authz._event_resolve(v_body -> v_key, p_context);
            IF r.missing IS NOT NULL THEN
                v_missing := v_missing || r.missing;
            ELSIF jsonb_typeof(r.value) <> 'number' THEN
                v_bad := true;
            ELSE
                IF v_key = 'max'  THEN v_max  := (r.value #>> '{}')::numeric; END IF;
                IF v_key = 'min'  THEN v_min  := (r.value #>> '{}')::numeric; END IF;
                IF v_key = 'plus' THEN v_plus := (r.value #>> '{}')::numeric; END IF;
            END IF;
        END IF;
    END LOOP;

    IF array_length(v_missing, 1) > 0 THEN
        missing_keys := (SELECT array_agg(DISTINCT m ORDER BY m) FROM unnest(v_missing) m);
        IF p_assume THEN
            -- Optimistic pass (check_access_detailed's second evaluation): a
            -- clause failing ONLY for missing request keys is treated as passing
            -- so the surrounding decision reveals whether context could flip it.
            passed := true; reason := 'gate_missing_context';
            detail := 'assumed passing: missing ' || array_to_string(missing_keys, ', ');
        ELSE
            passed := false; reason := 'gate_missing_context';
            detail := 'missing request context: ' || array_to_string(missing_keys, ', ');
        END IF;
        RETURN;
    END IF;
    IF v_bad THEN
        passed := false; reason := 'gate_bad_request_value';
        detail := 'a $request threshold value is not numeric';
        RETURN;
    END IF;

    CASE v_prim
        WHEN 'formerly_within' THEN
            observed  := CASE WHEN authz._event_formerly_within(
                                  p_store_id, p_subject_type, p_subject_id, v_action, v_kind, v_obj_type, v_obj_id,
                                  v_from, v_from_incl, p_now, v_match, v_recorded_by, p_as_of)
                              THEN 1 ELSE 0 END;
            threshold := 1;
            passed    := observed = 1;
        WHEN 'count_within' THEN
            -- `plus` (typically 1) counts the request being decided, so
            -- "max: 5, plus: 1" means at most 5 actions INCLUDING this one.
            observed  := authz._event_count_within(
                             p_store_id, p_subject_type, p_subject_id, v_action, v_kind, v_obj_type, v_obj_id,
                             v_from, v_from_incl, p_now, v_match, v_recorded_by, p_as_of) + v_plus;
            threshold := COALESCE(v_max, v_min);
            passed    := (v_max IS NULL OR observed <= v_max) AND (v_min IS NULL OR observed >= v_min);
        WHEN 'count_distinct_within' THEN
            observed  := authz._event_count_distinct_within(
                             p_store_id, p_subject_type, p_subject_id, v_action, v_kind, v_obj_type, v_obj_id,
                             v_from, v_from_incl, p_now, v_match, v_recorded_by, p_as_of,
                             v_body ->> 'key') + v_plus;
            threshold := COALESCE(v_max, v_min);
            passed    := (v_max IS NULL OR observed <= v_max) AND (v_min IS NULL OR observed >= v_min);
        WHEN 'sum_within' THEN
            SELECT * INTO v_sum FROM authz._event_sum_within(
                         p_store_id, p_subject_type, p_subject_id, v_action, v_kind, v_obj_type, v_obj_id,
                         v_from, v_from_incl, p_now, v_match, v_recorded_by, p_as_of,
                         v_body ->> 'field');
            IF NOT v_sum.all_numeric THEN
                passed := false; reason := 'gate_payload_not_numeric';
                detail := 'a matched event has no numeric "' || (v_body ->> 'field') || '"';
                RETURN;
            END IF;
            observed  := v_sum.total + v_plus;
            threshold := COALESCE(v_max, v_min);
            passed    := (v_max IS NULL OR observed <= v_max) AND (v_min IS NULL OR observed >= v_min);
    END CASE;

    reason := CASE WHEN passed THEN 'gate_passed' ELSE 'gate_denied' END;
    detail := v_prim || ' observed ' || observed || ' vs ' || COALESCE(threshold::text, '-')
              || ' in ' || window_text || CASE WHEN scope = 'object' THEN ' on this object' ELSE '' END;
EXCEPTION
    WHEN query_canceled THEN
        RAISE;         -- statement_timeout / cancel aborts the check, never a silent deny
    WHEN program_limit_exceeded THEN
        RAISE;
    WHEN OTHERS THEN
        passed := false; reason := 'gate_error'; detail := SQLERRM;
END;
$$;

------------------------------------------------------------------------
-- _event_gates_mode: the database-wide switch, GUC authz.gates_mode —
--   enforce (default): gates deny;
--   shadow:  every gate evaluates and reports but never denies (rollout);
--   off:     gates are not evaluated at all (emergency kill switch).
-- Per session (SET) or per database (ALTER DATABASE authz SET …). Any other
-- value reads as enforce (fail closed). Per-gate `mode: shadow` in the spec
-- shadows one gate regardless of the switch.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._event_gates_mode() RETURNS text
    LANGUAGE sql STABLE AS $$
    SELECT CASE current_setting('authz.gates_mode', true)
               WHEN 'shadow' THEN 'shadow'
               WHEN 'off'    THEN 'off'
               ELSE 'enforce'
           END
$$;

------------------------------------------------------------------------
-- _event_check_gates: evaluate every gate on (store, object_type, relation)
-- for the checked principal; true when none exist or all clauses pass.
--
-- p_gates: a pre-resolved gate list (list_subjects hoists it once per
-- statement; list_objects passes '[]' after evaluating subject-scoped gates
-- up front, or the list itself when a clause is object-scoped); NULL =
-- resolve here. p_object_type/p_object_id are the checked object — what
-- scope = object clauses filter on. p_as_of / p_from_snapshot: the time-travel path (windows
-- relative to p_as_of, definitions from the audit snapshot, events bounded
-- by recorded_at <= p_as_of). With authz.trace on, one temporal_gate step
-- per clause is written into pg_temp._access_trace (depth 0), and every
-- clause is evaluated so explain shows the whole gate; otherwise the first
-- failing clause short-circuits.
--
-- SHADOW: a gate with spec mode = shadow, or every gate while
-- authz.gates_mode = shadow, is evaluated exactly the same way but a failing
-- clause does NOT deny; a gate with spec mode = off is skipped entirely
-- (kept for its definition and history): the step is traced with shadow = true (its real
-- reason/observed/threshold kept; decision.reason and missing_context ignore
-- it) and a structured line goes to the server log (RAISE LOG:
-- "gate_shadow store=… gate=… clause=… reason=… observed=… threshold=…"),
-- which is replica-safe — the check path still never writes. With
-- authz.gates_mode = off no gate is evaluated (no steps, no cost).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._event_check_gates(
    p_store_id        integer,
    p_user_type       integer,
    p_user_id         text,
    p_relation        integer,
    p_object_type     integer,
    p_object_id       text,
    p_request_context jsonb DEFAULT NULL,
    p_as_of           timestamptz DEFAULT NULL,
    p_from_snapshot   boolean DEFAULT false,
    p_gates           jsonb DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_gates   jsonb := COALESCE(p_gates, authz._event_resolve_gates(p_store_id, p_object_type, p_relation, p_from_snapshot));
    v_trace   boolean;
    v_assume  boolean;
    v_now     timestamptz;
    v_all     boolean := true;
    v_gate    jsonb;
    v_clause  jsonb;
    v_idx     int;
    r         record;
    v_subject text;
    v_rel     text;
    v_object  text;
    v_start   timestamptz;
    v_mode    text;
    v_shadow  boolean;
    v_store   text;
BEGIN
    IF jsonb_array_length(v_gates) = 0 THEN
        RETURN true;
    END IF;
    v_mode := authz._event_gates_mode();
    IF v_mode = 'off' THEN
        RETURN true;   -- kill switch: gates are not evaluated at all
    END IF;

    v_trace  := COALESCE(current_setting('authz.trace', true), 'off') = 'on';
    v_assume := COALESCE(current_setting('authz._assume_missing_ctx', true), '') = 'on';
    -- clock_timestamp(), not statement_timestamp(): reserve_event evaluates
    -- gates AFTER waiting for its per-subject lock, inside the statement that
    -- took it. The statement's start time would predate events the previous
    -- lock holder recorded meanwhile, leaving them outside the window's upper
    -- bound (reproduced as over-admission under parallel reserves).
    v_now    := COALESCE(p_as_of, clock_timestamp());

    IF v_trace THEN
        v_subject := (SELECT name FROM authz.types     WHERE id = p_user_type)   || ':' || p_user_id;
        v_rel     := (SELECT name FROM authz.relations WHERE id = p_relation);
        v_object  := (SELECT name FROM authz.types     WHERE id = p_object_type) || ':' || COALESCE(p_object_id, '*');
    END IF;

    FOR v_gate IN SELECT * FROM jsonb_array_elements(v_gates) LOOP
        IF (v_gate -> 'spec' ->> 'mode') = 'off' THEN
            CONTINUE;   -- defined but disabled: no clauses evaluated, no steps
        END IF;
        v_idx := 0;
        v_shadow := v_mode = 'shadow' OR (v_gate -> 'spec' ->> 'mode') = 'shadow';
        FOR v_clause IN SELECT * FROM jsonb_array_elements(v_gate -> 'spec' -> 'all_of') LOOP
            v_start := clock_timestamp();
            SELECT * INTO r FROM authz._event_eval_clause(
                     p_store_id, p_user_type, p_user_id, p_relation, p_object_type, p_object_id, v_clause,
                     p_request_context, v_now, p_as_of, v_assume);
            IF v_trace THEN
                INSERT INTO _access_trace (
                    depth, rule_type, subject, relation, object, result, detail, duration_ms,
                    condition_missing_keys, gate_name, gate_clause, gate_window,
                    gate_observed, gate_threshold, gate_reason, gate_scope, gate_shadow)
                VALUES (
                    0, 'temporal_gate', v_subject, v_rel, v_object, r.passed,
                    'gate "' || (v_gate ->> 'name') || '" clause ' || v_idx
                        || CASE WHEN v_shadow THEN ' [shadow]' ELSE '' END || ': ' || COALESCE(r.detail, r.reason),
                    extract(epoch from clock_timestamp() - v_start) * 1000,
                    r.missing_keys, v_gate ->> 'name',
                    v_idx || ':' || (SELECT k FROM jsonb_object_keys(v_clause) k LIMIT 1),
                    r.window_text, r.observed, r.threshold, r.reason, r.scope, v_shadow);
            END IF;
            IF NOT r.passed THEN
                IF v_shadow THEN
                    -- Report, never deny. Structured server-log line (replica-safe).
                    -- Names are resolved lazily (only tracing resolves them up front):
                    -- the line is for humans reading the server log.
                    IF v_store IS NULL THEN
                        SELECT st.name INTO v_store FROM authz.stores st WHERE st.id = p_store_id;
                    END IF;
                    IF v_rel IS NULL THEN
                        v_subject := (SELECT name FROM authz.types     WHERE id = p_user_type)   || ':' || p_user_id;
                        v_rel     := (SELECT name FROM authz.relations WHERE id = p_relation);
                        v_object  := (SELECT name FROM authz.types     WHERE id = p_object_type) || ':' || COALESCE(p_object_id, '*');
                    END IF;
                    RAISE LOG 'gate_shadow store=% gate=% clause=%:% relation=% subject=% object=% reason=% observed=% threshold=% missing=%',
                        v_store, v_gate ->> 'name', v_idx, (SELECT k FROM jsonb_object_keys(v_clause) k LIMIT 1),
                        v_rel, v_subject, v_object,
                        r.reason, r.observed, r.threshold, COALESCE(array_to_string(r.missing_keys, ','), '-');
                ELSE
                    v_all := false;
                    IF NOT v_trace THEN
                        RETURN false;
                    END IF;
                END IF;
            END IF;
            v_idx := v_idx + 1;
        END LOOP;
    END LOOP;

    RETURN v_all;
END;
$$;

------------------------------------------------------------------------
-- gate_windows / max_gate_window: the retention requirement gates impose.
-- A dropped month or purged range under-counts every window that reaches
-- into it, which can only RELAX a cap — so event retention must be >= the
-- longest live gate window. gate_windows lists each clause's effective
-- window length: the interval itself for `window`; for `calendar` the
-- longest span a bucket can cover (day = 25 h for a DST transition, week =
-- 7 d 1 h, month = 31 d, year = 366 d). max_gate_window is the maximum
-- (NULL when no gates); NULL p_store = every store (the fleet-wide bound the
-- partition drop checks). Reader-callable: the readiness runbook compares it
-- with the retention schedule; drop_event_partitions_before / purge_events
-- enforce it (events_admin.sql). Gates in mode = shadow or off are INCLUDED:
-- their definitions are live, and re-enabling one after a purge would
-- under-count — drop a gate to lift its retention requirement.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._event_clause_window(p_body jsonb) RETURNS interval
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
        WHEN p_body ? 'window' THEN (p_body ->> 'window')::interval
        ELSE CASE p_body ->> 'calendar'
            WHEN 'hour'  THEN interval '1 hour'
            WHEN 'day'   THEN interval '25 hours'
            WHEN 'week'  THEN interval '7 days 1 hour'
            WHEN 'month' THEN interval '31 days'
            WHEN 'year'  THEN interval '366 days'
        END
    END
$$;

CREATE OR REPLACE FUNCTION authz.gate_windows(p_store text DEFAULT NULL)
RETURNS TABLE (store text, object_type text, relation text, gate text, clause text, "window" interval)
LANGUAGE sql STABLE AS $$
    SELECT st.name, ot.name, rl.name, g.name,
           (c.ord - 1) || ':' || (SELECT k FROM jsonb_object_keys(c.clause) k LIMIT 1),
           authz._event_clause_window(c.clause -> (SELECT k FROM jsonb_object_keys(c.clause) k LIMIT 1))
      FROM authz.model_gates g
      JOIN authz.stores    st ON st.id = g.store_id
      JOIN authz.types     ot ON ot.id = g.object_type
      JOIN authz.relations rl ON rl.id = g.relation
      CROSS JOIN LATERAL jsonb_array_elements(g.spec -> 'all_of') WITH ORDINALITY AS c(clause, ord)
     WHERE p_store IS NULL OR st.name = p_store
     ORDER BY 1, 2, 3, 4, 5
$$;

CREATE OR REPLACE FUNCTION authz.max_gate_window(p_store text DEFAULT NULL) RETURNS interval
LANGUAGE sql STABLE AS $$
    SELECT max(w."window") FROM authz.gate_windows(p_store) w
$$;
