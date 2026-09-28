-- Action log (authz.events) — the READ side: kind constants, the record-time
-- bounds, and list_events (auditor inspection). Part of the READ profile so a
-- read-only install fed by replication can inspect the log; recording and
-- partition management live in events_admin.sql (write profile). ADR 0012.
--
-- Naming: the whole events family shares the _event_ prefix (constants, bound
-- helpers, and — in phase 2 — the window primitives and gate evaluator), the
-- way _rls_* / _audit_* / _eval_* group their subsystems. Public names
-- (record_event, list_events, …) stay unprefixed like the rest of the API.
--
-- Depends on: core_internal.sql (_s/_t/_r), migration 0010 (authz.events).

------------------------------------------------------------------------
-- Event kind constants — the `kind` column of authz.events. Use these
-- instead of bare literals in engine code and tests. (The CHECK on the
-- table spells the literals out: it resolves when the migration creates the
-- table, before this file loads — keep the two in sync.)
------------------------------------------------------------------------

-- request: the PEP is about to perform the action (Dogwood's `request`).
CREATE OR REPLACE FUNCTION authz._event_kind_request() RETURNS smallint
    LANGUAGE sql IMMUTABLE AS $$ SELECT 1::smallint $$;

-- response: the action completed; its outcome lives in payload.output.*.
CREATE OR REPLACE FUNCTION authz._event_kind_response() RETURNS smallint
    LANGUAGE sql IMMUTABLE AS $$ SELECT 2::smallint $$;

-- denied: the PEP got (or enforced) a deny and wants the attempt on record
-- (enables "lock out after N denied attempts" gates in phase 2).
CREATE OR REPLACE FUNCTION authz._event_kind_denied() RETURNS smallint
    LANGUAGE sql IMMUTABLE AS $$ SELECT 3::smallint $$;

-- Resolve a kind name to its id. Strict like _s/_t/_r: an unknown kind is a
-- caller bug and raises (invalid_parameter_value, so pgauthzd maps it to 400).
CREATE OR REPLACE FUNCTION authz._event_kind(p_name text) RETURNS smallint
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_kind smallint := CASE p_name
        WHEN 'request'  THEN authz._event_kind_request()
        WHEN 'response' THEN authz._event_kind_response()
        WHEN 'denied'   THEN authz._event_kind_denied()
    END;
BEGIN
    IF v_kind IS NULL THEN
        RAISE EXCEPTION 'Unknown event kind "%": expected request | response | denied', p_name
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    RETURN v_kind;
END;
$$;

-- Render a kind id as its name (list_events, views).
CREATE OR REPLACE FUNCTION authz._event_kind_name(p_kind smallint) RETURNS text
    LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE p_kind
        WHEN 1 THEN 'request'
        WHEN 2 THEN 'response'
        WHEN 3 THEN 'denied'
    END
$$;

------------------------------------------------------------------------
-- Record-time bounds on the caller-asserted occurred_at (ADR 0012 §trust).
-- The recorder already asserts THAT the event happened; trusting WHEN adds no
-- new trust — but an unbounded timestamp would let a buggy or hostile
-- recorder park events outside every window (or inside a future one), so
-- both directions are capped. Override per session or per database:
--   ALTER DATABASE authz SET authz.event_max_backdate = '72 hours';
------------------------------------------------------------------------

-- How far in the future occurred_at may be (clock skew between the recorder
-- and the database). Default 5 seconds.
CREATE OR REPLACE FUNCTION authz._event_max_future_skew() RETURNS interval
    LANGUAGE sql STABLE AS
    $$ SELECT COALESCE(NULLIF(current_setting('authz.event_max_future_skew', true), '')::interval, interval '5 seconds') $$;

-- How far in the past occurred_at may be (asynchronous ingestion lag: set it
-- to the queue's worst-case delivery delay). Default 24 hours.
CREATE OR REPLACE FUNCTION authz._event_max_backdate() RETURNS interval
    LANGUAGE sql STABLE AS
    $$ SELECT COALESCE(NULLIF(current_setting('authz.event_max_backdate', true), '')::interval, interval '24 hours') $$;

------------------------------------------------------------------------
-- Payload schemas (migration 0014): authz.relations.payload_schema.
--
--   {"required": {"input.amount": "number", "input.stock": "string"},
--    "optional": {"input.memo": "string"},
--    "additional": false,                       -- default true
--    "kinds": {"response": {"required": {"output.status": "string"},
--                           "optional": {"output.approved": "boolean"}}}}
--
-- Paths are dotted object paths (no arrays); types are the JSON kinds string
-- | number | boolean | object | array | any. `required`/`optional` apply to
-- every kind; `kinds.<request|response|denied>` adds paths for one kind.
-- `additional: false` closes the shape: every payload leaf must be declared
-- (a declared `object` or `any` path admits an arbitrary subtree beneath it).
------------------------------------------------------------------------

-- _event_validate_payload_schema: validate + normalize a schema (raises
-- invalid_parameter_value). NULL passes through (no schema).
CREATE OR REPLACE FUNCTION authz._event_validate_payload_schema(p_schema jsonb) RETURNS jsonb
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_key  text;
    v_kind text;
    v_sec  jsonb;
BEGIN
    IF p_schema IS NULL THEN
        RETURN NULL;
    END IF;
    IF jsonb_typeof(p_schema) <> 'object' THEN
        RAISE EXCEPTION 'payload schema must be a JSON object' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOR v_key IN SELECT jsonb_object_keys(p_schema) LOOP
        IF v_key NOT IN ('required', 'optional', 'additional', 'kinds') THEN
            RAISE EXCEPTION 'payload schema has unknown key "%"', v_key USING ERRCODE = 'invalid_parameter_value';
        END IF;
    END LOOP;
    PERFORM authz._event_validate_schema_section(p_schema, '');
    IF p_schema ? 'additional' AND jsonb_typeof(p_schema -> 'additional') <> 'boolean' THEN
        RAISE EXCEPTION 'payload schema "additional" must be a boolean' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_schema ? 'kinds' THEN
        IF jsonb_typeof(p_schema -> 'kinds') <> 'object' THEN
            RAISE EXCEPTION 'payload schema "kinds" must be an object' USING ERRCODE = 'invalid_parameter_value';
        END IF;
        FOR v_kind, v_sec IN SELECT * FROM jsonb_each(p_schema -> 'kinds') LOOP
            IF v_kind NOT IN ('request', 'response', 'denied') THEN
                RAISE EXCEPTION 'payload schema kinds: unknown kind "%"', v_kind USING ERRCODE = 'invalid_parameter_value';
            END IF;
            IF jsonb_typeof(v_sec) <> 'object' THEN
                RAISE EXCEPTION 'payload schema kinds.% must be an object', v_kind USING ERRCODE = 'invalid_parameter_value';
            END IF;
            FOR v_key IN SELECT jsonb_object_keys(v_sec) LOOP
                IF v_key NOT IN ('required', 'optional') THEN
                    RAISE EXCEPTION 'payload schema kinds.% has unknown key "%"', v_kind, v_key USING ERRCODE = 'invalid_parameter_value';
                END IF;
            END LOOP;
            PERFORM authz._event_validate_schema_section(v_sec, 'kinds.' || v_kind || '.');
        END LOOP;
    END IF;
    RETURN p_schema;
END;
$$;

-- one {required, optional} section: dotted paths → known types
CREATE OR REPLACE FUNCTION authz._event_validate_schema_section(p_sec jsonb, p_prefix text) RETURNS void
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_list text;
    v_path text;
    v_type jsonb;
BEGIN
    FOREACH v_list IN ARRAY ARRAY['required', 'optional'] LOOP
        IF p_sec ? v_list THEN
            IF jsonb_typeof(p_sec -> v_list) <> 'object' THEN
                RAISE EXCEPTION 'payload schema % must be an object of {path: type}', p_prefix || v_list
                    USING ERRCODE = 'invalid_parameter_value';
            END IF;
            FOR v_path, v_type IN SELECT * FROM jsonb_each(p_sec -> v_list) LOOP
                IF NOT authz._event_path_ok(v_path) THEN
                    RAISE EXCEPTION 'payload schema %: "%" is not a dotted path', p_prefix || v_list, v_path
                        USING ERRCODE = 'invalid_parameter_value';
                END IF;
                IF jsonb_typeof(v_type) <> 'string'
                   OR (v_type #>> '{}') NOT IN ('string', 'number', 'boolean', 'object', 'array', 'any') THEN
                    RAISE EXCEPTION 'payload schema %.%: type must be string | number | boolean | object | array | any',
                        p_prefix || v_list, v_path USING ERRCODE = 'invalid_parameter_value';
                END IF;
            END LOOP;
        END IF;
    END LOOP;
END;
$$;

-- _event_schema_paths: the effective {path: type} map for a kind (base +
-- kinds.<kind>), required and optional combined; p_required_only narrows.
CREATE OR REPLACE FUNCTION authz._event_schema_paths(p_schema jsonb, p_kind text, p_required_only boolean) RETURNS jsonb
LANGUAGE sql IMMUTABLE AS $$
    SELECT COALESCE(p_schema -> 'required', '{}'::jsonb)
        || CASE WHEN p_required_only THEN '{}'::jsonb ELSE COALESCE(p_schema -> 'optional', '{}'::jsonb) END
        || COALESCE(p_schema -> 'kinds' -> p_kind -> 'required', '{}'::jsonb)
        || CASE WHEN p_required_only THEN '{}'::jsonb ELSE COALESCE(p_schema -> 'kinds' -> p_kind -> 'optional', '{}'::jsonb) END
$$;

-- _event_check_payload: enforce a relation's declared schema on one event's
-- payload. Raises invalid_parameter_value naming every violation. The caller
-- passes the schema it already read with the relation row (record_event
-- resolves the action and its schema in one lookup); NULL = no schema.
DROP FUNCTION IF EXISTS authz._event_check_payload(integer, text, jsonb);
CREATE OR REPLACE FUNCTION authz._event_check_payload(
    p_schema  jsonb,
    p_kind    text,
    p_payload jsonb
) RETURNS void
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_schema  jsonb := p_schema;
    v_all     jsonb;
    v_path    text;
    v_type    text;
    v_val     jsonb;
    v_errs    text[] := '{}';
    v_leaf    record;
BEGIN
    IF v_schema IS NULL THEN
        RETURN;
    END IF;
    -- required paths present, and every declared path present has the declared type
    FOR v_path, v_type IN SELECT key, value #>> '{}' FROM jsonb_each(authz._event_schema_paths(v_schema, p_kind, true)) LOOP
        v_val := p_payload #> string_to_array(v_path, '.');
        IF v_val IS NULL OR jsonb_typeof(v_val) = 'null' THEN
            v_errs := v_errs || format('missing required %s (%s)', v_path, v_type);
        END IF;
    END LOOP;
    v_all := authz._event_schema_paths(v_schema, p_kind, false);
    FOR v_path, v_type IN SELECT key, value #>> '{}' FROM jsonb_each(v_all) LOOP
        v_val := p_payload #> string_to_array(v_path, '.');
        IF v_val IS NOT NULL AND jsonb_typeof(v_val) <> 'null' AND v_type <> 'any' AND jsonb_typeof(v_val) <> v_type THEN
            v_errs := v_errs || format('%s must be %s (got %s)', v_path, v_type, jsonb_typeof(v_val));
        END IF;
    END LOOP;
    -- closed shape: every payload leaf must be declared, or lie under a declared object/any path
    IF COALESCE((v_schema ->> 'additional')::boolean, true) = false THEN
        FOR v_leaf IN SELECT * FROM authz._event_payload_leaves(p_payload, '') LOOP
            IF NOT EXISTS (
                SELECT 1 FROM jsonb_each(v_all) d
                 WHERE d.key = v_leaf.path
                    OR (v_leaf.path LIKE d.key || '.%' AND (d.value #>> '{}') IN ('object', 'any'))
            ) THEN
                v_errs := v_errs || format('undeclared field %s (schema is closed)', v_leaf.path);
            END IF;
        END LOOP;
    END IF;
    IF array_length(v_errs, 1) > 0 THEN
        RAISE EXCEPTION 'payload does not match the action''s schema (kind %): %', p_kind, array_to_string(v_errs, '; ')
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
END;
$$;

-- dotted paths of every leaf (non-object value) in a payload
CREATE OR REPLACE FUNCTION authz._event_payload_leaves(p_doc jsonb, p_prefix text)
RETURNS TABLE (path text) LANGUAGE sql IMMUTABLE AS $$
    WITH RECURSIVE walk(path, val) AS (
        SELECT p_prefix || e.key, e.value FROM jsonb_each(p_doc) e
        UNION ALL
        SELECT w.path || '.' || e.key, e.value
          FROM walk w CROSS JOIN LATERAL jsonb_each(w.val) e
         WHERE jsonb_typeof(w.val) = 'object'
    )
    SELECT path FROM walk WHERE jsonb_typeof(val) <> 'object' OR val = '{}'::jsonb
$$;

------------------------------------------------------------------------
-- list_events: inspect a store's action log — "what did X do?" — keyset
-- paginated like watch_changes: (occurred_at, seq) ascending, the caller
-- feeds the last row's pair back as (p_after_at, p_after_seq). Every filter
-- is optional (NULL = any) except that p_subject_id needs p_subject_type (a
-- subject is a pair, and idx_events_subject_list is keyed on both);
-- p_since/p_until bound occurred_at inclusively (p_since also drives
-- partition pruning). Unknown filter names yield an
-- empty result rather than an error — a filter is a filter, not a lookup.
--
-- Payload is returned as-is (the auditor's data, like audit_list_*'s
-- condition_context). Auditor-level privilege: the log exposes per-principal
-- behaviour. Retired stores stay inspectable (_s(..., true)), as for audit.
--
-- '-infinity' (not NULL) is the empty-cursor sentinel: a NULL inside a row
-- comparison makes the whole comparison NULL and returns zero rows.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.list_events(
    p_store        text,
    p_subject_type text        DEFAULT NULL,
    p_subject_id   text        DEFAULT NULL,
    p_action       text        DEFAULT NULL,
    p_kind         text        DEFAULT NULL,
    p_object_type  text        DEFAULT NULL,
    p_object_id    text        DEFAULT NULL,
    p_recorded_by  text        DEFAULT NULL,
    p_since        timestamptz DEFAULT NULL,
    p_until        timestamptz DEFAULT NULL,
    p_after_at     timestamptz DEFAULT '-infinity',
    p_after_seq    bigint      DEFAULT 0,
    p_limit        int         DEFAULT 100
) RETURNS TABLE (
    seq          bigint,
    event_id     text,
    subject_type text,
    subject_id   text,
    action       text,
    object_type  text,
    object_id    text,
    kind         text,
    payload      jsonb,
    occurred_at  timestamptz,
    recorded_at  timestamptz,
    recorded_by  text
)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id     integer := authz._s(p_store, true);
    v_subject_type integer;
    v_action       integer;
    v_object_type  integer;
    v_kind         smallint;
    v_sql          text;
BEGIN
    IF p_limit IS NULL OR p_limit < 0 THEN
        RAISE EXCEPTION 'p_limit must be >= 0' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    -- A subject is a (type, id) pair; the listing index is keyed on both, and an
    -- id-only filter would degrade to a scan of the whole log.
    IF p_subject_id IS NOT NULL AND p_subject_type IS NULL THEN
        RAISE EXCEPTION 'p_subject_id requires p_subject_type' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Filters resolve by direct lookup (no _t/_r: those raise on unknown
    -- names, and an unknown filter value simply matches nothing). A name that
    -- does not resolve pins the id to -1, which no row carries.
    IF p_subject_type IS NOT NULL THEN
        SELECT t.id INTO v_subject_type FROM authz.types t
         WHERE t.store_id = v_store_id AND t.name = p_subject_type;
        v_subject_type := COALESCE(v_subject_type, -1);
    END IF;
    IF p_action IS NOT NULL THEN
        SELECT r.id INTO v_action FROM authz.relations r
         WHERE r.store_id = v_store_id AND r.name = p_action;
        v_action := COALESCE(v_action, -1);
    END IF;
    IF p_object_type IS NOT NULL THEN
        SELECT t.id INTO v_object_type FROM authz.types t
         WHERE t.store_id = v_store_id AND t.name = p_object_type;
        v_object_type := COALESCE(v_object_type, -1);
    END IF;
    IF p_kind IS NOT NULL THEN
        v_kind := CASE p_kind
            WHEN 'request'  THEN authz._event_kind_request()
            WHEN 'response' THEN authz._event_kind_response()
            WHEN 'denied'   THEN authz._event_kind_denied()
            ELSE -1
        END;
    END IF;

    -- Dynamic SQL, deliberately: written as `(param IS NULL OR col = param)`,
    -- the generic plan a plpgsql function settles on after a few calls cannot
    -- fold the NULL checks, so no filter ever becomes an index condition and a
    -- subject listing degrades to an ordered scan of the whole log (measured:
    -- 23 ms and 191k buffers for a 100-row page on a 220k-row log — the
    -- realistic case being a recently active subject whose events all sit at
    -- the end of the time order). Only the filters actually supplied become
    -- predicates, so each call gets the plan its filters deserve
    -- (idx_events_subject_list serves the by-subject case). Values are passed
    -- as parameters, never interpolated.
    v_sql := 'SELECT e.seq, e.event_id, st.name, e.subject_id, r.name, ot.name, e.object_id,
                     authz._event_kind_name(e.kind), e.payload, e.occurred_at, e.recorded_at, e.recorded_by
                FROM authz.events e
                LEFT JOIN authz.types     st ON st.id = e.subject_type   -- LEFT: a purged dictionary must not hide history
                LEFT JOIN authz.relations r  ON r.id  = e.action
                LEFT JOIN authz.types     ot ON ot.id = e.object_type
               WHERE e.store_id = $1
                 AND (e.occurred_at, e.seq) > ($2, $3)'
          || CASE WHEN v_subject_type IS NOT NULL THEN ' AND e.subject_type = $4'  ELSE '' END
          || CASE WHEN p_subject_id   IS NOT NULL THEN ' AND e.subject_id = $5'    ELSE '' END
          || CASE WHEN v_action       IS NOT NULL THEN ' AND e.action = $6'        ELSE '' END
          || CASE WHEN v_kind         IS NOT NULL THEN ' AND e.kind = $7'          ELSE '' END
          || CASE WHEN v_object_type  IS NOT NULL THEN ' AND e.object_type = $8'   ELSE '' END
          || CASE WHEN p_object_id    IS NOT NULL THEN ' AND e.object_id = $9'     ELSE '' END
          || CASE WHEN p_recorded_by  IS NOT NULL THEN ' AND e.recorded_by = $10'  ELSE '' END
          || CASE WHEN p_since        IS NOT NULL THEN ' AND e.occurred_at >= $11' ELSE '' END
          || CASE WHEN p_until        IS NOT NULL THEN ' AND e.occurred_at <= $12' ELSE '' END
          || ' ORDER BY e.occurred_at, e.seq LIMIT $13';
    RETURN QUERY EXECUTE v_sql
        USING v_store_id, p_after_at, p_after_seq, v_subject_type, p_subject_id, v_action, v_kind,
              v_object_type, p_object_id, p_recorded_by, p_since, p_until, p_limit;
END;
$$;

------------------------------------------------------------------------
-- events_readiness: can the temporal gates be trusted right now? One row
-- per store (or the given store): how many gates and in which mode, the
-- longest window any of them looks back, how far back the retained history
-- reaches (the earliest range partition's lower bound — partitions are
-- fleet-wide — or the store's oldest event), whether that history covers
-- the longest window (a young deployment or an aggressive retention
-- under-counts, which can only RELAX a cap), recording activity in the last
-- hour, the worst occurred→recorded delay in that hour (ingestion-lag proxy;
-- queue-side lag and dead letters live in the consumer's own metrics), and
-- the recorder identities seen in the last 24 hours. Reader-callable
-- (SECURITY DEFINER); sampled by pgauthzd into metrics and checked by
-- `pgauthzd doctor`. Review #11.
CREATE OR REPLACE FUNCTION authz.events_readiness(p_store text DEFAULT NULL)
RETURNS TABLE (
    store                   text,
    gates                   integer,
    gates_enforce           integer,
    gates_shadow            integer,
    gates_off               integer,
    max_gate_window         interval,
    history_since           timestamptz,
    history_covers_gates    boolean,
    history_deficit         interval,
    oldest_event_at         timestamptz,
    newest_event_at         timestamptz,
    last_recorded_at        timestamptz,
    events_1h               bigint,
    max_recording_delay_1h  interval,
    recorders_24h           text[]
)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_partition_from timestamptz;
    v_now            timestamptz := clock_timestamp();
BEGIN
    -- Earliest retained RANGE partition of authz.events (the DEFAULT partition
    -- has no lower bound and is never dropped by retention).
    SELECT min(substring(pg_get_expr(c.relpartbound, c.oid) FROM $re$FROM \('([^']+)'\)$re$)::timestamptz)
      INTO v_partition_from
      FROM pg_catalog.pg_inherits i
      JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE i.inhparent = 'authz.events'::regclass
       AND n.nspname = 'authz'
       AND pg_get_expr(c.relpartbound, c.oid) <> 'DEFAULT';

    RETURN QUERY
    WITH st AS (
        SELECT s.id, s.name
          FROM authz.stores s
         WHERE s.deleted_at IS NULL
           AND (p_store IS NULL OR s.name = p_store)
    ),
    g AS (
        SELECT mg.store_id,
               count(*)::int                                                          AS gates,
               count(*) FILTER (WHERE coalesce(mg.spec ->> 'mode', 'enforce') = 'enforce')::int AS gates_enforce,
               count(*) FILTER (WHERE mg.spec ->> 'mode' = 'shadow')::int              AS gates_shadow,
               count(*) FILTER (WHERE mg.spec ->> 'mode' = 'off')::int                 AS gates_off
          FROM authz.model_gates mg
         GROUP BY mg.store_id
    ),
    ev AS (
        SELECT e.store_id,
               min(e.occurred_at)  AS oldest_event_at,
               max(e.occurred_at)  AS newest_event_at,
               max(e.recorded_at)  AS last_recorded_at
          FROM authz.events e
         GROUP BY e.store_id
    ),
    ev1h AS (
        SELECT e.store_id,
               count(*)::bigint                       AS events_1h,
               max(e.recorded_at - e.occurred_at)     AS max_delay
          FROM authz.events e
         WHERE e.recorded_at > v_now - interval '1 hour'
         GROUP BY e.store_id
    ),
    rec AS (
        SELECT e.store_id, array_agg(DISTINCT e.recorded_by ORDER BY e.recorded_by) AS recorders
          FROM authz.events e
         WHERE e.recorded_at > v_now - interval '24 hours'
         GROUP BY e.store_id
    ),
    w AS (
        SELECT gw.store AS name, max(gw."window") AS max_window
          FROM authz.gate_windows(p_store) gw
         GROUP BY gw.store
    )
    SELECT st.name,
           coalesce(g.gates, 0), coalesce(g.gates_enforce, 0), coalesce(g.gates_shadow, 0), coalesce(g.gates_off, 0),
           w.max_window,
           coalesce(v_partition_from, ev.oldest_event_at)                                   AS history_since,
           CASE WHEN w.max_window IS NULL THEN true                                          -- no gates: nothing to under-count
                WHEN coalesce(v_partition_from, ev.oldest_event_at) IS NULL THEN true       -- nothing retained, nothing dropped
                ELSE coalesce(v_partition_from, ev.oldest_event_at) <= v_now - w.max_window
           END                                                                              AS history_covers_gates,
           CASE WHEN w.max_window IS NOT NULL
                 AND coalesce(v_partition_from, ev.oldest_event_at) > v_now - w.max_window
                THEN coalesce(v_partition_from, ev.oldest_event_at) - (v_now - w.max_window) END AS history_deficit,
           ev.oldest_event_at, ev.newest_event_at, ev.last_recorded_at,
           coalesce(ev1h.events_1h, 0), ev1h.max_delay,
           coalesce(rec.recorders, '{}'::text[])
      FROM st
      LEFT JOIN g    ON g.store_id    = st.id
      LEFT JOIN ev   ON ev.store_id   = st.id
      LEFT JOIN ev1h ON ev1h.store_id = st.id
      LEFT JOIN rec  ON rec.store_id  = st.id
      LEFT JOIN w    ON w.name        = st.name
     ORDER BY st.name;
END;
$$;
