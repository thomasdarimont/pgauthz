-- Public audit API: point-in-time access checks and audit trail queries.
-- All functions accept text parameters and resolve IDs internally.
--
-- Depends on: engine/core_internal.sql, engine/audit_internal.sql

------------------------------------------------------------------------
-- ensure_audit_partitions: creates monthly audit partitions for the
-- current month and p_months_ahead following months. Returns the
-- number of partitions created (0 when all already exist).
--
-- Run this periodically (e.g. daily) from a scheduler so audit rows
-- never accumulate in the default partition and old months can be
-- dropped for retention. init.sh calls it once at setup; see
-- docs/DEVELOPMENT.md ("Audit partition maintenance") for scheduling.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.ensure_audit_partitions(
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
        IF authz._ensure_audit_partition(
               extract(year  from v_month)::int,
               extract(month from v_month)::int) THEN
            v_created := v_created + 1;
        END IF;
    END LOOP;

    RETURN v_created;
END;
$$;

------------------------------------------------------------------------
-- audit_check_access: "Could user X do action Y on resource Z at time T?"
-- Reconstructs the tuple state at p_at by replaying the audit log
-- into a snapshot temp table, then runs a check against that snapshot.
--
-- For conditional tuples, p_at is passed as request context (as
-- "current_time") so time-based conditions evaluate correctly.
-- Conditions that need other request keys (client IP, quotas, ...)
-- cannot be reconstructed from the audit log — supply them via
-- p_request_context; "current_time" is always overridden with p_at.
--
-- Note: the snapshot reconstructs the TUPLE state, the MODEL rule set, AND
-- the CONDITION expressions as of p_at (replaying tuples_audit, models_audit,
-- and conditions_audit), so the check resolves against the tuples, rules, and
-- condition expressions as they were then — not the current ones.
--
-- Note: uses _check_access_snapshot (dynamic SQL against temp tables)
-- to avoid reading current tuples, model rules, or condition expressions.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.audit_check_access(
    p_store           text,
    p_user_type       text,
    p_user_id         text,
    p_relation        text,
    p_object_type     text,
    p_object_id       text,
    p_at              timestamptz,
    p_request_context jsonb DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id    integer := authz._s(p_store);
    v_user_type   integer := authz._t(v_store_id, p_user_type);
    v_relation    integer := authz._r(v_store_id, p_relation);
    v_object_type integer := authz._t(v_store_id, p_object_type);
    v_result      boolean;
BEGIN
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');

    -- Build the tuple, model AND condition state as of p_at by replaying
    -- the logs, so the check resolves tuples, rules, and condition
    -- expressions all as they were then.
    PERFORM authz._build_audit_snapshot(v_store_id, p_at);
    PERFORM authz._build_model_snapshot(v_store_id, p_at);
    PERFORM authz._build_condition_snapshot(v_store_id, p_at);

    -- Run access check against the snapshot. Caller-supplied request
    -- context is merged in; current_time always reflects p_at.
    v_result := authz._check_access_snapshot(
        v_store_id, v_user_type, p_user_id, v_relation, v_object_type, p_object_id,
        COALESCE(p_request_context, '{}'::jsonb) || jsonb_build_object('current_time', p_at)
    );

    -- _snapshot_tuples has ON COMMIT DROP — no explicit cleanup needed.

    RETURN v_result;
END;
$$;

------------------------------------------------------------------------
-- audit_list_actions: "What could user X do on object Z at time T?"
-- Point-in-time variant of list_actions using the audit log.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.audit_list_actions(
    p_store           text,
    p_user_type       text,
    p_user_id         text,
    p_object_type     text,
    p_object_id       text,
    p_at              timestamptz,
    p_request_context jsonb DEFAULT NULL
) RETURNS TABLE (action text)
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id    integer := authz._s(p_store);
    v_user_type   integer := authz._t(v_store_id, p_user_type);
    v_object_type integer := authz._t(v_store_id, p_object_type);
BEGIN
    PERFORM authz._check_namespace_access(v_store_id, v_object_type, 'can_read');

    -- Build the point-in-time tuple, model AND condition snapshots ONCE and
    -- evaluate every relation against them (previously rebuilt per relation).
    PERFORM authz._build_audit_snapshot(v_store_id, p_at);
    PERFORM authz._build_model_snapshot(v_store_id, p_at);
    PERFORM authz._build_condition_snapshot(v_store_id, p_at);

    -- Candidate relations come from the model AS OF p_at (the snapshot),
    -- not the current model, so a relation whose rule was added later is
    -- not considered. Dynamic SQL because _snapshot_models is per-session.
    RETURN QUERY EXECUTE '
        SELECT r.name
          FROM (
              SELECT DISTINCT sm.relation
                FROM _snapshot_models sm
               WHERE sm.store_id    = $1
                 AND sm.object_type = $2
          ) dr
          JOIN authz.relations r ON r.id = dr.relation
         WHERE authz._check_access_snapshot($1, $3, $4, dr.relation, $2, $5, $6)'
    USING v_store_id, v_object_type, v_user_type, p_user_id, p_object_id,
          COALESCE(p_request_context, '{}'::jsonb) || jsonb_build_object('current_time', p_at);
END;
$$;

------------------------------------------------------------------------
-- audit_list_user: audit trail for a specific user.
-- Returns human-readable rows showing all permission changes for a user,
-- optionally filtered by time range.
--
-- Examples:
--   SELECT * FROM authz.audit_list_user('demo', 'internal_user', 'grace');
--   SELECT * FROM authz.audit_list_user('demo', 'internal_user', 'grace',
--       '2026-03-01'::timestamptz, '2026-03-31'::timestamptz);
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.audit_list_user(
    p_store       text,
    p_user_type   text,
    p_user_id     text,
    p_from        timestamptz DEFAULT NULL,
    p_to          timestamptz DEFAULT NULL
) RETURNS TABLE (
    id               uuid,
    action           text,
    performed_at     timestamptz,
    performed_by     text,
    user_relation    text,
    relation         text,
    object_type      text,
    object_id        text,
    condition_name   text,
    condition_context jsonb
)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id    integer := authz._s(p_store);
    v_user_type   integer := authz._t(v_store_id, p_user_type);
BEGIN
    RETURN QUERY
        SELECT a.id,
               a.action,
               a.performed_at,
               a.performed_by,
               ur.name  AS user_relation,
               r.name   AS relation,
               ot.name  AS object_type,
               a.object_id,
               c.name   AS condition_name,
               a.condition_context
          FROM authz.tuples_audit a
          JOIN authz.relations r  ON r.id  = a.relation
          JOIN authz.types ot     ON ot.id = a.object_type
          LEFT JOIN authz.relations ur ON ur.id = a.user_relation
          LEFT JOIN authz.conditions c ON c.id  = a.condition_id
         WHERE a.store_id  = v_store_id
           AND a.user_type = v_user_type
           AND a.user_id   = p_user_id
           AND (p_from IS NULL OR a.performed_at >= p_from)
           AND (p_to   IS NULL OR a.performed_at <= p_to)
         ORDER BY a.performed_at, a.seq;
END;
$$;

------------------------------------------------------------------------
-- audit_list_object: audit trail for a specific object.
-- Returns human-readable rows showing all permission changes on an object,
-- optionally filtered by time range.
--
-- Examples:
--   SELECT * FROM authz.audit_list_object('demo', 'document', 'doc_payroll_001');
--   SELECT * FROM authz.audit_list_object('demo', 'document', 'doc_payroll_001',
--       '2026-03-01'::timestamptz);
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.audit_list_object(
    p_store       text,
    p_object_type text,
    p_object_id   text,
    p_from        timestamptz DEFAULT NULL,
    p_to          timestamptz DEFAULT NULL
) RETURNS TABLE (
    action           text,
    performed_at     timestamptz,
    performed_by     text,
    user_type        text,
    user_id          text,
    user_relation    text,
    relation         text,
    condition_name   text,
    condition_context jsonb
)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_store_id    integer := authz._s(p_store);
    v_object_type integer := authz._t(v_store_id, p_object_type);
BEGIN
    RETURN QUERY
        SELECT a.action,
               a.performed_at,
               a.performed_by,
               ut.name  AS user_type,
               a.user_id,
               ur.name  AS user_relation,
               r.name   AS relation,
               c.name   AS condition_name,
               a.condition_context
          FROM authz.tuples_audit a
          JOIN authz.types ut     ON ut.id = a.user_type
          JOIN authz.relations r  ON r.id  = a.relation
          LEFT JOIN authz.relations ur ON ur.id = a.user_relation
          LEFT JOIN authz.conditions c ON c.id  = a.condition_id
         WHERE a.store_id    = v_store_id
           AND a.object_type = v_object_type
           AND a.object_id   = p_object_id
           AND (p_from IS NULL OR a.performed_at >= p_from)
           AND (p_to   IS NULL OR a.performed_at <= p_to)
         ORDER BY a.performed_at, a.seq;
END;
$$;
