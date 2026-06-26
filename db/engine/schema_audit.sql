-- Audit / time-travel schema: the immutable change logs and their triggers.
--
-- Split out of schema.sql so a READ-ONLY deployment (the substrate + read API,
-- e.g. an app database fed by replication — see db/replication/) can omit it:
-- the audit log lives centrally, and a read replica needs neither the audit
-- tables nor the write-side triggers. A full deployment loads this right after
-- schema.sql (the audited tables must already exist).
--
-- Depends on: schema.sql (authz.tuples, authz.models, authz.conditions, and the
-- lookup tables the views resolve against) and, at evaluation time only,
-- authz._effective_role() from core_internal.sql.

-- Audit log: records all tuple inserts and deletes.
-- Populated automatically by a trigger on authz.tuples.
-- Partitioned by RANGE on performed_at for efficient time-based queries
-- and easy retention management (DROP old partitions instead of DELETE).
CREATE TABLE authz.tuples_audit (
    id                uuid NOT NULL DEFAULT gen_random_uuid(),
    -- Monotonic event order. performed_at is the TRANSACTION timestamp
    -- (transaction_timestamp), so every change in one transaction shares
    -- one value — time-travel sees a transaction's effect atomically,
    -- never a partial mid-transaction state. seq then orders the events
    -- within that shared timestamp, so replay always applies the
    -- later-recorded event last (the last-event-wins tiebreaker).
    seq               bigint NOT NULL GENERATED ALWAYS AS IDENTITY,
    action            text NOT NULL,  -- 'INSERT' or 'DELETE'
    performed_at      timestamptz NOT NULL DEFAULT now(),
    performed_by      text NOT NULL DEFAULT current_user,
    store_id          smallint NOT NULL,
    user_type         smallint NOT NULL,
    user_id           text NOT NULL,
    user_relation     smallint,
    relation          smallint NOT NULL,
    object_type       smallint NOT NULL,
    object_id         text NOT NULL,
    condition_id      smallint,
    condition_context jsonb,
    PRIMARY KEY (id, performed_at)
) PARTITION BY RANGE (performed_at);

-- Default partition catches any rows not covered by explicit partitions.
CREATE TABLE authz.tuples_audit_default PARTITION OF authz.tuples_audit DEFAULT;

CREATE INDEX idx_tuples_audit_lookup
    ON authz.tuples_audit (store_id, object_type, object_id, user_type, user_id);

CREATE INDEX idx_tuples_audit_time
    ON authz.tuples_audit (performed_at);

-- Watch / changefeed cursor: (store_id, performed_at, seq) supports the
-- watch_changes scan `WHERE store_id = ? AND (performed_at, seq) > (?, ?)
-- ORDER BY performed_at, seq`, with partition pruning on performed_at.
CREATE INDEX idx_tuples_audit_watch
    ON authz.tuples_audit (store_id, performed_at, seq);

-- Replay index: matches the DISTINCT ON key of _build_audit_snapshot so
-- point-in-time reconstruction scans the events in order instead of
-- sorting the store's full audit history on every call.
CREATE INDEX idx_tuples_audit_replay
    ON authz.tuples_audit (store_id, user_type, user_id, COALESCE(user_relation, 0),
                           relation, object_type, object_id, performed_at DESC, seq DESC);

-- Trigger function: logs INSERT and DELETE on authz.tuples.
-- Reads the optional session variable 'authz.performed_by' to record
-- which application user triggered the change. Falls back to the
-- effective request role (authz._effective_role() — the SET ROLE
-- identity under PostgREST, or session_user for direct connections).
-- Set via: SELECT set_config('authz.performed_by', 'user@example.com', true);
-- The write_tuple/delete_tuple functions set this automatically when
-- a p_performed_by parameter is provided.
CREATE OR REPLACE FUNCTION authz._audit_tuple() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_row          authz.tuples;
    v_performed_by text;
BEGIN
    -- Read application user from session variable, fall back to DB role
    v_performed_by := COALESCE(
        NULLIF(current_setting('authz.performed_by', true), ''),
        authz._effective_role()
    );

    -- An UPDATE (condition change via write_tuple upsert) is recorded
    -- as DELETE(old) + INSERT(new) so time-travel replay (last event
    -- per tuple wins, ties broken by seq) reconstructs the right
    -- condition for any point in time.
    IF TG_OP = 'UPDATE' THEN
        INSERT INTO authz.tuples_audit (
            action, performed_at, performed_by, store_id, user_type, user_id, user_relation,
            relation, object_type, object_id, condition_id, condition_context
        ) VALUES
            ('DELETE', transaction_timestamp(), v_performed_by, OLD.store_id, OLD.user_type, OLD.user_id, OLD.user_relation,
             OLD.relation, OLD.object_type, OLD.object_id, OLD.condition_id, OLD.condition_context),
            ('INSERT', transaction_timestamp(), v_performed_by, NEW.store_id, NEW.user_type, NEW.user_id, NEW.user_relation,
             NEW.relation, NEW.object_type, NEW.object_id, NEW.condition_id, NEW.condition_context);
        -- Watch doorbell — deduplicated to one per store per transaction.
        PERFORM pg_notify('authz_changes', NEW.store_id::text);
        RETURN NEW;
    END IF;

    IF TG_OP = 'INSERT' THEN
        v_row := NEW;
    ELSIF TG_OP = 'DELETE' THEN
        v_row := OLD;
    ELSE
        RETURN NULL;
    END IF;

    INSERT INTO authz.tuples_audit (
        action, performed_at, performed_by, store_id, user_type, user_id, user_relation,
        relation, object_type, object_id, condition_id, condition_context
    ) VALUES (
        TG_OP, transaction_timestamp(), v_performed_by, v_row.store_id, v_row.user_type, v_row.user_id, v_row.user_relation,
        v_row.relation, v_row.object_type, v_row.object_id, v_row.condition_id, v_row.condition_context
    );

    -- Watch doorbell — deduplicated to one per store per transaction.
    PERFORM pg_notify('authz_changes', v_row.store_id::text);

    RETURN v_row;
END;
$$;

-- Attach trigger to tuples table (fires for all partitions).
CREATE TRIGGER trg_tuples_audit
    AFTER INSERT OR UPDATE OR DELETE ON authz.tuples
    FOR EACH ROW EXECUTE FUNCTION authz._audit_tuple();

-- The audit trail is append-only. UPDATE is never allowed; DELETE only
-- as part of sanctioned maintenance — partition row migration in
-- _ensure_audit_partition (rows are copied first, so data is preserved)
-- and explicit purge via delete_store(..., p_purge_audit => true) —
-- which set the transaction-local authz.audit_maintenance GUC around
-- their statements. Retention by DETACH/DROP of old partitions is DDL
-- and unaffected.
--
-- This guards against bugs in SECURITY DEFINER functions and careless
-- admin sessions; a superuser can always bypass triggers (e.g. via
-- session_replication_role — see docs/DEVELOPMENT.md).
CREATE OR REPLACE FUNCTION authz._audit_block_dml() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND current_setting('authz.audit_maintenance', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit log is append-only: % is not allowed', TG_OP;
END;
$$;

CREATE TRIGGER trg_tuples_audit_block_dml
    BEFORE UPDATE OR DELETE ON authz.tuples_audit
    FOR EACH ROW EXECUTE FUNCTION authz._audit_block_dml();

-- Human-readable view of the audit log (resolves integer IDs to names).
CREATE VIEW authz.tuples_audit_view AS
SELECT
    a.id,
    a.action,
    a.performed_at,
    a.performed_by,
    s.name  AS store,
    ut.name AS user_type,
    a.user_id,
    ur.name AS user_relation,
    r.name  AS relation,
    ot.name AS object_type,
    a.object_id,
    c.name  AS condition_name,
    a.condition_context
  FROM authz.tuples_audit a
  JOIN authz.stores s     ON s.id  = a.store_id
  JOIN authz.types ut     ON ut.id = a.user_type
  JOIN authz.relations r  ON r.id  = a.relation
  JOIN authz.types ot     ON ot.id = a.object_type
  LEFT JOIN authz.relations ur ON ur.id = a.user_relation
  LEFT JOIN authz.conditions c ON c.id  = a.condition_id;

-- Model change log: versions model rules so time-travel queries
-- (audit_check_access) resolve against the rule set as it was at a past
-- timestamp, not the current model. Mirrors tuples_audit: append-only,
-- one row per rule INSERT/DELETE (an UPDATE is split into DELETE+INSERT),
-- with a seq tiebreaker so replay applies the later event last. The model
-- is tiny and low-churn, so this table is not partitioned.
CREATE TABLE authz.models_audit (
    seq               bigint NOT NULL GENERATED ALWAYS AS IDENTITY,
    action            text NOT NULL,  -- 'INSERT' or 'DELETE'
    performed_at      timestamptz NOT NULL DEFAULT now(),
    performed_by      text NOT NULL DEFAULT current_user,
    model_id          smallint NOT NULL,  -- authz.models.id of the rule
    store_id          smallint NOT NULL,
    object_type       smallint NOT NULL,
    relation          smallint NOT NULL,
    rule_type         smallint NOT NULL,
    computed_relation smallint,
    tupleset_relation smallint,
    tupleset_computed smallint,
    group_id          smallint NOT NULL,
    group_op          smallint NOT NULL,
    negated           boolean  NOT NULL,
    allow_object_wildcard boolean NOT NULL,
    PRIMARY KEY (seq)
);

-- Replay index: matches the DISTINCT ON key of _build_model_snapshot (a
-- rule's business identity = the idx_models_unique columns) plus recency,
-- so point-in-time reconstruction scans in order instead of sorting the
-- store's full model history on every call.
CREATE INDEX idx_models_audit_replay
    ON authz.models_audit (
        store_id, object_type, relation, rule_type,
        COALESCE(computed_relation, -1),
        COALESCE(tupleset_relation, -1),
        COALESCE(tupleset_computed, -1),
        group_id, negated, performed_at DESC, seq DESC
    );

-- Trigger: log INSERT/DELETE on authz.models. An UPDATE (e.g. a group_op
-- change via upsert) is recorded as DELETE(old) + INSERT(new) so replay
-- (last event per rule wins, ties broken by seq) reconstructs the right
-- rule set for any point in time. Mirrors authz._audit_tuple.
CREATE OR REPLACE FUNCTION authz._audit_model() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_performed_by text;
BEGIN
    v_performed_by := COALESCE(
        NULLIF(current_setting('authz.performed_by', true), ''),
        authz._effective_role()
    );

    IF TG_OP = 'UPDATE' THEN
        INSERT INTO authz.models_audit (
            action, performed_at, performed_by, model_id, store_id, object_type, relation,
            rule_type, computed_relation, tupleset_relation, tupleset_computed,
            group_id, group_op, negated, allow_object_wildcard
        ) VALUES
            ('DELETE', transaction_timestamp(), v_performed_by, OLD.id, OLD.store_id, OLD.object_type, OLD.relation,
             OLD.rule_type, OLD.computed_relation, OLD.tupleset_relation, OLD.tupleset_computed,
             OLD.group_id, OLD.group_op, OLD.negated, OLD.allow_object_wildcard),
            ('INSERT', transaction_timestamp(), v_performed_by, NEW.id, NEW.store_id, NEW.object_type, NEW.relation,
             NEW.rule_type, NEW.computed_relation, NEW.tupleset_relation, NEW.tupleset_computed,
             NEW.group_id, NEW.group_op, NEW.negated, NEW.allow_object_wildcard);
        RETURN NEW;
    ELSIF TG_OP = 'INSERT' THEN
        INSERT INTO authz.models_audit (
            action, performed_at, performed_by, model_id, store_id, object_type, relation,
            rule_type, computed_relation, tupleset_relation, tupleset_computed,
            group_id, group_op, negated, allow_object_wildcard
        ) VALUES (
            'INSERT', transaction_timestamp(), v_performed_by, NEW.id, NEW.store_id, NEW.object_type, NEW.relation,
            NEW.rule_type, NEW.computed_relation, NEW.tupleset_relation, NEW.tupleset_computed,
            NEW.group_id, NEW.group_op, NEW.negated, NEW.allow_object_wildcard);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO authz.models_audit (
            action, performed_at, performed_by, model_id, store_id, object_type, relation,
            rule_type, computed_relation, tupleset_relation, tupleset_computed,
            group_id, group_op, negated, allow_object_wildcard
        ) VALUES (
            'DELETE', transaction_timestamp(), v_performed_by, OLD.id, OLD.store_id, OLD.object_type, OLD.relation,
            OLD.rule_type, OLD.computed_relation, OLD.tupleset_relation, OLD.tupleset_computed,
            OLD.group_id, OLD.group_op, OLD.negated, OLD.allow_object_wildcard);
        RETURN OLD;
    END IF;

    RETURN NULL;
END;
$$;

CREATE TRIGGER trg_models_audit
    AFTER INSERT OR UPDATE OR DELETE ON authz.models
    FOR EACH ROW EXECUTE FUNCTION authz._audit_model();

-- Same append-only protection as tuples_audit (DELETE only under the
-- authz.audit_maintenance maintenance window, used by delete_store purge).
CREATE TRIGGER trg_models_audit_block_dml
    BEFORE UPDATE OR DELETE ON authz.models_audit
    FOR EACH ROW EXECUTE FUNCTION authz._audit_block_dml();

-- Condition change log: versions condition expressions so time-travel
-- queries evaluate conditional grants against the expression that was in
-- effect at a past timestamp, not the current one. Mirrors models_audit:
-- append-only, one row per INSERT/DELETE (an UPDATE is split into
-- DELETE+INSERT), seq tiebreaker. A condition's replay identity is its
-- id — stable across in-place edits, and what tuples reference via
-- condition_id.
CREATE TABLE authz.conditions_audit (
    seq              bigint NOT NULL GENERATED ALWAYS AS IDENTITY,
    action           text NOT NULL,  -- 'INSERT' or 'DELETE'
    performed_at     timestamptz NOT NULL DEFAULT now(),
    performed_by     text NOT NULL DEFAULT current_user,
    condition_id     smallint NOT NULL,  -- authz.conditions.id
    store_id         smallint NOT NULL,
    name             text NOT NULL,
    expression       text NOT NULL,
    lang             text NOT NULL DEFAULT 'sql',  -- no CHECK: history records whatever was in effect
    required_context jsonb,
    PRIMARY KEY (seq)
);

-- Replay index: reconstruct a condition's expression as of a timestamp.
CREATE INDEX idx_conditions_audit_replay
    ON authz.conditions_audit (condition_id, performed_at DESC, seq DESC);

CREATE OR REPLACE FUNCTION authz._audit_condition() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_performed_by text;
BEGIN
    v_performed_by := COALESCE(
        NULLIF(current_setting('authz.performed_by', true), ''),
        authz._effective_role()
    );

    IF TG_OP = 'UPDATE' THEN
        INSERT INTO authz.conditions_audit (
            action, performed_at, performed_by, condition_id, store_id, name, expression, lang, required_context
        ) VALUES
            ('DELETE', transaction_timestamp(), v_performed_by, OLD.id, OLD.store_id, OLD.name, OLD.expression, OLD.lang, OLD.required_context),
            ('INSERT', transaction_timestamp(), v_performed_by, NEW.id, NEW.store_id, NEW.name, NEW.expression, NEW.lang, NEW.required_context);
        RETURN NEW;
    ELSIF TG_OP = 'INSERT' THEN
        INSERT INTO authz.conditions_audit (
            action, performed_at, performed_by, condition_id, store_id, name, expression, lang, required_context
        ) VALUES
            ('INSERT', transaction_timestamp(), v_performed_by, NEW.id, NEW.store_id, NEW.name, NEW.expression, NEW.lang, NEW.required_context);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO authz.conditions_audit (
            action, performed_at, performed_by, condition_id, store_id, name, expression, lang, required_context
        ) VALUES
            ('DELETE', transaction_timestamp(), v_performed_by, OLD.id, OLD.store_id, OLD.name, OLD.expression, OLD.lang, OLD.required_context);
        RETURN OLD;
    END IF;

    RETURN NULL;
END;
$$;

CREATE TRIGGER trg_conditions_audit
    AFTER INSERT OR UPDATE OR DELETE ON authz.conditions
    FOR EACH ROW EXECUTE FUNCTION authz._audit_condition();

CREATE TRIGGER trg_conditions_audit_block_dml
    BEFORE UPDATE OR DELETE ON authz.conditions_audit
    FOR EACH ROW EXECUTE FUNCTION authz._audit_block_dml();
