-- Audit code: the trigger functions, triggers, and view for the change logs.
--
-- Idempotent (CREATE OR REPLACE everything, incl. triggers — PostgreSQL 14+) so
-- it can be re-applied on every deploy. Part of the AUDIT profile; loaded after
-- schema_audit.sql (the audit tables) and after schema.sql (the audited tables
-- authz.tuples / authz.models / authz.conditions, which these triggers attach to).
--
-- Depends on: schema.sql (audited tables + lookup tables for the view),
-- schema_audit.sql (audit tables), core_internal.sql (authz._effective_role).

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
            relation, object_type, object_id, condition_id, condition_context, expires_at
        ) VALUES
            ('DELETE', transaction_timestamp(), v_performed_by, OLD.store_id, OLD.user_type, OLD.user_id, OLD.user_relation,
             OLD.relation, OLD.object_type, OLD.object_id, OLD.condition_id, OLD.condition_context, OLD.expires_at),
            ('INSERT', transaction_timestamp(), v_performed_by, NEW.store_id, NEW.user_type, NEW.user_id, NEW.user_relation,
             NEW.relation, NEW.object_type, NEW.object_id, NEW.condition_id, NEW.condition_context, NEW.expires_at);
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
        relation, object_type, object_id, condition_id, condition_context, expires_at
    ) VALUES (
        TG_OP, transaction_timestamp(), v_performed_by, v_row.store_id, v_row.user_type, v_row.user_id, v_row.user_relation,
        v_row.relation, v_row.object_type, v_row.object_id, v_row.condition_id, v_row.condition_context, v_row.expires_at
    );

    -- Watch doorbell — deduplicated to one per store per transaction.
    PERFORM pg_notify('authz_changes', v_row.store_id::text);

    RETURN v_row;
END;
$$;

-- Attach trigger to tuples table (fires for all partitions).
CREATE OR REPLACE TRIGGER trg_tuples_audit
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

CREATE OR REPLACE TRIGGER trg_tuples_audit_block_dml
    BEFORE UPDATE OR DELETE ON authz.tuples_audit
    FOR EACH ROW EXECUTE FUNCTION authz._audit_block_dml();

-- Human-readable view of the audit log (resolves integer IDs to names).
CREATE OR REPLACE VIEW authz.tuples_audit_view AS
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

CREATE OR REPLACE TRIGGER trg_models_audit
    AFTER INSERT OR UPDATE OR DELETE ON authz.models
    FOR EACH ROW EXECUTE FUNCTION authz._audit_model();

-- Same append-only protection as tuples_audit (DELETE only under the
-- authz.audit_maintenance maintenance window, used by delete_store purge).
CREATE OR REPLACE TRIGGER trg_models_audit_block_dml
    BEFORE UPDATE OR DELETE ON authz.models_audit
    FOR EACH ROW EXECUTE FUNCTION authz._audit_block_dml();

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

CREATE OR REPLACE TRIGGER trg_conditions_audit
    AFTER INSERT OR UPDATE OR DELETE ON authz.conditions
    FOR EACH ROW EXECUTE FUNCTION authz._audit_condition();

CREATE OR REPLACE TRIGGER trg_conditions_audit_block_dml
    BEFORE UPDATE OR DELETE ON authz.conditions_audit
    FOR EACH ROW EXECUTE FUNCTION authz._audit_block_dml();
