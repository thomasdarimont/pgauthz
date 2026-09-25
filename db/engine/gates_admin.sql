-- Temporal gates (ADR 0012, phase 2) — the WRITE side: add_gate / drop_gate
-- and the write-time validation trigger that normalizes a spec before it is
-- stored. Part of the WRITE profile (gates arrive on a read-only install via
-- replication, already validated upstream). Gate history (the audit trigger
-- and snapshot builder) is audit-profile code.
--
-- Depends on: gates.sql (_event_validate_gate_spec), core_internal.sql
-- (_s/_t/_r), migration 0011 (authz.model_gates).

-- Validate + normalize on every write, whatever path inserts the row. The
-- normalized spec carries the derived required_context the tri-state
-- classifier reads. SECURITY DEFINER so the validator's relation lookup
-- works for whoever runs the INSERT.
CREATE OR REPLACE FUNCTION authz._validate_gate_spec() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    BEGIN
        NEW.spec := authz._event_validate_gate_spec(NEW.store_id, NEW.spec);
    EXCEPTION WHEN check_violation THEN
        RAISE EXCEPTION 'gate "%": %', NEW.name, SQLERRM USING ERRCODE = 'check_violation';
    END;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_model_gates_validate
    BEFORE INSERT OR UPDATE ON authz.model_gates
    FOR EACH ROW EXECUTE FUNCTION authz._validate_gate_spec();

------------------------------------------------------------------------
-- add_gate: create or replace a named gate on (object_type, relation).
-- Upsert like create_condition: an actual change is versioned in
-- model_gates_audit; an identical re-run (same normalized spec) is a no-op
-- so it does not pollute the time-travel history. Returns the gate id.
--
--   SELECT authz.add_gate('bank', 'account', 'transfer', 'velocity_backstop', '{
--       "description": "transfer velocity backstop",
--       "all_of": [{"count_within": {"window": "1h", "max": 5}},
--                  {"sum_within":   {"window": "1h", "kind": "response", "field": "input.amount",
--                                    "plus": "$request.input.amount", "max": 5000}}]}');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.add_gate(
    p_store       text,
    p_object_type text,
    p_relation    text,
    p_name        text,
    p_spec        jsonb
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id    integer := authz._s(p_store);
    v_object_type integer := authz._t(v_store_id, p_object_type);
    v_relation    integer := authz._r(v_store_id, p_relation);
    v_spec        jsonb;
    v_id          integer;
BEGIN
    IF p_name IS NULL OR p_name !~ '^[A-Za-z_][A-Za-z0-9_]*$' OR length(p_name) > 63 THEN
        RAISE EXCEPTION 'gate name "%" must be an identifier (letters, digits, underscore; max 63)', p_name
            USING ERRCODE = 'check_violation';
    END IF;
    -- Normalize up front so the no-op comparison below sees the stored shape.
    v_spec := authz._event_validate_gate_spec(v_store_id, p_spec);

    INSERT INTO authz.model_gates (store_id, object_type, relation, name, spec)
    VALUES (v_store_id, v_object_type, v_relation, p_name, v_spec)
    ON CONFLICT (store_id, object_type, relation, name) DO UPDATE
        SET spec = EXCLUDED.spec
        WHERE authz.model_gates.spec IS DISTINCT FROM EXCLUDED.spec
    RETURNING id INTO v_id;

    IF v_id IS NULL THEN
        SELECT g.id INTO v_id FROM authz.model_gates g
         WHERE g.store_id = v_store_id AND g.object_type = v_object_type
           AND g.relation = v_relation AND g.name = p_name;
    END IF;
    RETURN v_id;
END;
$$;

------------------------------------------------------------------------
-- drop_gate: remove a gate. Returns true when a row was deleted. Dropping
-- a gate can only widen access (gates are veto-only), which is why it is
-- admin-only like every model change.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.drop_gate(
    p_store       text,
    p_object_type text,
    p_relation    text,
    p_name        text
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id integer := authz._s(p_store);
    v_count    int;
BEGIN
    DELETE FROM authz.model_gates g
     WHERE g.store_id    = v_store_id
       AND g.object_type = authz._t(v_store_id, p_object_type)
       AND g.relation    = authz._r(v_store_id, p_relation)
       AND g.name        = p_name;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count > 0;
END;
$$;
