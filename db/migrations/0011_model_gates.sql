-- 0011_model_gates.sql
--
-- Temporal gates (ADR 0012, phase 2): declarative, history-dependent clauses
-- attached to an (object_type, relation) and evaluated by engine code AFTER
-- the graph allows — "at most 5 transfers per hour", "only if an approver
-- approved this stock within the hour" — over the action log (authz.events,
-- migration 0010). Any failing clause denies.
--
-- authz.models is relational (rule_type/group_op ints) and cannot carry a
-- clause spec, so gates get their own table with a jsonb spec (the grammar is
-- validated and normalized at write time by authz._event_validate_gate_spec;
-- the normalized spec carries a derived required_context like conditions do).
-- Gate history follows the conditions precedent (conditions_audit): an
-- append-only audit table + replay index, so time-travel resolves the gate
-- definitions as of p_at.
CREATE TABLE authz.model_gates (
    id           integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    store_id     integer NOT NULL REFERENCES authz.stores(id),
    object_type  integer NOT NULL,
    relation     integer NOT NULL,
    name         text    NOT NULL,
    spec         jsonb   NOT NULL,
    UNIQUE (store_id, object_type, relation, name),   -- also the evaluator's lookup index
    -- Composite FKs: same-store references only (see authz.models).
    FOREIGN KEY (object_type, store_id) REFERENCES authz.types     (id, store_id),
    FOREIGN KEY (relation,    store_id) REFERENCES authz.relations (id, store_id)
);

CREATE TABLE authz.model_gates_audit (
    seq          bigint      NOT NULL GENERATED ALWAYS AS IDENTITY,
    action       text        NOT NULL,   -- 'INSERT' or 'DELETE'
    performed_at timestamptz NOT NULL DEFAULT now(),
    performed_by text        NOT NULL DEFAULT current_user,
    gate_id      integer     NOT NULL,   -- authz.model_gates.id
    store_id     integer     NOT NULL,
    object_type  integer     NOT NULL,
    relation     integer     NOT NULL,
    name         text        NOT NULL,
    spec         jsonb       NOT NULL,   -- no validation: history records whatever was in effect
    PRIMARY KEY (seq)
);

-- Replay index: reconstruct a gate's spec as of a timestamp.
CREATE INDEX idx_model_gates_audit_replay
    ON authz.model_gates_audit (gate_id, performed_at DESC, seq DESC);
