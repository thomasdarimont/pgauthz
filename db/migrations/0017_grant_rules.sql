-- 0017_grant_rules.sql
--
-- Grant rules: the sharing policy as model data. A grant rule says "to grant
-- relation R on type T through authz.grant, the actor must be allowed
-- relation `requires` on the SAME object" (and `requires_revoke`, defaulting
-- to `requires`, for authz.revoke). Without a rule a relation cannot be
-- granted through that API at all — fail-closed by construction, where a
-- hand-written write_tuples_checked precondition could simply be forgotten.
--
-- History follows the gates precedent: an append-only audit table so
-- describe_model-as-of and "who could share on Tuesday" stay answerable.

CREATE TABLE authz.grant_rules (
    id              integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    store_id        integer NOT NULL REFERENCES authz.stores(id),
    object_type     integer NOT NULL,
    relation        integer NOT NULL,
    requires        integer NOT NULL,   -- relation the actor must be allowed on the object to GRANT
    requires_revoke integer,            -- … to REVOKE; NULL = same as requires
    UNIQUE (store_id, object_type, relation),
    -- Composite FKs: same-store references only (see authz.models).
    FOREIGN KEY (object_type,     store_id) REFERENCES authz.types     (id, store_id),
    FOREIGN KEY (relation,        store_id) REFERENCES authz.relations (id, store_id),
    FOREIGN KEY (requires,        store_id) REFERENCES authz.relations (id, store_id),
    FOREIGN KEY (requires_revoke, store_id) REFERENCES authz.relations (id, store_id)
);

CREATE TABLE authz.grant_rules_audit (
    seq             bigint      NOT NULL GENERATED ALWAYS AS IDENTITY,
    action          text        NOT NULL,   -- 'INSERT' or 'DELETE'
    performed_at    timestamptz NOT NULL DEFAULT now(),
    performed_by    text        NOT NULL DEFAULT current_user,
    grant_rule_id   integer     NOT NULL,   -- authz.grant_rules.id
    store_id        integer     NOT NULL,
    object_type     integer     NOT NULL,
    relation        integer     NOT NULL,
    requires        integer     NOT NULL,
    requires_revoke integer,
    PRIMARY KEY (seq)
);

CREATE INDEX idx_grant_rules_audit_replay
    ON authz.grant_rules_audit (grant_rule_id, performed_at DESC, seq DESC);
CREATE INDEX idx_grant_rules_audit_store
    ON authz.grant_rules_audit (store_id, performed_at);
