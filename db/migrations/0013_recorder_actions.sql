-- 0013_recorder_actions.sql
--
-- Per-recorder action allowlists for the action log (ADR 0012).
--
-- Mirrors authz.namespace_access: maps a PostgreSQL role to the actions it
-- may record in a store. Semantics follow the namespace precedent — a role
-- with NO rows in a store is unrestricted (backward compatible; the recorder
-- is trusted for its assertions as a tuple writer is for its tuples); once
-- any rows exist for a role the caller is a member of, it may record ONLY the
-- listed actions. Enforced by authz.record_event via the effective role, so
-- reserve_event and the HTTP endpoints inherit it. Managed with
-- authz.grant_recorder_actions / revoke_recorder_actions (admin). Deployment-
-- specific like namespace grants: excluded from export_model.
CREATE TABLE authz.recorder_actions (
    store_id    integer NOT NULL REFERENCES authz.stores(id),
    db_role     text    NOT NULL,
    action      integer NOT NULL,
    PRIMARY KEY (store_id, db_role, action),
    -- Composite FK: same-store references only (see authz.models).
    FOREIGN KEY (action, store_id) REFERENCES authz.relations (id, store_id)
);
