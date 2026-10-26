-- 0030: model ownership and sharing between store groups (ADR 0017, phase 3).
--
-- A registry model (every version of a name) belongs to the group whose
-- store published it — or to that store itself when it is ungrouped, its own
-- group of one. A store may apply its own group's models and the platform's
-- (the default group's: the platform models of today); another group's only
-- with a relationship the owner grants: group:A model_consumer group:B.
CREATE TABLE authz.model_owners (
    name        text PRIMARY KEY,
    owner_group text REFERENCES authz.store_groups (name) ON UPDATE CASCADE,
    owner_store text,
    CHECK (num_nonnulls(owner_group, owner_store) <= 1),
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text NOT NULL DEFAULT current_user,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text NOT NULL DEFAULT current_user
);
-- every model known so far is the platform's
INSERT INTO authz.model_owners (name, owner_group, created_by, updated_by)
SELECT DISTINCT name, 'default', 'migration', 'migration' FROM authz.model_registry;

CREATE TABLE authz.store_group_relations (
    from_group  text NOT NULL REFERENCES authz.store_groups (name) ON UPDATE CASCADE ON DELETE CASCADE,
    to_group    text NOT NULL REFERENCES authz.store_groups (name) ON UPDATE CASCADE ON DELETE CASCADE,
    relation    text NOT NULL CHECK (relation IN ('model_consumer')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text NOT NULL DEFAULT current_user,
    PRIMARY KEY (from_group, to_group, relation),
    CHECK (from_group <> to_group)
);

-- the group audit records relationships too
ALTER TABLE authz.store_group_audit DROP CONSTRAINT store_group_audit_action_check;
ALTER TABLE authz.store_group_audit ADD CONSTRAINT store_group_audit_action_check
    CHECK (action IN ('CREATE', 'UPDATE', 'DELETE', 'ATTACH', 'DETACH', 'RELATE', 'UNRELATE', 'OWN'));
