-- 0028: store groups (ADR 0017) — a named set of stores that shares
-- administration, trust and models. Phase 1: the object and membership.
--
-- A store may belong to one group or to none (an ungrouped store is its own
-- group of one). The platform-owned `default` group holds every store that
-- exists at migration time; the console places new stores there unless told
-- otherwise. Group names follow the store-name rule.

CREATE TABLE authz.store_groups (
    id          integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name        text UNIQUE NOT NULL
                CHECK (name ~ '^[a-zA-Z_][a-zA-Z0-9_]*$' AND length(name) <= 63),
    description text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text NOT NULL DEFAULT current_user,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text NOT NULL DEFAULT current_user
);

ALTER TABLE authz.stores ADD COLUMN group_id integer REFERENCES authz.store_groups (id);
CREATE INDEX stores_group_id_idx ON authz.stores (group_id);

-- Every change to a group or a membership, by whom: a tenant's shape is an
-- administrative fact worth a trail (the engine functions write it).
CREATE TABLE authz.store_group_audit (
    seq          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action       text NOT NULL CHECK (action IN ('CREATE', 'UPDATE', 'DELETE', 'ATTACH', 'DETACH')),
    performed_at timestamptz NOT NULL DEFAULT now(),
    performed_by text NOT NULL,
    group_name   text NOT NULL,
    store        text,                      -- ATTACH / DETACH: the store that moved
    description  text                       -- CREATE / UPDATE: the description written
);
CREATE INDEX store_group_audit_group_idx ON authz.store_group_audit (group_name, seq DESC);

INSERT INTO authz.store_groups (name, description, created_by, updated_by)
VALUES ('default', 'The platform''s own group: every store not placed elsewhere', 'migration', 'migration');

UPDATE authz.stores SET group_id = (SELECT id FROM authz.store_groups WHERE name = 'default');
