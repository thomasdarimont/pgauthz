-- 0024_store_deletions.sql
--
-- Receipts of physical store deletions: the deleted incarnation
-- (authz.stores.id), its name and the deletion time — the database clock,
-- read inside the store's lifecycle lock. delete_store writes one; the
-- decision log's purge consumes them (a purge of a deleted store names the
-- incarnation the engine certifies, never one read before the lock, and a
-- retry cannot fence a live store). Small and kept: one row per deletion.
CREATE TABLE IF NOT EXISTS authz.store_deletions (
    store_id   integer PRIMARY KEY,
    name       text NOT NULL,
    deleted_at timestamptz NOT NULL,
    deleted_by text
);
CREATE INDEX IF NOT EXISTS store_deletions_name ON authz.store_deletions (name, deleted_at DESC);
