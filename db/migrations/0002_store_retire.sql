-- 0002_store_retire.sql
--
-- Soft-delete / retire support for stores (audit-retention governance).
--
-- delete_store physically removes a store's dictionary rows
-- (stores/types/relations), so even when its audit history is *preserved*
-- those rows reference IDs that are no longer resolvable by name — the
-- audit_* time-travel API (which starts by resolving names) can no longer
-- query the preserved history.
--
-- retire_store (added in db/engine/store.sql) instead drops only the live
-- tuple data and marks the store with deleted_at, keeping the full
-- dictionary and audit log intact. The name→id resolver authz._s() filters
-- to live stores by default (so every live API rejects a retired store),
-- while the audit_* functions opt into resolving retired stores so their
-- preserved history stays queryable by name.
--
-- Structure only (a column); the behavior lives in idempotent engine code.
-- stores.name stays globally UNIQUE: a retired name remains reserved, so
-- there is never any by-name ambiguity between a retired store and a new one.

ALTER TABLE authz.stores ADD COLUMN deleted_at timestamptz;

COMMENT ON COLUMN authz.stores.deleted_at IS
    'When set, the store is retired: live APIs reject it (authz._s resolves '
    'live-only) but its dictionary + audit history are preserved so the '
    'audit_* functions can still resolve it by name. NULL = active.';
