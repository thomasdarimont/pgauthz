-- Creates subscriptions on the accounting app database.
-- Connects to the primary and subscribes to the metadata + accounting publications.

-- Metadata: the subscriber has ALREADY loaded the demo model locally (model.sql,
-- run before this) to create the tuple partitions with IDs matching the primary.
-- That model load populates stores/types/relations/models, so an initial COPY
-- here would hit duplicate-key conflicts (the tablesync workers crash-loop and
-- exhaust replication worker slots). Use copy_data = false: skip the initial
-- copy — the metadata is already present and identical — and only stream future
-- model changes from the primary.
CREATE SUBSCRIPTION sub_authz_metadata
    CONNECTION 'host=authz-primary port=5432 user=replicator password=replicator dbname=authz'
    PUBLICATION authz_metadata
    WITH (copy_data = false);

-- Tuples: the subscriber has the (empty) partitions but no tuple data, so copy
-- the existing accounting-relevant tuples during initial sync.
CREATE SUBSCRIPTION sub_authz_accounting
    CONNECTION 'host=authz-primary port=5432 user=replicator password=replicator dbname=authz'
    PUBLICATION authz_accounting
    WITH (copy_data = true);
