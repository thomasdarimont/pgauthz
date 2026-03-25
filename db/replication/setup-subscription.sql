-- Creates subscriptions on the accounting app database.
-- Connects to the primary and subscribes to the metadata + accounting publications.
--
-- copy_data = true (default): existing data is copied during initial sync.

CREATE SUBSCRIPTION sub_authz_metadata
    CONNECTION 'host=authz-primary port=5432 user=replicator password=replicator dbname=authz'
    PUBLICATION authz_metadata
    WITH (copy_data = true);

CREATE SUBSCRIPTION sub_authz_accounting
    CONNECTION 'host=authz-primary port=5432 user=replicator password=replicator dbname=authz'
    PUBLICATION authz_accounting
    WITH (copy_data = true);
