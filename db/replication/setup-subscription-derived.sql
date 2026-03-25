-- Creates a subscription on the derived app database.
-- Only subscribes to the materialized_permissions table — no authz
-- schema, functions, or model knowledge needed.

CREATE SUBSCRIPTION sub_authz_derived
    CONNECTION 'host=authz-primary port=5432 user=replicator password=replicator dbname=authz'
    PUBLICATION authz_derived
    WITH (copy_data = true);
