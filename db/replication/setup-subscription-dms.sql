-- Creates a subscription on an application database that wants the derived
-- permissions of ITS object types only: publication authz_derived_dms is
-- row-filtered to namespace 'dms' (setup-publication.sql). Same minimal
-- schema (schema-derived.sql); check_permission() and permissions_fresh()
-- work unchanged — there are simply no rows for the other object types.

CREATE SUBSCRIPTION sub_authz_derived_dms
    CONNECTION 'host=authz-primary port=5432 user=replicator password=replicator dbname=authz'
    PUBLICATION authz_derived_dms
    WITH (copy_data = true);
