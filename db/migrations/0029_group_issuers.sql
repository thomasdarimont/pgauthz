-- 0029: group issuers (ADR 0017, phase 2). An issuer binding row may name a
-- store group instead of store patterns — its tokens then reach the group's
-- stores, as they are at any moment — and may carry its own trust anchor
-- (jwks_url, audiences): the group's admins add their tenant's identity
-- provider from the console, bounded by the group. Such a row may also carry
-- admin rules, but only delegated ones (decide): the row grants trust, the
-- console store decides what its people and pipelines may manage.
ALTER TABLE authz.issuer_bindings
    ADD COLUMN store_group text REFERENCES authz.store_groups (name) ON UPDATE CASCADE,
    ADD COLUMN jwks_url    text,
    ADD COLUMN audience    text,
    ADD COLUMN audiences   text[] NOT NULL DEFAULT '{}',
    ADD COLUMN admin       jsonb  NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(admin) = 'array');
CREATE INDEX issuer_bindings_group_idx ON authz.issuer_bindings (store_group);

ALTER TABLE authz.issuer_bindings_audit
    ADD COLUMN store_group text,
    ADD COLUMN jwks_url    text,
    ADD COLUMN audience    text,
    ADD COLUMN audiences   text[],
    ADD COLUMN admin       jsonb;
