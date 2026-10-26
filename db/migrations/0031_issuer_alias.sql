-- 0031: issuer aliases. An issuer is referenced by its full `iss` URL
-- everywhere — admin API queries, pgauthzctl, console deep links. A binding
-- row may carry a short alias (lowercase, [a-z0-9_-], unique) that stands
-- for the URL wherever an issuer is referenced (authz.resolve_issuer).
ALTER TABLE authz.issuer_bindings
    ADD COLUMN alias text CHECK (alias ~ '^[a-z0-9][a-z0-9_-]{0,63}$');
CREATE UNIQUE INDEX issuer_bindings_alias_idx ON authz.issuer_bindings (alias);

ALTER TABLE authz.issuer_bindings_audit
    ADD COLUMN alias text;
