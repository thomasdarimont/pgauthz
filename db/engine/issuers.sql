-- Issuer bindings, the read side (ADR 0016 / scratch/notes/issuer-management.md):
-- what pgauthzd polls to merge the database's bindings over its environment's
-- trusted issuers. SECURITY DEFINER, reader tier: the content is policy, not
-- secret (patterns, client ids, role names — never keys).
--
-- Depends on: migration 0023 (authz.issuer_bindings*).

-- issuer_bindings_revision: the current revision — a cheap poll; a change
-- bumps it (and notifies the channel authz_issuer_bindings).
CREATE OR REPLACE FUNCTION authz.issuer_bindings_revision()
RETURNS bigint
LANGUAGE sql STABLE AS $$
    SELECT revision FROM authz.issuer_bindings_revision;
$$;

-- list_issuer_bindings: every binding row, as pgauthzd and the console read
-- them (the console joins them with the instance's effective issuer set).
CREATE OR REPLACE FUNCTION authz.list_issuer_bindings()
RETURNS TABLE (
    issuer          text,
    stores          text[],
    db_roles        text[],
    client_db_roles jsonb,
    pep_clients     jsonb,
    enabled         boolean,
    description     text,
    created_at      timestamptz,
    created_by      text,
    updated_at      timestamptz,
    updated_by      text
)
LANGUAGE sql STABLE AS $$
    SELECT issuer, stores, db_roles, client_db_roles, pep_clients, enabled, description, created_at, created_by, updated_at, updated_by
      FROM authz.issuer_bindings
     ORDER BY issuer;
$$;

-- list_issuer_bindings_audit: the change history, newest first.
CREATE OR REPLACE FUNCTION authz.list_issuer_bindings_audit(
    p_issuer text DEFAULT NULL,
    p_limit  int  DEFAULT 200
)
RETURNS TABLE (
    seq             bigint,
    action          text,
    performed_at    timestamptz,
    performed_by    text,
    issuer          text,
    stores          text[],
    db_roles        text[],
    client_db_roles jsonb,
    pep_clients     jsonb,
    enabled         boolean,
    description     text
)
LANGUAGE sql STABLE AS $$
    SELECT seq, action, performed_at, performed_by, issuer, stores, db_roles, client_db_roles, pep_clients, enabled, description
      FROM authz.issuer_bindings_audit
     WHERE p_issuer IS NULL OR issuer = p_issuer
     ORDER BY seq DESC
     LIMIT p_limit;
$$;
