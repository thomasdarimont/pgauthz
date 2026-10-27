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
-- The shape grew in 0029 (group issuers): CREATE OR REPLACE cannot change
-- a function's columns, so the old shape is dropped first. A group row's
-- `stores` are the group's member stores as they are now (plain names), so
-- pgauthzd needs no second lookup; `store_group` says it is a group row.
DROP FUNCTION IF EXISTS authz.list_issuer_bindings();
-- resolve_issuer: an issuer reference — the full `iss` URL, or a binding
-- row's alias (migration 0031, case-insensitive) — to the URL; NULL when an
-- alias names nothing. Everything that takes an issuer accepts both.
CREATE OR REPLACE FUNCTION authz.resolve_issuer(p_ref text)
RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT CASE
        WHEN p_ref IS NULL OR btrim(p_ref) = '' THEN NULL
        WHEN btrim(p_ref) ~ '^https?://' THEN btrim(p_ref)
        ELSE (SELECT b.issuer FROM authz.issuer_bindings b WHERE b.alias = lower(btrim(p_ref)))
    END;
$$;

-- the return shape gained `alias` (0031): drop the old one so a reload
-- replaces it instead of failing on the changed record type
DROP FUNCTION IF EXISTS authz.list_issuer_bindings();
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
    updated_by      text,
    store_group     text,
    jwks_url        text,
    audience        text,
    audiences       text[],
    admin           jsonb,
    alias           text
)
LANGUAGE sql STABLE AS $$
    SELECT b.issuer,
           CASE WHEN b.store_group IS NULL THEN b.stores
                ELSE COALESCE((SELECT array_agg(s.name ORDER BY s.name) FROM authz.stores s JOIN authz.store_groups g ON g.id = s.group_id WHERE g.name = b.store_group), '{}') END,
           b.db_roles, b.client_db_roles, b.pep_clients, b.enabled, b.description, b.created_at, b.created_by, b.updated_at, b.updated_by,
           b.store_group, b.jwks_url, b.audience, b.audiences, b.admin, b.alias
      FROM authz.issuer_bindings b
     ORDER BY b.issuer;
$$;

-- list_issuer_bindings_audit: the change history, newest first; keyset
-- paged — p_before_seq continues below the last seq of the previous page.
-- p_store_groups narrows to the rows written while the issuer belonged to
-- one of those groups (a group's admins read their group's history, never
-- what another group did with the issuer before a transfer).
DROP FUNCTION IF EXISTS authz.list_issuer_bindings_audit(text, int, bigint);
CREATE OR REPLACE FUNCTION authz.list_issuer_bindings_audit(
    p_issuer       text   DEFAULT NULL,
    p_limit        int    DEFAULT 200,
    p_before_seq   bigint DEFAULT NULL,
    p_store_groups text[] DEFAULT NULL
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
    description     text,
    store_group     text
)
LANGUAGE sql STABLE AS $$
    SELECT seq, action, performed_at, performed_by, issuer, stores, db_roles, client_db_roles, pep_clients, enabled, description, store_group
      FROM authz.issuer_bindings_audit
     WHERE (p_issuer IS NULL OR issuer = COALESCE(authz.resolve_issuer(p_issuer), p_issuer))
       AND (p_store_groups IS NULL OR store_group = ANY(p_store_groups))
       AND (p_before_seq IS NULL OR seq < p_before_seq)
     ORDER BY seq DESC
     LIMIT p_limit;
$$;

-- count_issuer_bindings_audit: how many history rows (for a pager).
DROP FUNCTION IF EXISTS authz.count_issuer_bindings_audit(text);
CREATE OR REPLACE FUNCTION authz.count_issuer_bindings_audit(p_issuer text DEFAULT NULL, p_store_groups text[] DEFAULT NULL)
RETURNS bigint
LANGUAGE sql STABLE AS $$
    SELECT count(*) FROM authz.issuer_bindings_audit
     WHERE (p_issuer IS NULL OR issuer = COALESCE(authz.resolve_issuer(p_issuer), p_issuer))
       AND (p_store_groups IS NULL OR store_group = ANY(p_store_groups));
$$;
