-- Issuer bindings, the write side (scratch/notes/issuer-management.md):
-- validation, upsert and delete, the audit trigger and the revision bump
-- pgauthzd instances pick up. Admin tier: changing what an issuer's tokens
-- may do is the console's most consequential write (disable the wrong
-- issuer and every application of that identity provider stops), so the
-- functions are SECURITY DEFINER for authz_admin and every change is
-- recorded with the actor.
--
-- Depends on: migration 0023, engine/issuers.sql.

------------------------------------------------------------------------
-- _issuer_bindings_changed: AFTER trigger — audit row + revision bump +
-- NOTIFY, for the functions below and for any direct edit alike.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._issuer_bindings_changed()
RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_by  text := COALESCE(NULLIF(current_setting('authz.performed_by', true), ''), current_user);
    v_rev bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN
        INSERT INTO authz.issuer_bindings_audit (action, performed_by, issuer, stores, db_roles, client_db_roles, pep_clients, enabled, description,
                                                 store_group, jwks_url, audience, audiences, admin, alias)
        VALUES ('DELETE', v_by, OLD.issuer, OLD.stores, OLD.db_roles, OLD.client_db_roles, OLD.pep_clients, OLD.enabled, OLD.description,
                OLD.store_group, OLD.jwks_url, OLD.audience, OLD.audiences, OLD.admin, OLD.alias);
    ELSE
        INSERT INTO authz.issuer_bindings_audit (action, performed_by, issuer, stores, db_roles, client_db_roles, pep_clients, enabled, description,
                                                 store_group, jwks_url, audience, audiences, admin, alias)
        VALUES (TG_OP, v_by, NEW.issuer, NEW.stores, NEW.db_roles, NEW.client_db_roles, NEW.pep_clients, NEW.enabled, NEW.description,
                NEW.store_group, NEW.jwks_url, NEW.audience, NEW.audiences, NEW.admin, NEW.alias);
    END IF;
    UPDATE authz.issuer_bindings_revision SET revision = revision + 1, changed_at = now() RETURNING revision INTO v_rev;
    PERFORM pg_notify('authz_issuer_bindings', v_rev::text);
    RETURN NULL;
END;
$$;

CREATE OR REPLACE TRIGGER issuer_bindings_changed
    AFTER INSERT OR UPDATE OR DELETE ON authz.issuer_bindings
    FOR EACH ROW EXECUTE FUNCTION authz._issuer_bindings_changed();

------------------------------------------------------------------------
-- _validate_issuer_binding: the shape rules pgauthzd applies at load,
-- applied at write time so a bad row never reaches an instance: anchored
-- patterns compile; client_db_roles is {client: role}; pep_clients is
-- {client: [pattern, ...]} with non-empty lists whose patterns are covered
-- by the stores binding when one exists (a plain name matched by a stores
-- pattern, or the same pattern) — assertion cannot widen where tokens may
-- ask (ADR 0014).
------------------------------------------------------------------------
DROP FUNCTION IF EXISTS authz._validate_issuer_binding(text[], text[], jsonb, jsonb);
CREATE OR REPLACE FUNCTION authz._validate_issuer_binding(
    p_stores          text[],
    p_db_roles        text[],
    p_client_db_roles jsonb,
    p_pep_clients     jsonb,
    p_store_group     text  DEFAULT NULL,
    p_jwks_url        text  DEFAULT NULL,
    p_audience        text  DEFAULT NULL,
    p_audiences       text[] DEFAULT '{}',
    p_admin           jsonb DEFAULT '[]'::jsonb
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_pat     text;
    v_client  text;
    v_value   jsonb;
    v_covered boolean;
    v_sp      text;
    v_rule    jsonb;
BEGIN
    -- group issuers (ADR 0017): the group decides the stores; a trust anchor
    -- is only ever a group's (platform issuers stay in the environment) and
    -- needs an audience; admin rules on a row delegate only.
    IF p_store_group IS NOT NULL THEN
        PERFORM authz._sg(p_store_group);
        IF COALESCE(array_length(p_stores, 1), 0) > 0 THEN
            RAISE EXCEPTION 'a group issuer binds the group''s stores: stores must be empty when store_group is set' USING ERRCODE = 'invalid_parameter_value';
        END IF;
    END IF;
    IF p_jwks_url IS NOT NULL THEN
        IF p_store_group IS NULL THEN
            RAISE EXCEPTION 'a trust anchor (jwks_url) needs a store group: platform issuers are configured in the environment (JWT_ISSUERS)' USING ERRCODE = 'invalid_parameter_value';
        END IF;
        IF p_jwks_url !~ '^https://' THEN
            RAISE EXCEPTION 'jwks_url must be an https:// URL' USING ERRCODE = 'invalid_parameter_value';
        END IF;
        IF NULLIF(btrim(COALESCE(p_audience, '')), '') IS NULL AND COALESCE(array_length(p_audiences, 1), 0) = 0 THEN
            RAISE EXCEPTION 'a trust anchor needs an audience (audience or audiences): without one, tokens the provider mints for any other API would be accepted' USING ERRCODE = 'invalid_parameter_value';
        END IF;
    END IF;
    IF p_admin IS NULL OR jsonb_typeof(p_admin) <> 'array' THEN
        RAISE EXCEPTION 'admin must be a JSON array of rules' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOR v_rule IN SELECT jsonb_array_elements(p_admin) LOOP
        IF jsonb_typeof(v_rule) <> 'object' OR jsonb_typeof(v_rule -> 'decide') <> 'object' OR NULLIF(v_rule #>> '{decide,store}', '') IS NULL THEN
            RAISE EXCEPTION 'admin rules of a database row delegate only: each rule needs {"decide": {"store": …}}' USING ERRCODE = 'invalid_parameter_value';
        END IF;
        IF v_rule ? 'capabilities' OR v_rule ? 'stores' OR (v_rule ->> 'scope') = 'platform' THEN
            RAISE EXCEPTION 'admin rules of a database row take no capabilities, stores or platform scope: the deciding store grants what the credential may manage' USING ERRCODE = 'invalid_parameter_value';
        END IF;
    END LOOP;
    FOREACH v_pat IN ARRAY COALESCE(p_stores, '{}') LOOP
        IF v_pat = '' THEN RAISE EXCEPTION 'stores: empty pattern' USING ERRCODE = 'invalid_parameter_value'; END IF;
        PERFORM regexp_match('', '^(?:' || v_pat || ')$');   -- compiles, or raises
    END LOOP;
    FOREACH v_pat IN ARRAY COALESCE(p_db_roles, '{}') LOOP
        IF v_pat = '' THEN RAISE EXCEPTION 'db_roles: empty pattern' USING ERRCODE = 'invalid_parameter_value'; END IF;
        PERFORM regexp_match('', '^(?:' || v_pat || ')$');
    END LOOP;
    IF p_client_db_roles IS NULL OR jsonb_typeof(p_client_db_roles) <> 'object' THEN
        RAISE EXCEPTION 'client_db_roles must be an object {client id: db role}' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOR v_client, v_value IN SELECT * FROM jsonb_each(p_client_db_roles) LOOP
        IF v_client = '' OR jsonb_typeof(v_value) <> 'string' OR (v_value #>> '{}') = '' THEN
            RAISE EXCEPTION 'client_db_roles[%]: a non-empty client id and a role name are required', v_client USING ERRCODE = 'invalid_parameter_value';
        END IF;
    END LOOP;
    IF p_pep_clients IS NULL OR jsonb_typeof(p_pep_clients) <> 'object' THEN
        RAISE EXCEPTION 'pep_clients must be an object {client id: [store pattern, ...]}' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOR v_client, v_value IN SELECT * FROM jsonb_each(p_pep_clients) LOOP
        IF v_client = '' THEN
            RAISE EXCEPTION 'pep_clients has an empty client id' USING ERRCODE = 'invalid_parameter_value';
        END IF;
        IF jsonb_typeof(v_value) <> 'array' OR jsonb_array_length(v_value) = 0 THEN
            RAISE EXCEPTION 'pep_clients[%] lists no stores (use [".*"] for every store of the binding)', v_client USING ERRCODE = 'invalid_parameter_value';
        END IF;
        FOR v_pat IN SELECT jsonb_array_elements_text(v_value) LOOP
            PERFORM regexp_match('', '^(?:' || v_pat || ')$');
            IF COALESCE(array_length(p_stores, 1), 0) > 0 THEN
                v_covered := false;
                FOREACH v_sp IN ARRAY p_stores LOOP
                    IF v_sp = v_pat OR (v_pat !~ '[\\^$.|?*+()\[\]{}]' AND v_pat ~ ('^(?:' || v_sp || ')$')) THEN
                        v_covered := true;
                    END IF;
                END LOOP;
                IF NOT v_covered THEN
                    RAISE EXCEPTION 'pep_clients[%]: store pattern % is not covered by the stores binding % — assertion cannot widen where tokens may ask', v_client, v_pat, p_stores USING ERRCODE = 'invalid_parameter_value';
                END IF;
            END IF;
        END LOOP;
    END LOOP;
END;
$$;

------------------------------------------------------------------------
-- set_issuer_binding: create or replace the binding row of an issuer (the
-- whole row — a PUT), validated, recorded as p_performed_by (else the
-- session's authz.performed_by, else the connection role).
------------------------------------------------------------------------
-- The signature grew in 0029 (group issuers): the old overload is dropped so
-- a positional call cannot be ambiguous between the two.
DROP FUNCTION IF EXISTS authz.set_issuer_binding(text, text[], text[], jsonb, jsonb, boolean, text, text);
-- The 13-parameter signature (before the alias, migration 0031) is dropped so
-- a reload never leaves two overloads behind.
DROP FUNCTION IF EXISTS authz.set_issuer_binding(text, text[], text[], jsonb, jsonb, boolean, text, text, text, text, text, text[], jsonb);
CREATE OR REPLACE FUNCTION authz.set_issuer_binding(
    p_issuer          text,
    p_stores          text[]  DEFAULT '{}',
    p_db_roles        text[]  DEFAULT '{}',
    p_client_db_roles jsonb   DEFAULT '{}'::jsonb,
    p_pep_clients     jsonb   DEFAULT '{}'::jsonb,
    p_enabled         boolean DEFAULT true,
    p_description     text    DEFAULT NULL,
    p_performed_by    text    DEFAULT NULL,
    p_store_group     text    DEFAULT NULL,      -- ADR 0017: the group whose stores the issuer reaches
    p_jwks_url        text    DEFAULT NULL,      -- a group issuer's own trust anchor
    p_audience        text    DEFAULT NULL,
    p_audiences       text[]  DEFAULT '{}',
    p_admin           jsonb   DEFAULT '[]'::jsonb, -- delegated admin rules only
    p_alias           text    DEFAULT NULL       -- a short handle for the issuer (0031): [a-z0-9_-], unique
) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
    v_rev   bigint;
    v_alias text := NULLIF(lower(btrim(COALESCE(p_alias, ''))), '');
    v_other text;
BEGIN
    IF p_issuer IS NULL OR btrim(p_issuer) = '' THEN
        RAISE EXCEPTION 'issuer is required (the token''s iss)' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF v_alias IS NOT NULL THEN
        IF v_alias !~ '^[a-z0-9][a-z0-9_-]{0,63}$' THEN
            RAISE EXCEPTION 'alias %: letters, digits, _ and - only (max 64), starting with a letter or digit', v_alias
                USING ERRCODE = 'invalid_parameter_value';
        END IF;
        IF v_alias ~ '^https?' THEN
            RAISE EXCEPTION 'alias % looks like a URL: an alias is a short name', v_alias USING ERRCODE = 'invalid_parameter_value';
        END IF;
        SELECT b.issuer INTO v_other FROM authz.issuer_bindings b WHERE b.alias = v_alias AND b.issuer <> btrim(p_issuer);
        IF FOUND THEN
            RAISE EXCEPTION 'alias % already names issuer %', v_alias, v_other USING ERRCODE = 'invalid_parameter_value';
        END IF;
    END IF;
    PERFORM authz._validate_issuer_binding(COALESCE(p_stores, '{}'), COALESCE(p_db_roles, '{}'),
                                           COALESCE(p_client_db_roles, '{}'::jsonb), COALESCE(p_pep_clients, '{}'::jsonb),
                                           NULLIF(btrim(COALESCE(p_store_group, '')), ''), NULLIF(btrim(COALESCE(p_jwks_url, '')), ''),
                                           NULLIF(btrim(COALESCE(p_audience, '')), ''), COALESCE(p_audiences, '{}'), COALESCE(p_admin, '[]'::jsonb));
    PERFORM set_config('authz.performed_by', COALESCE(p_performed_by, ''), true);
    -- created_at / created_by are set once (the INSERT) and kept by a replace.
    INSERT INTO authz.issuer_bindings (issuer, stores, db_roles, client_db_roles, pep_clients, enabled, description,
                                       store_group, jwks_url, audience, audiences, admin, alias,
                                       created_at, created_by, updated_at, updated_by)
    VALUES (btrim(p_issuer), COALESCE(p_stores, '{}'), COALESCE(p_db_roles, '{}'), COALESCE(p_client_db_roles, '{}'::jsonb),
            COALESCE(p_pep_clients, '{}'::jsonb), COALESCE(p_enabled, true), p_description,
            NULLIF(btrim(COALESCE(p_store_group, '')), ''), NULLIF(btrim(COALESCE(p_jwks_url, '')), ''),
            NULLIF(btrim(COALESCE(p_audience, '')), ''), COALESCE(p_audiences, '{}'), COALESCE(p_admin, '[]'::jsonb), v_alias,
            now(), COALESCE(NULLIF(p_performed_by, ''), current_user),
            now(), COALESCE(NULLIF(p_performed_by, ''), current_user))
    ON CONFLICT (issuer) DO UPDATE SET
        stores = EXCLUDED.stores, db_roles = EXCLUDED.db_roles, client_db_roles = EXCLUDED.client_db_roles,
        pep_clients = EXCLUDED.pep_clients, enabled = EXCLUDED.enabled, description = EXCLUDED.description,
        store_group = EXCLUDED.store_group, jwks_url = EXCLUDED.jwks_url, audience = EXCLUDED.audience,
        audiences = EXCLUDED.audiences, admin = EXCLUDED.admin, alias = EXCLUDED.alias,
        updated_at = now(), updated_by = EXCLUDED.updated_by;
    SELECT revision INTO v_rev FROM authz.issuer_bindings_revision;
    RETURN v_rev;
END;
$$;

------------------------------------------------------------------------
-- delete_issuer_binding: drop the row — the issuer falls back to its
-- environment bindings. Returns true when a row existed. p_issuer is the
-- URL or the row's alias (resolve_issuer).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.delete_issuer_binding(
    p_issuer       text,
    p_performed_by text DEFAULT NULL
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_n integer;
BEGIN
    PERFORM set_config('authz.performed_by', COALESCE(p_performed_by, ''), true);
    DELETE FROM authz.issuer_bindings WHERE issuer = COALESCE(authz.resolve_issuer(p_issuer), btrim(p_issuer));
    GET DIAGNOSTICS v_n = ROW_COUNT;
    RETURN v_n > 0;
END;
$$;
