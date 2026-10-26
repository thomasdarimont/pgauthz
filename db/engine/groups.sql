-- ============================================================================
-- Store groups (ADR 0017): create, describe, delete a group; attach a store
-- to one or detach it. Membership is the engine's fact — the console and
-- the admin API manage it here; pgauthzd's gate and the console's access
-- model read it. Every change is written to authz.store_group_audit as
-- authz.performed_by (else the connection role).
-- ============================================================================

CREATE OR REPLACE FUNCTION authz._sg(p_name text) RETURNS integer
LANGUAGE plpgsql STABLE AS $$
DECLARE v_id integer;
BEGIN
    SELECT id INTO v_id FROM authz.store_groups WHERE name = p_name;
    IF v_id IS NULL THEN
        RAISE EXCEPTION 'Unknown store group: %', p_name USING ERRCODE = 'invalid_parameter_value';
    END IF;
    RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION authz._store_group_audit(p_action text, p_group text, p_store text DEFAULT NULL, p_description text DEFAULT NULL)
RETURNS void LANGUAGE sql AS $$
    INSERT INTO authz.store_group_audit (action, performed_by, group_name, store, description)
    VALUES (p_action, COALESCE(NULLIF(current_setting('authz.performed_by', true), ''), current_user), p_group, p_store, p_description);
$$;

------------------------------------------------------------------------
-- create_store_group: a new, empty group. Names follow the store-name rule.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.create_store_group(p_name text, p_description text DEFAULT NULL)
RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_id integer;
    v_by text := COALESCE(NULLIF(current_setting('authz.performed_by', true), ''), current_user);
BEGIN
    IF p_name IS NULL OR p_name !~ '^[a-zA-Z_][a-zA-Z0-9_]*$' OR length(p_name) > 63 THEN
        RAISE EXCEPTION 'invalid store group name %: must match ^[a-zA-Z_][a-zA-Z0-9_]*$ (<=63 chars)', p_name
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO authz.store_groups (name, description, created_by, updated_by)
    VALUES (p_name, NULLIF(p_description, ''), v_by, v_by)
    RETURNING id INTO v_id;
    PERFORM authz._store_group_audit('CREATE', p_name, NULL, NULLIF(p_description, ''));
    RETURN v_id;
END;
$$;

------------------------------------------------------------------------
-- update_store_group: the description (NULL leaves it, '' clears it).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.update_store_group(p_name text, p_description text)
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE v_id integer := authz._sg(p_name);
BEGIN
    UPDATE authz.store_groups
       SET description = CASE WHEN p_description IS NULL THEN description ELSE NULLIF(p_description, '') END,
           updated_at = now(),
           updated_by = COALESCE(NULLIF(current_setting('authz.performed_by', true), ''), current_user)
     WHERE id = v_id;
    PERFORM authz._store_group_audit('UPDATE', p_name, NULL, p_description);
END;
$$;

------------------------------------------------------------------------
-- delete_store_group: an EMPTY group other than default. Move or detach
-- its stores first: a deletion never changes what a store belongs to.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.delete_store_group(p_name text)
RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_id integer;
    v_n  integer;
BEGIN
    IF p_name = 'default' THEN
        RAISE EXCEPTION 'the default store group cannot be deleted' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT id INTO v_id FROM authz.store_groups WHERE name = p_name;
    IF v_id IS NULL THEN
        RETURN false;
    END IF;
    SELECT count(*) INTO v_n FROM authz.stores WHERE group_id = v_id;
    IF v_n > 0 THEN
        RAISE EXCEPTION 'store group % still holds % store(s): move or detach them first', p_name, v_n
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    SELECT count(*) INTO v_n FROM authz.issuer_bindings WHERE store_group = p_name;
    IF v_n > 0 THEN
        RAISE EXCEPTION 'store group % still has % issuer(s): remove them first', p_name, v_n
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    DELETE FROM authz.store_groups WHERE id = v_id;
    PERFORM authz._store_group_audit('DELETE', p_name);
    RETURN true;
END;
$$;

------------------------------------------------------------------------
-- set_store_group: attach a store to a group, or detach it (p_group NULL
-- or ''): an ungrouped store is its own group of one. Retired stores
-- included (their group still says who administers their history).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.set_store_group(p_store text, p_group text)
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_store integer := authz._s(p_store, true);
    v_old   text;
    v_new   integer;
BEGIN
    SELECT g.name INTO v_old FROM authz.stores s LEFT JOIN authz.store_groups g ON g.id = s.group_id WHERE s.id = v_store;
    IF NULLIF(p_group, '') IS NOT NULL THEN
        v_new := authz._sg(p_group);
    END IF;
    IF v_old IS NOT DISTINCT FROM NULLIF(p_group, '') THEN
        RETURN;                                 -- already there: nothing to record
    END IF;
    UPDATE authz.stores SET group_id = v_new WHERE id = v_store;
    IF v_old IS NOT NULL THEN
        PERFORM authz._store_group_audit('DETACH', v_old, p_store);
    END IF;
    IF v_new IS NOT NULL THEN
        PERFORM authz._store_group_audit('ATTACH', p_group, p_store);
    END IF;
    -- a group issuer's reach is the group's stores: the fleet re-reads the
    -- bindings (the revision pgauthzd polls, the doorbell it listens to)
    UPDATE authz.issuer_bindings_revision SET revision = revision + 1, changed_at = now();
    PERFORM pg_notify('authz_issuer_bindings', (SELECT revision FROM authz.issuer_bindings_revision)::text);
END;
$$;
