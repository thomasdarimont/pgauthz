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

-- ============================================================================
-- Model ownership and sharing (ADR 0017, phase 3)
-- ============================================================================

------------------------------------------------------------------------
-- grant_model_consumer / revoke_model_consumer: group:A model_consumer
-- group:B — B's stores may apply A's models. Granted by A (its admins, or
-- the platform); recorded in the group audit under A.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.grant_model_consumer(p_owner_group text, p_consumer_group text)
RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM authz._sg(p_owner_group);
    PERFORM authz._sg(p_consumer_group);
    IF p_owner_group = p_consumer_group THEN
        RAISE EXCEPTION 'a group always applies its own models: no relationship with itself' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    INSERT INTO authz.store_group_relations (from_group, to_group, relation, created_by)
    VALUES (p_owner_group, p_consumer_group, 'model_consumer', COALESCE(NULLIF(current_setting('authz.performed_by', true), ''), current_user))
    ON CONFLICT DO NOTHING;
    IF FOUND THEN
        PERFORM authz._store_group_audit('RELATE', p_owner_group, NULL, 'model_consumer ' || p_consumer_group);
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION authz.revoke_model_consumer(p_owner_group text, p_consumer_group text)
RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE v_n integer;
BEGIN
    DELETE FROM authz.store_group_relations
     WHERE from_group = p_owner_group AND to_group = p_consumer_group AND relation = 'model_consumer';
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n > 0 THEN
        PERFORM authz._store_group_audit('UNRELATE', p_owner_group, NULL, 'model_consumer ' || p_consumer_group);
    END IF;
    RETURN v_n > 0;
END;
$$;

-- list_model_consumers: the groups that may apply p_owner_group's models.
CREATE OR REPLACE FUNCTION authz.list_model_consumers(p_owner_group text)
RETURNS TABLE (consumer_group text, created_at timestamptz, created_by text)
LANGUAGE sql STABLE AS $$
    SELECT to_group, created_at, created_by
      FROM authz.store_group_relations
     WHERE from_group = p_owner_group AND relation = 'model_consumer'
     ORDER BY to_group;
$$;

------------------------------------------------------------------------
-- model_owner: who a registry model belongs to — a group, a store (an
-- ungrouped store's own group of one), or nobody known (NULL, NULL: a
-- model from before ownership, treated as the platform's).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_owner(p_name text, OUT owner_group text, OUT owner_store text)
LANGUAGE sql STABLE AS $$
    SELECT o.owner_group, o.owner_store FROM authz.model_owners o WHERE o.name = p_name;
$$;

-- set_model_owner: move a model to a group (or to a store, or to the
-- platform with both NULL) — the platform's call; recorded under the group.
CREATE OR REPLACE FUNCTION authz.set_model_owner(p_name text, p_owner_group text DEFAULT NULL, p_owner_store text DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE v_by text := COALESCE(NULLIF(current_setting('authz.performed_by', true), ''), current_user);
BEGIN
    IF NOT EXISTS (SELECT 1 FROM authz.model_registry WHERE name = p_name) THEN
        RAISE EXCEPTION 'no registry model %', p_name USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_owner_group IS NOT NULL AND p_owner_store IS NOT NULL THEN
        RAISE EXCEPTION 'a model belongs to a group or to a store, not both' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_owner_group IS NOT NULL THEN PERFORM authz._sg(p_owner_group); END IF;
    IF p_owner_store IS NOT NULL THEN PERFORM authz._s(p_owner_store, true); END IF;
    INSERT INTO authz.model_owners (name, owner_group, owner_store, created_by, updated_by)
    VALUES (p_name, p_owner_group, p_owner_store, v_by, v_by)
    ON CONFLICT (name) DO UPDATE SET owner_group = EXCLUDED.owner_group, owner_store = EXCLUDED.owner_store, updated_at = now(), updated_by = v_by;
    PERFORM authz._store_group_audit('OWN', COALESCE(p_owner_group, 'default'), p_owner_store, 'model ' || p_name);
END;
$$;

------------------------------------------------------------------------
-- _claim_model_owner: on publish — a new name takes the publisher's
-- ownership (the store's group, the store itself when ungrouped, or the
-- platform when no store is involved); a group's name takes new versions
-- from that group only.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._claim_model_owner(p_name text, p_from_store text)
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_group text;
    v_store text;
    v_cur   record;
BEGIN
    IF p_from_store IS NOT NULL THEN
        SELECT g.name INTO v_group FROM authz.stores s LEFT JOIN authz.store_groups g ON g.id = s.group_id WHERE s.name = p_from_store;
        IF v_group IS NULL THEN v_store := p_from_store; END IF;
    ELSE
        v_group := 'default';
    END IF;
    SELECT * INTO v_cur FROM authz.model_owners WHERE name = p_name;
    IF NOT FOUND THEN
        INSERT INTO authz.model_owners (name, owner_group, owner_store, created_by, updated_by)
        VALUES (p_name, v_group, v_store,
                COALESCE(NULLIF(current_setting('authz.performed_by', true), ''), current_user),
                COALESCE(NULLIF(current_setting('authz.performed_by', true), ''), current_user));
        RETURN;
    END IF;
    -- a group's model takes new versions from that group only (the platform's
    -- and an ungrouped store's from anywhere: the API and the console decide
    -- who may publish; the engine keeps the ungrouped round-trip working)
    IF v_cur.owner_group IS NOT NULL AND v_cur.owner_group <> 'default' AND v_cur.owner_group IS DISTINCT FROM v_group THEN
        RAISE EXCEPTION 'model % belongs to group % — a new version is published from that group (set_model_owner moves it)',
            p_name, v_cur.owner_group USING ERRCODE = 'insufficient_privilege';
    END IF;
END;
$$;

------------------------------------------------------------------------
-- _model_applicable: may p_store apply registry model p_name? Isolation
-- is a GROUP's property: a model owned by a group other than default is
-- applied by that group's stores, and by the stores of groups it granted
-- model_consumer. The platform's models (the default group's, or unowned)
-- and an ungrouped store's models are open to every store — the registry
-- of a deployment without groups behaves as it always did. Reported by
-- plan_model_apply, enforced by apply_model.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._model_applicable(p_store text, p_name text, OUT ok boolean, OUT why text)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_owner record;
    v_group text;
BEGIN
    ok := true; why := NULL;
    SELECT * INTO v_owner FROM authz.model_owners WHERE name = p_name;
    IF NOT FOUND OR v_owner.owner_group IS NULL OR v_owner.owner_group = 'default' THEN
        RETURN;                                           -- the platform's, or an ungrouped store's: open
    END IF;
    SELECT g.name INTO v_group FROM authz.stores s LEFT JOIN authz.store_groups g ON g.id = s.group_id WHERE s.name = p_store;
    IF v_group IS NOT DISTINCT FROM v_owner.owner_group THEN RETURN; END IF;
    IF v_group IS NOT NULL AND EXISTS (SELECT 1 FROM authz.store_group_relations r
                                        WHERE r.from_group = v_owner.owner_group AND r.to_group = v_group AND r.relation = 'model_consumer') THEN
        RETURN;
    END IF;
    ok := false;
    why := format('model %s belongs to group %s; store %s (%s) may apply it only with a model_consumer grant from %s',
                  p_name, v_owner.owner_group, p_store, COALESCE('group ' || v_group, 'ungrouped'), v_owner.owner_group);
END;
$$;
