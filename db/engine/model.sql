-- Public model management API: type/relation registration, rule management,
-- and namespace access control.
-- All functions accept text parameters and resolve IDs internally.
--
-- Depends on: engine/core_internal.sql

------------------------------------------------------------------------
-- model_register_type: registers a new object type and creates its
-- tuple partition in one call.
--
-- Parameters:
--   p_store          — store name
--   p_type_name      — the object type name (e.g. 'invoice')
--   p_hash_modulus   — number of hash sub-partitions on object_id
--                      (0 = simple partition, 8 = recommended for high-volume types)
--   p_namespace      — optional namespace for access control
--   p_description    — optional description
--
-- Returns the new type's smallint ID.
-- Idempotent for the partition (safe to call again), but will raise
-- a unique violation if the type name already exists in this store.
--
-- Examples:
--   SELECT authz.model_register_type('demo', 'invoice');
--   SELECT authz.model_register_type('demo', 'invoice', 8);
--   SELECT authz.model_register_type('demo', 'invoice', 8, 'accounting');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_register_type(
    p_store        text,
    p_type_name    text,
    p_hash_modulus int DEFAULT 0,
    p_namespace    text DEFAULT NULL,
    p_description  text DEFAULT NULL
) RETURNS smallint
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id smallint := authz._s(p_store);
    v_type_id  smallint;
BEGIN
    INSERT INTO authz.types (store_id, name, namespace, description)
    VALUES (v_store_id, p_type_name, p_namespace, p_description)
    RETURNING id INTO v_type_id;

    PERFORM authz._ensure_tuple_partition(v_store_id, p_type_name, p_hash_modulus);

    RETURN v_type_id;
END;
$$;

------------------------------------------------------------------------
-- model_register_relation: registers a new relation name in a store.
--
-- Idempotent — returns the relation's smallint ID whether it was
-- newly created or already existed.
--
-- Examples:
--   SELECT authz.model_register_relation('demo', 'can_archive');
--   SELECT authz.model_register_relation('demo', 'can_approve', 'Approval permission');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_register_relation(
    p_store       text,
    p_name        text,
    p_description text DEFAULT NULL
) RETURNS smallint
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id    smallint := authz._s(p_store);
    v_relation_id smallint;
BEGIN
    INSERT INTO authz.relations (store_id, name, description)
    VALUES (v_store_id, p_name, p_description)
    ON CONFLICT (store_id, name) DO UPDATE SET name = EXCLUDED.name
    RETURNING id INTO v_relation_id;

    RETURN v_relation_id;
END;
$$;

------------------------------------------------------------------------
-- model_add_rule: adds a single model rule. Idempotent — duplicate
-- inserts are silently ignored (ON CONFLICT DO NOTHING).
-- Returns the rule's smallint ID (existing or new).
--
-- Validates:
--   - rule_type is one of 'direct', 'computed', 'ttu'
--   - computed rules require p_computed_relation
--   - TTU rules require p_tupleset_relation and p_tupleset_computed
--   - group_op consistency: all rules in a group must use the same op
--
-- Examples:
--   SELECT authz.model_add_rule('demo', 'document', 'viewer', 'direct');
--   SELECT authz.model_add_rule('demo', 'document', 'can_read', 'computed',
--       p_computed_relation => 'viewer');
--   SELECT authz.model_add_rule('demo', 'document', 'can_read', 'ttu',
--       p_tupleset_relation => 'in_internal_space',
--       p_tupleset_computed => 'can_view');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_add_rule(
    p_store              text,
    p_object_type        text,
    p_relation           text,
    p_rule_type          text,                    -- 'direct', 'computed', 'ttu'
    p_computed_relation  text DEFAULT NULL,
    p_tupleset_relation  text DEFAULT NULL,
    p_tupleset_computed  text DEFAULT NULL,
    p_group_id           smallint DEFAULT 0,
    p_group_op           text DEFAULT 'or',       -- 'or', 'intersection', 'exclusion'
    p_negated            boolean DEFAULT false
) RETURNS smallint
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id     smallint := authz._s(p_store);
    v_object_type  smallint := authz._t(v_store_id, p_object_type);
    v_relation     smallint := authz._r(v_store_id, p_relation);
    v_rule_type    smallint;
    v_computed_rel smallint;
    v_tupleset_rel smallint;
    v_tupleset_cmp smallint;
    v_group_op     smallint;
    v_rule_id      smallint;
BEGIN
    -- Resolve rule_type
    CASE p_rule_type
        WHEN 'direct'   THEN v_rule_type := authz._rel_direct();
        WHEN 'computed' THEN v_rule_type := authz._rel_computed();
        WHEN 'ttu'      THEN v_rule_type := authz._rel_ttu();
        ELSE RAISE EXCEPTION 'Invalid rule_type: %. Must be direct, computed, or ttu', p_rule_type;
    END CASE;

    -- Resolve group_op
    CASE p_group_op
        WHEN 'or'           THEN v_group_op := authz._combine_or();
        WHEN 'intersection' THEN v_group_op := authz._combine_and();
        WHEN 'exclusion'    THEN v_group_op := authz._combine_exclusion();
        ELSE RAISE EXCEPTION 'Invalid group_op: %. Must be or, intersection, or exclusion', p_group_op;
    END CASE;

    -- Validate rule-type-specific parameters
    IF v_rule_type = authz._rel_computed() THEN
        IF p_computed_relation IS NULL THEN
            RAISE EXCEPTION 'computed rules require p_computed_relation';
        END IF;
        v_computed_rel := authz._r(v_store_id, p_computed_relation);
    ELSIF v_rule_type = authz._rel_ttu() THEN
        IF p_tupleset_relation IS NULL OR p_tupleset_computed IS NULL THEN
            RAISE EXCEPTION 'ttu rules require p_tupleset_relation and p_tupleset_computed';
        END IF;
        v_tupleset_rel := authz._r(v_store_id, p_tupleset_relation);
        v_tupleset_cmp := authz._r(v_store_id, p_tupleset_computed);
    END IF;

    -- Check group_op consistency: all rules in a group must use the same op
    IF EXISTS (
        SELECT 1 FROM authz.models
         WHERE store_id = v_store_id
           AND object_type = v_object_type
           AND relation = v_relation
           AND group_id = p_group_id
           AND group_op <> v_group_op
    ) THEN
        RAISE EXCEPTION 'group % already uses a different group_op', p_group_id;
    END IF;

    -- Insert (idempotent via unique index)
    INSERT INTO authz.models (
        store_id, object_type, relation, rule_type,
        computed_relation, tupleset_relation, tupleset_computed,
        group_id, group_op, negated
    ) VALUES (
        v_store_id, v_object_type, v_relation, v_rule_type,
        v_computed_rel, v_tupleset_rel, v_tupleset_cmp,
        p_group_id, v_group_op, p_negated
    )
    ON CONFLICT (
        store_id, object_type, relation, rule_type,
        COALESCE(computed_relation, -1),
        COALESCE(tupleset_relation, -1),
        COALESCE(tupleset_computed, -1),
        group_id, negated
    ) DO NOTHING;

    -- Return the rule ID (whether newly inserted or already existing)
    SELECT id INTO v_rule_id FROM authz.models
     WHERE store_id = v_store_id
       AND object_type = v_object_type
       AND relation = v_relation
       AND rule_type = v_rule_type
       AND COALESCE(computed_relation, -1) = COALESCE(v_computed_rel, -1)
       AND COALESCE(tupleset_relation, -1) = COALESCE(v_tupleset_rel, -1)
       AND COALESCE(tupleset_computed, -1) = COALESCE(v_tupleset_cmp, -1)
       AND group_id = p_group_id
       AND negated = p_negated;

    RETURN v_rule_id;
END;
$$;

------------------------------------------------------------------------
-- model_remove_rule: removes a single model rule by ID.
-- Returns true if the rule was deleted, false if it didn't exist.
-- Validates that the rule belongs to the specified store.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_remove_rule(
    p_store   text,
    p_rule_id smallint
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id smallint := authz._s(p_store);
    v_deleted  boolean;
BEGIN
    DELETE FROM authz.models
     WHERE id = p_rule_id
       AND store_id = v_store_id;

    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$;

------------------------------------------------------------------------
-- model_remove_rules: removes all model rules for a specific
-- (object_type, relation) combination. Returns the count of deleted rules.
-- Useful when redefining how a relation is resolved.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_remove_rules(
    p_store       text,
    p_object_type text,
    p_relation    text
) RETURNS int
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id    smallint := authz._s(p_store);
    v_object_type smallint := authz._t(v_store_id, p_object_type);
    v_relation    smallint := authz._r(v_store_id, p_relation);
    v_count       int;
BEGIN
    -- Cascade: remove type restrictions for this (object_type, relation)
    DELETE FROM authz.type_restrictions
     WHERE store_id = v_store_id
       AND object_type = v_object_type
       AND relation = v_relation;

    DELETE FROM authz.models
     WHERE store_id = v_store_id
       AND object_type = v_object_type
       AND relation = v_relation;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

------------------------------------------------------------------------
-- grant_namespace_access: grants read and/or write access to a namespace
-- for a DB role. Uses INSERT ... ON CONFLICT to upsert — calling it
-- multiple times with different flags merges them (OR'd).
--
-- Examples:
--   SELECT authz.grant_namespace_access('demo', 'hr', 'app_hr', true, true);
--   SELECT authz.grant_namespace_access('demo', 'hr', 'app_portal', can_read := true);
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.grant_namespace_access(
    p_store     text,
    p_namespace text,
    p_db_role   text,
    p_can_read  boolean DEFAULT false,
    p_can_write boolean DEFAULT false
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id smallint := authz._s(p_store);
BEGIN
    INSERT INTO authz.namespace_access (store_id, namespace, db_role, can_read, can_write)
    VALUES (v_store_id, p_namespace, p_db_role, p_can_read, p_can_write)
    ON CONFLICT (store_id, namespace, db_role) DO UPDATE
        SET can_read  = authz.namespace_access.can_read  OR EXCLUDED.can_read,
            can_write = authz.namespace_access.can_write OR EXCLUDED.can_write;
END;
$$;

------------------------------------------------------------------------
-- revoke_namespace_access: revokes read and/or write access from a
-- namespace for a DB role. When both flags become false, the row is
-- deleted automatically.
--
-- Examples:
--   SELECT authz.revoke_namespace_access('demo', 'hr', 'app_portal', can_read := true);
--   SELECT authz.revoke_namespace_access('demo', 'hr', 'app_hr', true, true);
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.revoke_namespace_access(
    p_store     text,
    p_namespace text,
    p_db_role   text,
    p_can_read  boolean DEFAULT false,
    p_can_write boolean DEFAULT false
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id smallint := authz._s(p_store);
BEGIN
    UPDATE authz.namespace_access
       SET can_read  = can_read  AND NOT p_can_read,
           can_write = can_write AND NOT p_can_write
     WHERE store_id  = v_store_id
       AND namespace = p_namespace
       AND db_role   = p_db_role;

    IF NOT FOUND THEN
        RETURN false;
    END IF;

    -- Clean up rows with no permissions remaining
    DELETE FROM authz.namespace_access
     WHERE store_id  = v_store_id
       AND namespace = p_namespace
       AND db_role   = p_db_role
       AND NOT can_read
       AND NOT can_write;

    RETURN true;
END;
$$;

------------------------------------------------------------------------
-- model_add_type_restriction: defines which subject types can be
-- directly assigned to a relation. Idempotent (ON CONFLICT DO NOTHING).
--
-- Examples:
--   -- Allow direct user assignments:
--   SELECT authz.model_add_type_restriction('demo', 'document', 'viewer', 'user');
--   -- Allow wildcard (user:*):
--   SELECT authz.model_add_type_restriction('demo', 'document', 'viewer', 'user',
--       p_allow_wildcard => true);
--   -- Allow userset (group#member):
--   SELECT authz.model_add_type_restriction('demo', 'document', 'viewer', 'group',
--       p_allowed_user_relation => 'member');
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_add_type_restriction(
    p_store                 text,
    p_object_type           text,
    p_relation              text,
    p_allowed_user_type     text,
    p_allowed_user_relation text DEFAULT NULL,
    p_allow_wildcard        boolean DEFAULT false
) RETURNS smallint
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id         smallint := authz._s(p_store);
    v_object_type      smallint := authz._t(v_store_id, p_object_type);
    v_relation         smallint := authz._r(v_store_id, p_relation);
    v_allowed_user_type smallint := authz._t(v_store_id, p_allowed_user_type);
    v_allowed_user_rel smallint;
    v_id               smallint;
BEGIN
    -- Wildcard and user_relation are mutually exclusive
    IF p_allow_wildcard AND p_allowed_user_relation IS NOT NULL THEN
        RAISE EXCEPTION 'allow_wildcard and allowed_user_relation cannot be combined';
    END IF;

    IF p_allowed_user_relation IS NOT NULL THEN
        v_allowed_user_rel := authz._r(v_store_id, p_allowed_user_relation);
    END IF;

    INSERT INTO authz.type_restrictions (
        store_id, object_type, relation,
        allowed_user_type, allowed_user_relation, allow_wildcard
    ) VALUES (
        v_store_id, v_object_type, v_relation,
        v_allowed_user_type, v_allowed_user_rel, p_allow_wildcard
    )
    ON CONFLICT (store_id, object_type, relation, allowed_user_type,
                 COALESCE(allowed_user_relation, -1), allow_wildcard)
    DO NOTHING;

    -- Return the restriction ID (whether newly inserted or already existing)
    SELECT id INTO v_id FROM authz.type_restrictions
     WHERE store_id = v_store_id
       AND object_type = v_object_type
       AND relation = v_relation
       AND allowed_user_type = v_allowed_user_type
       AND COALESCE(allowed_user_relation, -1) = COALESCE(v_allowed_user_rel, -1)
       AND allow_wildcard = p_allow_wildcard;

    RETURN v_id;
END;
$$;

------------------------------------------------------------------------
-- model_remove_type_restriction: removes a single type restriction by ID.
-- Returns true if it was deleted, false if it didn't exist.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_remove_type_restriction(
    p_store          text,
    p_restriction_id smallint
) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id smallint := authz._s(p_store);
BEGIN
    DELETE FROM authz.type_restrictions
     WHERE id = p_restriction_id
       AND store_id = v_store_id;

    RETURN FOUND;
END;
$$;

------------------------------------------------------------------------
-- model_remove_type_restrictions: removes all type restrictions for a
-- specific (object_type, relation). Returns the count of deleted rows.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.model_remove_type_restrictions(
    p_store       text,
    p_object_type text,
    p_relation    text
) RETURNS int
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id    smallint := authz._s(p_store);
    v_object_type smallint := authz._t(v_store_id, p_object_type);
    v_relation    smallint := authz._r(v_store_id, p_relation);
    v_count       int;
BEGIN
    DELETE FROM authz.type_restrictions
     WHERE store_id = v_store_id
       AND object_type = v_object_type
       AND relation = v_relation;

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;
