-- OpenFGA import functions.
-- Converts OpenFGA JSON models and tuples into authz DB format.
--
-- Depends on: engine/core_internal.sql, engine/model.sql (must be loaded first)

------------------------------------------------------------------------
-- _import_register_relations: recursively registers relation names
-- found in an OpenFGA relation definition node.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._import_register_relations(p_store_id smallint, p_node jsonb)
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_child jsonb;
    v_rel   text;
BEGIN
    -- computedUserset references a relation name
    IF p_node->'computedUserset' IS NOT NULL THEN
        v_rel := p_node->'computedUserset'->>'relation';
        IF v_rel IS NOT NULL AND v_rel <> '' THEN
            INSERT INTO authz.relations (store_id, name) VALUES (p_store_id, v_rel)
            ON CONFLICT (store_id, name) DO NOTHING;
        END IF;
    END IF;

    -- tupleToUserset references two relation names
    IF p_node->'tupleToUserset' IS NOT NULL THEN
        v_rel := p_node->'tupleToUserset'->'tupleset'->>'relation';
        IF v_rel IS NOT NULL AND v_rel <> '' THEN
            INSERT INTO authz.relations (store_id, name) VALUES (p_store_id, v_rel)
            ON CONFLICT (store_id, name) DO NOTHING;
        END IF;
        v_rel := p_node->'tupleToUserset'->'computedUserset'->>'relation';
        IF v_rel IS NOT NULL AND v_rel <> '' THEN
            INSERT INTO authz.relations (store_id, name) VALUES (p_store_id, v_rel)
            ON CONFLICT (store_id, name) DO NOTHING;
        END IF;
    END IF;

    -- Recurse into union/intersection children
    IF p_node->'union' IS NOT NULL THEN
        FOR v_child IN SELECT jsonb_array_elements(p_node->'union'->'child')
        LOOP
            PERFORM authz._import_register_relations(p_store_id, v_child);
        END LOOP;
    END IF;
    IF p_node->'intersection' IS NOT NULL THEN
        FOR v_child IN SELECT jsonb_array_elements(p_node->'intersection'->'child')
        LOOP
            PERFORM authz._import_register_relations(p_store_id, v_child);
        END LOOP;
    END IF;
    -- 'difference' is the OpenFGA API key; 'exclusion' is kept as an alias
    IF p_node->'difference' IS NOT NULL THEN
        PERFORM authz._import_register_relations(p_store_id, p_node->'difference'->'base');
        PERFORM authz._import_register_relations(p_store_id, p_node->'difference'->'subtract');
    END IF;
    IF p_node->'exclusion' IS NOT NULL THEN
        PERFORM authz._import_register_relations(p_store_id, p_node->'exclusion'->'base');
        PERFORM authz._import_register_relations(p_store_id, p_node->'exclusion'->'subtract');
    END IF;
END;
$$;

------------------------------------------------------------------------
-- _import_rule: converts a single OpenFGA leaf rule node into a models
-- row, optionally inside a rule group (intersection/exclusion).
-- Handles: this (direct), computedUserset (computed), tupleToUserset (ttu).
-- Anything else (a nested operator where a leaf is required) raises —
-- importing an approximation would silently grant more access than the
-- original model.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._import_rule(
    p_store_id  smallint,
    p_type_name text,
    p_rel_name  text,
    p_node      jsonb,
    p_group_id  smallint DEFAULT 0,
    p_group_op  smallint DEFAULT 0,
    p_negated   boolean  DEFAULT false
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_tupleset_rel text;
    v_computed_rel text;
BEGIN
    -- this -> direct
    IF p_node ? 'this' THEN
        INSERT INTO authz.models (store_id, object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed, group_id, group_op, negated)
        VALUES (p_store_id, authz._t(p_store_id, p_type_name), authz._r(p_store_id, p_rel_name), authz._rel_direct(), NULL, NULL, NULL, p_group_id, p_group_op, p_negated);

    -- computedUserset -> computed
    ELSIF p_node->'computedUserset' IS NOT NULL THEN
        v_computed_rel := p_node->'computedUserset'->>'relation';
        INSERT INTO authz.models (store_id, object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed, group_id, group_op, negated)
        VALUES (p_store_id, authz._t(p_store_id, p_type_name), authz._r(p_store_id, p_rel_name), authz._rel_computed(), authz._r(p_store_id, v_computed_rel), NULL, NULL, p_group_id, p_group_op, p_negated);

    -- tupleToUserset -> ttu
    ELSIF p_node->'tupleToUserset' IS NOT NULL THEN
        v_tupleset_rel := p_node->'tupleToUserset'->'tupleset'->>'relation';
        v_computed_rel := p_node->'tupleToUserset'->'computedUserset'->>'relation';
        INSERT INTO authz.models (store_id, object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed, group_id, group_op, negated)
        VALUES (p_store_id, authz._t(p_store_id, p_type_name), authz._r(p_store_id, p_rel_name), authz._rel_ttu(), NULL, authz._r(p_store_id, v_tupleset_rel), authz._r(p_store_id, v_computed_rel), p_group_id, p_group_op, p_negated);

    ELSE
        RAISE EXCEPTION 'import_openfga_model: unsupported rule node for %.% — operators may nest at most one level below union, re-model manually as rule groups: %',
            p_type_name, p_rel_name, p_node::text;
    END IF;
END;
$$;

------------------------------------------------------------------------
-- _import_exclusion: translates an OpenFGA difference/exclusion node
-- into exclusion rule group(s).
--
-- Base rules within ONE exclusion group are AND-ed by this engine,
-- while an OpenFGA difference base is typically a union — so a union
-- base is expanded into one exclusion group per base alternative, each
-- carrying the negated subtract rule(s). A union subtract maps to
-- multiple negated rules in the same group (any match excludes).
--
-- Returns the next free group id.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._import_exclusion(
    p_store_id    smallint,
    p_type_name   text,
    p_rel_name    text,
    p_base        jsonb,
    p_subtract    jsonb,
    p_group_start smallint
) RETURNS smallint
LANGUAGE plpgsql AS $$
DECLARE
    v_base_children     jsonb[];
    v_subtract_children jsonb[];
    v_base              jsonb;
    v_subtract          jsonb;
    v_group             smallint := p_group_start;
BEGIN
    IF p_base->'union' IS NOT NULL THEN
        SELECT array_agg(c) INTO v_base_children
          FROM jsonb_array_elements(p_base->'union'->'child') c;
    ELSE
        v_base_children := ARRAY[p_base];
    END IF;

    IF p_subtract->'union' IS NOT NULL THEN
        SELECT array_agg(c) INTO v_subtract_children
          FROM jsonb_array_elements(p_subtract->'union'->'child') c;
    ELSE
        v_subtract_children := ARRAY[p_subtract];
    END IF;

    FOREACH v_base IN ARRAY v_base_children LOOP
        -- Base rule first: the validation trigger rejects exclusion
        -- groups that (even transiently) contain only negated rules.
        PERFORM authz._import_rule(p_store_id, p_type_name, p_rel_name, v_base,
            v_group, authz._combine_exclusion(), false);
        FOREACH v_subtract IN ARRAY v_subtract_children LOOP
            PERFORM authz._import_rule(p_store_id, p_type_name, p_rel_name, v_subtract,
                v_group, authz._combine_exclusion(), true);
        END LOOP;
        v_group := v_group + 1;
    END LOOP;

    RETURN v_group;
END;
$$;

------------------------------------------------------------------------
-- import_openfga_model: imports an OpenFGA JSON model into a store.
-- Creates the store (if it doesn't exist), registers types and relations,
-- and inserts model rules. Existing rules for the store are replaced.
--
-- Returns a JSON summary with types, relations, rule counts, and warnings.
--
-- Supports schema_version 1.1 and 1.2.
-- Handles: this (direct), computedUserset (computed),
--          tupleToUserset (ttu), union (OR rules),
--          intersection (AND rule group), and difference/exclusion
--          (exclusion rule groups — one per base alternative).
-- Operators may nest at most one level below union; deeper nesting
-- raises an error rather than importing a more permissive model.
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.import_openfga_model(
    p_store text,
    p_model jsonb
) RETURNS jsonb
LANGUAGE plpgsql AS $$
DECLARE
    v_store_id   smallint;
    v_type_def   jsonb;
    v_type_name  text;
    v_rel_name   text;
    v_rel_def    jsonb;
    v_child      jsonb;
    v_types      text[] := '{}';
    v_relations  text[] := '{}';
    v_rules_before int;
    v_rules_after  int;
    v_warnings   text[] := '{}';
    v_metadata   jsonb;
    v_rel_meta   jsonb;
    v_drut       jsonb;
    v_drut_item  jsonb;
    v_drut_type  text;
    v_drut_rel   text;
    v_drut_wild  boolean;
    v_type_restrictions_imported int := 0;
    v_sub        jsonb;
    v_next_group smallint;
BEGIN
    -- Create or get store
    INSERT INTO authz.stores (name) VALUES (p_store)
    ON CONFLICT (name) DO NOTHING;
    v_store_id := authz._s(p_store);

    -- Clear existing model rules and type restrictions for this store
    SELECT count(*) INTO v_rules_before FROM authz.models WHERE store_id = v_store_id;
    DELETE FROM authz.type_restrictions WHERE store_id = v_store_id;
    DELETE FROM authz.models WHERE store_id = v_store_id;

    -- Register all types and create partitions
    FOR v_type_def IN SELECT jsonb_array_elements(p_model->'type_definitions')
    LOOP
        v_type_name := v_type_def->>'type';
        INSERT INTO authz.types (store_id, name) VALUES (v_store_id, v_type_name)
        ON CONFLICT (store_id, name) DO NOTHING;
        v_types := array_append(v_types, v_type_name);
        PERFORM authz._ensure_tuple_partition(v_store_id, v_type_name);
    END LOOP;

    -- Process each type definition
    FOR v_type_def IN SELECT jsonb_array_elements(p_model->'type_definitions')
    LOOP
        v_type_name := v_type_def->>'type';

        -- Skip types with no relations (e.g. "user")
        IF v_type_def->'relations' IS NULL OR v_type_def->'relations' = '{}'::jsonb THEN
            CONTINUE;
        END IF;

        -- Process each relation
        FOR v_rel_name, v_rel_def IN SELECT * FROM jsonb_each(v_type_def->'relations')
        LOOP
            -- Register relation
            INSERT INTO authz.relations (store_id, name) VALUES (v_store_id, v_rel_name)
            ON CONFLICT (store_id, name) DO NOTHING;
            IF NOT v_rel_name = ANY(v_relations) THEN
                v_relations := array_append(v_relations, v_rel_name);
            END IF;

            -- Register any referenced relations from the definition
            PERFORM authz._import_register_relations(v_store_id, v_rel_def);

            -- Extract type restrictions from metadata.relations.<rel>.directly_related_user_types
            v_metadata := v_type_def->'metadata';
            IF v_metadata IS NOT NULL THEN
                v_rel_meta := v_metadata->'relations'->v_rel_name;
                IF v_rel_meta IS NOT NULL THEN
                    v_drut := v_rel_meta->'directly_related_user_types';
                    IF v_drut IS NOT NULL AND jsonb_typeof(v_drut) = 'array' THEN
                        FOR v_drut_item IN SELECT jsonb_array_elements(v_drut)
                        LOOP
                            v_drut_type := v_drut_item->>'type';
                            v_drut_rel  := v_drut_item->>'relation';
                            v_drut_wild := v_drut_item ? 'wildcard';

                            -- Register the allowed user type if not already known
                            INSERT INTO authz.types (store_id, name) VALUES (v_store_id, v_drut_type)
                            ON CONFLICT (store_id, name) DO NOTHING;

                            IF v_drut_rel IS NOT NULL AND v_drut_rel <> '' THEN
                                -- Userset restriction (e.g. group#member)
                                INSERT INTO authz.relations (store_id, name) VALUES (v_store_id, v_drut_rel)
                                ON CONFLICT (store_id, name) DO NOTHING;
                                INSERT INTO authz.type_restrictions (
                                    store_id, object_type, relation,
                                    allowed_user_type, allowed_user_relation, allow_wildcard
                                ) VALUES (
                                    v_store_id,
                                    authz._t(v_store_id, v_type_name),
                                    authz._r(v_store_id, v_rel_name),
                                    authz._t(v_store_id, v_drut_type),
                                    authz._r(v_store_id, v_drut_rel),
                                    false
                                ) ON CONFLICT DO NOTHING;
                            ELSIF v_drut_wild THEN
                                -- Wildcard restriction (e.g. user:*)
                                INSERT INTO authz.type_restrictions (
                                    store_id, object_type, relation,
                                    allowed_user_type, allowed_user_relation, allow_wildcard
                                ) VALUES (
                                    v_store_id,
                                    authz._t(v_store_id, v_type_name),
                                    authz._r(v_store_id, v_rel_name),
                                    authz._t(v_store_id, v_drut_type),
                                    NULL,
                                    true
                                ) ON CONFLICT DO NOTHING;
                            ELSE
                                -- Direct user restriction (e.g. user)
                                INSERT INTO authz.type_restrictions (
                                    store_id, object_type, relation,
                                    allowed_user_type, allowed_user_relation, allow_wildcard
                                ) VALUES (
                                    v_store_id,
                                    authz._t(v_store_id, v_type_name),
                                    authz._r(v_store_id, v_rel_name),
                                    authz._t(v_store_id, v_drut_type),
                                    NULL,
                                    false
                                ) ON CONFLICT DO NOTHING;
                            END IF;
                            v_type_restrictions_imported := v_type_restrictions_imported + 1;
                        END LOOP;
                    END IF;
                END IF;
            END IF;

            -- Translate the relation definition into model rules.
            -- union children go to group 0 (OR); intersection becomes an
            -- AND group; difference/exclusion becomes exclusion group(s).
            -- Operator children of a union get their own groups (groups
            -- are OR'd), so one nesting level below union is supported.
            v_next_group := 1;

            IF v_rel_def->'union' IS NOT NULL THEN
                FOR v_child IN SELECT jsonb_array_elements(v_rel_def->'union'->'child')
                LOOP
                    IF v_child->'intersection' IS NOT NULL THEN
                        FOR v_sub IN SELECT jsonb_array_elements(v_child->'intersection'->'child')
                        LOOP
                            PERFORM authz._import_rule(v_store_id, v_type_name, v_rel_name, v_sub,
                                v_next_group, authz._combine_and(), false);
                        END LOOP;
                        v_next_group := v_next_group + 1;
                    ELSIF COALESCE(v_child->'difference', v_child->'exclusion') IS NOT NULL THEN
                        v_next_group := authz._import_exclusion(v_store_id, v_type_name, v_rel_name,
                            COALESCE(v_child->'difference', v_child->'exclusion')->'base',
                            COALESCE(v_child->'difference', v_child->'exclusion')->'subtract',
                            v_next_group);
                    ELSE
                        PERFORM authz._import_rule(v_store_id, v_type_name, v_rel_name, v_child);
                    END IF;
                END LOOP;

            -- intersection -> one AND group
            ELSIF v_rel_def->'intersection' IS NOT NULL THEN
                FOR v_child IN SELECT jsonb_array_elements(v_rel_def->'intersection'->'child')
                LOOP
                    PERFORM authz._import_rule(v_store_id, v_type_name, v_rel_name, v_child,
                        v_next_group, authz._combine_and(), false);
                END LOOP;

            -- difference (OpenFGA API key) / exclusion (alias) -> exclusion group(s)
            ELSIF COALESCE(v_rel_def->'difference', v_rel_def->'exclusion') IS NOT NULL THEN
                PERFORM authz._import_exclusion(v_store_id, v_type_name, v_rel_name,
                    COALESCE(v_rel_def->'difference', v_rel_def->'exclusion')->'base',
                    COALESCE(v_rel_def->'difference', v_rel_def->'exclusion')->'subtract',
                    v_next_group);

            -- Single rule (no operator wrapper)
            ELSE
                PERFORM authz._import_rule(v_store_id, v_type_name, v_rel_name, v_rel_def);
            END IF;
        END LOOP;
    END LOOP;

    SELECT count(*) INTO v_rules_after FROM authz.models WHERE store_id = v_store_id;

    RETURN jsonb_build_object(
        'store',          p_store,
        'types',          to_jsonb(v_types),
        'relations',      to_jsonb(v_relations),
        'rules_imported', v_rules_after,
        'rules_replaced', v_rules_before,
        'type_restrictions_imported', v_type_restrictions_imported,
        'warnings',       to_jsonb(v_warnings)
    );
END;
$$;

------------------------------------------------------------------------
-- import_openfga_tuples: imports tuples from an OpenFGA JSON export.
-- Expects the format returned by the OpenFGA ReadTuples API:
--   {"tuples": [{"key": {"user": "...", "relation": "...", "object": "..."}, ...}]}
-- Parses OpenFGA colon notation: user is "type:id", "type:id#relation"
-- (userset), or "type:*" (wildcard); object is "type:id".
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz.import_openfga_tuples(
    p_store  text,
    p_tuples jsonb
) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
    v_tuple     jsonb;
    v_key       jsonb;
    v_user      text;
    v_relation  text;
    v_object    text;
    v_user_type text;
    v_user_id   text;
    v_user_rel  text;
    v_obj_type  text;
    v_obj_id    text;
    v_condition jsonb;
    v_cond_name text;
    v_cond_ctx  jsonb;
    v_count     integer := 0;
BEGIN
    FOR v_tuple IN SELECT jsonb_array_elements(p_tuples->'tuples')
    LOOP
        v_key      := v_tuple->'key';
        v_user     := v_key->>'user';
        v_relation := v_key->>'relation';
        v_object   := v_key->>'object';

        IF v_user IS NULL OR position(':' in v_user) = 0
           OR v_object IS NULL OR position(':' in v_object) = 0 THEN
            RAISE EXCEPTION 'import_openfga_tuples: user and object must use "type:id" notation, got user=%, object=%',
                v_user, v_object;
        END IF;

        -- user: "type:id", "type:id#relation", or "type:*"
        -- (split at the FIRST colon — ids may contain colons)
        v_user_type := split_part(v_user, ':', 1);
        v_user_id   := substr(v_user, length(v_user_type) + 2);
        IF position('#' in v_user_id) > 0 THEN
            v_user_rel := split_part(v_user_id, '#', 2);
            v_user_id  := split_part(v_user_id, '#', 1);
        ELSE
            v_user_rel := NULL;
        END IF;

        -- object: "type:id"
        v_obj_type := split_part(v_object, ':', 1);
        v_obj_id   := substr(v_object, length(v_obj_type) + 2);

        -- Handle condition if present
        v_condition := v_key->'condition';
        IF v_condition IS NOT NULL AND v_condition <> 'null'::jsonb THEN
            v_cond_name := v_condition->>'name';
            v_cond_ctx  := v_condition->'context';
        ELSE
            v_cond_name := NULL;
            v_cond_ctx  := NULL;
        END IF;

        PERFORM authz.write_tuple(p_store,
            v_user_type, v_user_id, v_relation, v_obj_type, v_obj_id,
            p_user_relation     => v_user_rel,
            p_condition         => v_cond_name,
            p_condition_context => v_cond_ctx);
        v_count := v_count + 1;
    END LOOP;

    RETURN v_count;
END;
$$;
