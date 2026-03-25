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
    IF p_node->'exclusion' IS NOT NULL THEN
        PERFORM authz._import_register_relations(p_store_id, p_node->'exclusion'->'base');
        PERFORM authz._import_register_relations(p_store_id, p_node->'exclusion'->'subtract');
    END IF;
END;
$$;

------------------------------------------------------------------------
-- _import_rule: converts a single OpenFGA rule node into a models row.
-- Handles: this (direct), computedUserset (computed), tupleToUserset (ttu).
------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION authz._import_rule(
    p_store_id  smallint,
    p_type_name text,
    p_rel_name  text,
    p_node      jsonb
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_tupleset_rel text;
    v_computed_rel text;
BEGIN
    -- this -> direct
    IF p_node ? 'this' THEN
        INSERT INTO authz.models (store_id, object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed)
        VALUES (p_store_id, authz._t(p_store_id, p_type_name), authz._r(p_store_id, p_rel_name), authz._rel_direct(), NULL, NULL, NULL);

    -- computedUserset -> computed
    ELSIF p_node->'computedUserset' IS NOT NULL THEN
        v_computed_rel := p_node->'computedUserset'->>'relation';
        INSERT INTO authz.models (store_id, object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed)
        VALUES (p_store_id, authz._t(p_store_id, p_type_name), authz._r(p_store_id, p_rel_name), authz._rel_computed(), authz._r(p_store_id, v_computed_rel), NULL, NULL);

    -- tupleToUserset -> ttu
    ELSIF p_node->'tupleToUserset' IS NOT NULL THEN
        v_tupleset_rel := p_node->'tupleToUserset'->'tupleset'->>'relation';
        v_computed_rel := p_node->'tupleToUserset'->'computedUserset'->>'relation';
        INSERT INTO authz.models (store_id, object_type, relation, rule_type, computed_relation, tupleset_relation, tupleset_computed)
        VALUES (p_store_id, authz._t(p_store_id, p_type_name), authz._r(p_store_id, p_rel_name), authz._rel_ttu(), NULL, authz._r(p_store_id, v_tupleset_rel), authz._r(p_store_id, v_computed_rel));

    ELSE
        RAISE WARNING '_import_rule: unrecognized rule node for %.%: %',
            p_type_name, p_rel_name, p_node::text;
    END IF;
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
--          tupleToUserset (ttu), and union (multiple rules).
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

            -- Handle union: process each child
            IF v_rel_def->'union' IS NOT NULL THEN
                FOR v_child IN SELECT jsonb_array_elements(v_rel_def->'union'->'child')
                LOOP
                    PERFORM authz._import_rule(v_store_id, v_type_name, v_rel_name, v_child);
                END LOOP;

            -- Handle intersection/exclusion: not directly supported, but process children
            -- (the model will be approximate — these need manual review)
            ELSIF v_rel_def->'intersection' IS NOT NULL THEN
                v_warnings := array_append(v_warnings,
                    format('intersection on %s.%s imported as union (manual review needed)', v_type_name, v_rel_name));
                RAISE WARNING 'import_openfga_model: intersection on %.% is not natively supported — importing as union (manual review needed)',
                    v_type_name, v_rel_name;
                FOR v_child IN SELECT jsonb_array_elements(v_rel_def->'intersection'->'child')
                LOOP
                    PERFORM authz._import_rule(v_store_id, v_type_name, v_rel_name, v_child);
                END LOOP;

            ELSIF v_rel_def->'exclusion' IS NOT NULL THEN
                v_warnings := array_append(v_warnings,
                    format('exclusion on %s.%s imported base only (manual review needed)', v_type_name, v_rel_name));
                RAISE WARNING 'import_openfga_model: exclusion on %.% is not natively supported — importing base only (manual review needed)',
                    v_type_name, v_rel_name;
                PERFORM authz._import_rule(v_store_id, v_type_name, v_rel_name, v_rel_def->'exclusion'->'base');

            -- Single rule (no union wrapper)
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
-- Uses write_tuple (colon notation) internally, so user/object formats
-- like "type:id" and "type:id#relation" are supported.
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

        -- Handle condition if present
        v_condition := v_key->'condition';
        IF v_condition IS NOT NULL AND v_condition <> 'null'::jsonb THEN
            v_cond_name := v_condition->>'name';
            v_cond_ctx  := v_condition->'context';
        ELSE
            v_cond_name := NULL;
            v_cond_ctx  := NULL;
        END IF;

        PERFORM authz.write_tuple(p_store, v_user, v_relation, v_object, v_cond_name, v_cond_ctx);
        v_count := v_count + 1;
    END LOOP;

    RETURN v_count;
END;
$$;
