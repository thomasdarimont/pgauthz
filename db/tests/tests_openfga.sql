-- Tests for the OpenFGA import functions: model translation
-- (union, intersection, difference/exclusion, nesting limits) and
-- tuple import (type:id, type:id#relation notation).

SELECT _test_reset();

-- Import a model exercising all supported operators into 'test_ofga'.
DROP FUNCTION IF EXISTS _test_setup_ofga();
CREATE OR REPLACE FUNCTION _test_setup_ofga() RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE
    v_summary jsonb;
BEGIN
    BEGIN PERFORM authz.delete_store('test_ofga'); EXCEPTION WHEN OTHERS THEN NULL; END;

    v_summary := authz.import_openfga_model('test_ofga', '{
      "schema_version": "1.1",
      "type_definitions": [
        {"type": "user", "relations": {}},
        {"type": "group", "relations": {"member": {"this": {}}}},
        {"type": "doc", "relations": {
          "member":   {"this": {}},
          "licensed": {"this": {}},
          "blocked":  {"this": {}},
          "viewer":   {"this": {}},
          "editor":   {"this": {}},
          "can_view": {"intersection": {"child": [
              {"computedUserset": {"relation": "member"}},
              {"computedUserset": {"relation": "licensed"}}]}},
          "can_comment": {"difference": {
              "base":     {"computedUserset": {"relation": "member"}},
              "subtract": {"computedUserset": {"relation": "blocked"}}}},
          "can_read": {"difference": {
              "base": {"union": {"child": [
                  {"computedUserset": {"relation": "viewer"}},
                  {"computedUserset": {"relation": "editor"}}]}},
              "subtract": {"computedUserset": {"relation": "blocked"}}}}
        }}
      ]
    }'::jsonb);

    PERFORM authz.import_openfga_tuples('test_ofga', '{
      "tuples": [
        {"key": {"user": "user:amy",  "relation": "member",   "object": "doc:d1"}},
        {"key": {"user": "user:ben",  "relation": "member",   "object": "doc:d1"}},
        {"key": {"user": "user:ben",  "relation": "licensed", "object": "doc:d1"}},
        {"key": {"user": "user:cleo", "relation": "member",   "object": "doc:d1"}},
        {"key": {"user": "user:cleo", "relation": "blocked",  "object": "doc:d1"}},
        {"key": {"user": "user:dan",  "relation": "editor",   "object": "doc:d1"}},
        {"key": {"user": "user:eve",  "relation": "viewer",   "object": "doc:d1"}},
        {"key": {"user": "user:eve",  "relation": "blocked",  "object": "doc:d1"}},
        {"key": {"user": "group:g1#member", "relation": "viewer", "object": "doc:d1"}},
        {"key": {"user": "user:fred", "relation": "member", "object": "group:g1"}}
      ]
    }'::jsonb);

    RETURN v_summary;
END;
$$;

DROP FUNCTION IF EXISTS _test_teardown_ofga();
CREATE OR REPLACE FUNCTION _test_teardown_ofga()
RETURNS SETOF _test_results LANGUAGE plpgsql AS $$
BEGIN
    BEGIN PERFORM authz.delete_store('test_ofga'); EXCEPTION WHEN OTHERS THEN NULL; END;
    BEGIN PERFORM authz.delete_store('test_ofga_alias'); EXCEPTION WHEN OTHERS THEN NULL; END;
    BEGIN PERFORM authz.delete_store('test_ofga_bad'); EXCEPTION WHEN OTHERS THEN NULL; END;
    RETURN QUERY DELETE FROM _test_results RETURNING *;
END;
$$;

-- ofga_01..08: operators translate to rule groups with correct semantics
DO $$
DECLARE
    v_summary jsonb;
BEGIN
    v_summary := _test_setup_ofga();

    -- No "manual review" warnings: the operators are translated natively
    PERFORM _test_assert('ofga_01_no_import_warnings',
        (v_summary->'warnings')::text, '[]');

    -- intersection: member AND licensed
    PERFORM _test_assert('ofga_02_intersection_member_only_denied',
        authz.check_access('test_ofga', 'user', 'amy', 'can_view', 'doc', 'd1')::text, 'false');
    PERFORM _test_assert('ofga_03_intersection_both_allowed',
        authz.check_access('test_ofga', 'user', 'ben', 'can_view', 'doc', 'd1')::text, 'true');

    -- difference: member BUT NOT blocked
    PERFORM _test_assert('ofga_04_difference_member_allowed',
        authz.check_access('test_ofga', 'user', 'amy', 'can_comment', 'doc', 'd1')::text, 'true');
    PERFORM _test_assert('ofga_05_difference_blocked_denied',
        authz.check_access('test_ofga', 'user', 'cleo', 'can_comment', 'doc', 'd1')::text, 'false');

    -- difference with union base: (viewer OR editor) BUT NOT blocked
    PERFORM _test_assert('ofga_06_union_base_editor_allowed',
        authz.check_access('test_ofga', 'user', 'dan', 'can_read', 'doc', 'd1')::text, 'true');
    PERFORM _test_assert('ofga_07_union_base_blocked_viewer_denied',
        authz.check_access('test_ofga', 'user', 'eve', 'can_read', 'doc', 'd1')::text, 'false');

    -- tuple import: userset tuple (group:g1#member as viewer)
    PERFORM _test_assert('ofga_08_userset_tuple_grants_via_group',
        authz.check_access('test_ofga', 'user', 'fred', 'can_read', 'doc', 'd1')::text, 'true');
END;
$$;
SELECT * FROM _test_teardown_ofga();

-- ofga_09: the legacy "exclusion" key is accepted as an alias for "difference"
DO $$
BEGIN
    BEGIN PERFORM authz.delete_store('test_ofga_alias'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.import_openfga_model('test_ofga_alias', '{
      "schema_version": "1.1",
      "type_definitions": [
        {"type": "user", "relations": {}},
        {"type": "doc", "relations": {
          "member":  {"this": {}},
          "blocked": {"this": {}},
          "can_comment": {"exclusion": {
              "base":     {"computedUserset": {"relation": "member"}},
              "subtract": {"computedUserset": {"relation": "blocked"}}}}
        }}
      ]
    }'::jsonb);
    PERFORM authz.write_tuple('test_ofga_alias', 'user', 'amy', 'member', 'doc', 'd1');
    PERFORM authz.write_tuple('test_ofga_alias', 'user', 'amy', 'blocked', 'doc', 'd1');
    PERFORM _test_assert('ofga_09_exclusion_alias_blocked_denied',
        authz.check_access('test_ofga_alias', 'user', 'amy', 'can_comment', 'doc', 'd1')::text, 'false');
END;
$$;
SELECT * FROM _test_teardown_ofga();

-- ofga_10: deeper operator nesting is rejected, not imported approximately
DO $$
BEGIN
    BEGIN PERFORM authz.delete_store('test_ofga_bad'); EXCEPTION WHEN OTHERS THEN NULL; END;
    PERFORM authz.import_openfga_model('test_ofga_bad', '{
      "schema_version": "1.1",
      "type_definitions": [
        {"type": "user", "relations": {}},
        {"type": "doc", "relations": {
          "member": {"this": {}},
          "viewer": {"this": {}},
          "weird": {"intersection": {"child": [
              {"computedUserset": {"relation": "member"}},
              {"union": {"child": [{"computedUserset": {"relation": "viewer"}}]}}]}}
        }}
      ]
    }'::jsonb);
    PERFORM _test_assert_true('ofga_10_nested_operators_rejected', false, 'expected exception');
EXCEPTION WHEN raise_exception THEN
    PERFORM _test_assert_true('ofga_10_nested_operators_rejected',
        SQLERRM LIKE '%unsupported%', SQLERRM);
END;
$$;
SELECT * FROM _test_teardown_ofga();

-- Cleanup file-level functions
DROP FUNCTION IF EXISTS _test_teardown_ofga();
DROP FUNCTION IF EXISTS _test_setup_ofga();

SELECT _test_report('openfga import checks');
