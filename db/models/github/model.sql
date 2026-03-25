-- ============================================================================
-- GitHub Permission Model — OpenFGA Import
-- ============================================================================
--
-- GitHub's repo permission hierarchy:
--
--   admin → maintainer → writer → triager → reader
--
-- Organization owners can delegate roles (repo_admin, repo_writer,
-- repo_reader) to all org members. Teams can be nested — a team's
-- members inherit the team's repo permissions.
--
-- The OpenFGA JSON model defines 4 types:
--   - user:         identity type (no relations)
--   - organization: has members, owners, and org-level repo roles
--   - team:         has members (can be nested: team members in another team)
--   - repo:         has owner (org), plus role hierarchy admin→...→reader
--
-- import_openfga_model creates the store, registers types/relations,
-- and inserts all model rules.

SELECT authz.import_openfga_model('github', '{
  "schema_version": "1.1",
  "type_definitions": [
    {
      "type": "user",
      "relations": {}
    },
    {
      "type": "organization",
      "relations": {
        "owner": {"this": {}},
        "member": {
          "union": {
            "child": [
              {"this": {}},
              {"computedUserset": {"relation": "owner"}}
            ]
          }
        },
        "repo_admin":  {"this": {}},
        "repo_reader": {"this": {}},
        "repo_writer": {"this": {}}
      }
    },
    {
      "type": "team",
      "relations": {
        "member": {"this": {}}
      }
    },
    {
      "type": "repo",
      "relations": {
        "owner": {"this": {}},
        "admin": {
          "union": {
            "child": [
              {"this": {}},
              {"tupleToUserset": {
                "tupleset":       {"relation": "owner"},
                "computedUserset": {"relation": "repo_admin"}
              }}
            ]
          }
        },
        "maintainer": {
          "union": {
            "child": [
              {"this": {}},
              {"computedUserset": {"relation": "admin"}}
            ]
          }
        },
        "writer": {
          "union": {
            "child": [
              {"this": {}},
              {"computedUserset": {"relation": "maintainer"}},
              {"tupleToUserset": {
                "tupleset":       {"relation": "owner"},
                "computedUserset": {"relation": "repo_writer"}
              }}
            ]
          }
        },
        "triager": {
          "union": {
            "child": [
              {"this": {}},
              {"computedUserset": {"relation": "writer"}}
            ]
          }
        },
        "reader": {
          "union": {
            "child": [
              {"this": {}},
              {"computedUserset": {"relation": "triager"}},
              {"tupleToUserset": {
                "tupleset":       {"relation": "owner"},
                "computedUserset": {"relation": "repo_reader"}
              }}
            ]
          }
        }
      }
    }
  ]
}'::jsonb);
