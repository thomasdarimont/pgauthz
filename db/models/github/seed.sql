-- ============================================================================
-- GitHub Permission Model — Seed Data
-- ============================================================================
--
-- Scenario:
--   Organization "openfga" with two teams:
--     - openfga/core    (members: charles, + nested openfga/backend)
--     - openfga/backend (members: diane)
--
--   Repo "openfga/openfga":
--     - owned by organization:openfga
--     - team openfga/core members are admins
--     - anne is a direct reader
--     - beth is a direct writer
--
--   Organization-level roles:
--     - erik is an org member
--     - all org members get repo_admin on the org
--
-- This means:
--   charles → core team member → repo admin
--   diane   → backend team member → core team member → repo admin
--   erik    → org member → org repo_admin → repo admin (via TTU)
--   anne    → direct reader only
--   beth    → direct writer → triager → reader

SELECT authz.import_openfga_tuples('github', '{
  "tuples": [
    {
      "key": {"user": "user:erik",    "relation": "member", "object": "organization:openfga"},
      "timestamp": "2023-03-16T00:35:52.673Z"
    },
    {
      "key": {"user": "organization:openfga#member", "relation": "repo_admin", "object": "organization:openfga"},
      "timestamp": "2023-03-16T00:35:52.673Z"
    },
    {
      "key": {"user": "organization:openfga", "relation": "owner", "object": "repo:openfga/openfga"},
      "timestamp": "2023-03-16T00:35:52.673Z"
    },
    {
      "key": {"user": "team:openfga/core#member", "relation": "admin", "object": "repo:openfga/openfga"},
      "timestamp": "2023-03-16T00:35:52.673Z"
    },
    {
      "key": {"user": "user:anne", "relation": "reader", "object": "repo:openfga/openfga"},
      "timestamp": "2023-03-16T00:35:52.673Z"
    },
    {
      "key": {"user": "user:beth", "relation": "writer", "object": "repo:openfga/openfga"},
      "timestamp": "2023-03-16T00:35:52.673Z"
    },
    {
      "key": {"user": "user:charles", "relation": "member", "object": "team:openfga/core"},
      "timestamp": "2023-03-16T00:35:52.673Z"
    },
    {
      "key": {"user": "team:openfga/backend#member", "relation": "member", "object": "team:openfga/core"},
      "timestamp": "2023-03-16T00:35:52.673Z"
    },
    {
      "key": {"user": "user:diane", "relation": "member", "object": "team:openfga/backend"},
      "timestamp": "2023-03-16T00:35:52.673Z"
    }
  ]
}'::jsonb) AS tuples_imported;
