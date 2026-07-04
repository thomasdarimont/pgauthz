-- 0004_model_registry.sql
--
-- Named, versioned model definitions shared across stores.
--
-- Multi-tenant deployments keep one store per tenant (tuples are isolated by
-- construction) but share a common authorization model. The registry stores
-- that model as a canonical, name-based JSONB definition (produced by
-- authz.export_model) under a (name, version) identity; versions are
-- immutable — updating a model means publishing the next version and rolling
-- it out with authz.apply_model (canary one tenant store, then the fleet).
--
-- store_model_state records which registry model+version a store last had
-- applied, so drift is detectable: authz.model_status re-exports the store's
-- live model and compares checksums. Stores without a state row are
-- "unmanaged" (hand-rolled models) — nothing changes for them.
--
-- Structure only — export/publish/apply/status live in idempotent engine
-- code (db/engine/model_registry.sql, write profile).

CREATE TABLE authz.model_registry (
    id          integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name        text NOT NULL,
    version     integer NOT NULL CHECK (version > 0),
    -- Canonical name-based model definition (authz.export_model format):
    -- types (namespace/description/labels/hash_modulus), relations, rules,
    -- type restrictions, conditions. No tuples, no namespace_access (role
    -- grants are deployment-specific, not part of the model).
    definition  jsonb NOT NULL,
    -- sha256 over the definition with physical-layout fields (hash_modulus)
    -- stripped — partition layout may legitimately differ per store and must
    -- not read as model drift.
    checksum    text NOT NULL,
    description text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text NOT NULL DEFAULT current_user,
    UNIQUE (name, version)
);

CREATE TABLE authz.store_model_state (
    store_id         integer PRIMARY KEY REFERENCES authz.stores(id) ON DELETE CASCADE,
    model_name       text NOT NULL,
    model_version    integer NOT NULL,
    -- Checksum of the registry version at apply time (denormalized so state
    -- stays interpretable even if registry rows are pruned later).
    applied_checksum text NOT NULL,
    applied_at       timestamptz NOT NULL DEFAULT now(),
    applied_by       text NOT NULL DEFAULT current_user,
    FOREIGN KEY (model_name, model_version)
        REFERENCES authz.model_registry (name, version)
);

COMMENT ON TABLE authz.model_registry IS
    'Named, versioned canonical model definitions (authz.export_model JSONB). '
    'Versions are immutable; publish_model appends, apply_model rolls out.';
COMMENT ON TABLE authz.store_model_state IS
    'Which registry model+version each managed store last applied. Absent row '
    '= unmanaged store. Drift detection: authz.model_status.';
