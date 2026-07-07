-- Restrict store names to a Rego-safe identifier charset.
--
-- Store == tenant, and store-scoped OPA policy hooks (ADR 0011) live under the
-- Rego package `authz.hooks.v1.stores.<store>.<name>`. A Rego package segment
-- must be an identifier, so the store name IS the package segment directly —
-- which requires store names to be identifier-safe. Constraining them here
-- (rather than hashing to a canonical scope key) keeps the hook namespace
-- readable and removes an entire class of encoding bugs.
--
-- Format: ^[a-zA-Z_][a-zA-Z0-9_]*$, max 63 chars (also a valid PostgreSQL
-- identifier, and collision-free under the tuples_<store>_<type> partition
-- naming). Every existing store name already satisfies this.
ALTER TABLE authz.stores
    ADD CONSTRAINT stores_name_format
    CHECK (name ~ '^[a-zA-Z_][a-zA-Z0-9_]*$' AND length(name) <= 63);
