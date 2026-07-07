-- Store names are Rego package segments (authz.hooks.v1.stores.<store>.*,
-- ADR 0011). Migration 0008 restricted them to identifier syntax; this adds a
-- reserved-word blacklist: Rego keywords and the root document names parse
-- inconsistently across Rego tooling as package segments (e.g. an
-- `import data.authz.hooks.v1.stores.if` is a syntax error), so they cannot be
-- store names. Case-sensitive, matching Rego (a store named "If" is fine).
ALTER TABLE authz.stores ADD CONSTRAINT stores_name_not_reserved CHECK (
    name NOT IN (
        'as', 'contains', 'default', 'else', 'every', 'false', 'if', 'import',
        'in', 'not', 'null', 'package', 'some', 'true', 'with',
        'input', 'data'
    )
);
