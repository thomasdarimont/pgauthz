# ADR 0003 — SECURITY DEFINER over Row-Level Security

- **Status:** Accepted (foundational)
- **Date:** 2026-07-06 (recorded; the decision predates the ADR log)
- **Deciders:** maintainers

> Consolidated from `ARCHITECTURE.md` §9 into the `docs/adr/` log.

## Context

Application roles need to be prevented from reading or modifying authorization
tables directly.

## Decision

All public functions are `SECURITY DEFINER` (run as the schema owner). No direct
table grants to any application role. The schema owner is `authz_owner`, a
**non-superuser** role, so definer functions execute with table-ownership
privileges only — never superuser — limiting the blast radius of any flaw in the
function layer.

## Consequences

The table schema is an internal implementation detail that can change freely. RLS
is unnecessary for access control — the function layer enforces it. All writes go
through `write_tuple` / `delete_tuple`, which validate input, enforce namespaces,
and fire audit triggers.

> Note: RLS *is* used for one narrow purpose unrelated to this decision — hiding
> expired tuples (migration 0006 / SECURITY-AUDIT F11), via `BYPASSRLS`-owned
> `authz._rls_*` helpers.
