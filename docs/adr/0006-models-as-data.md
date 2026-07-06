# ADR 0006 — Models as data, not schema

- **Status:** Accepted (foundational)
- **Date:** 2026-07-06 (recorded; the decision predates the ADR log)
- **Deciders:** maintainers

> Consolidated from `ARCHITECTURE.md` §9 into the `docs/adr/` log.

## Context

Authorization models evolve over time. Schema-based changes require migrations
and downtime.

## Decision

Store model rules as rows in `authz.models`. Model changes are INSERT/DELETE
operations that take effect immediately.

## Consequences

No schema migrations for model changes. The model table has a primary key and
unique index, enabling both full replacement (`import_openfga_model`) and
incremental updates (`model_add_rule`, `model_remove_rule`). Full replacement is
transactional — PostgreSQL MVCC ensures concurrent readers see either the complete
old model or the complete new model, with no denial window.
