# ADR 0004 — Integer IDs for type and relation names

- **Status:** Accepted (foundational)
- **Date:** 2026-07-06 (recorded; the decision predates the ADR log)
- **Deciders:** maintainers

> Consolidated from `ARCHITECTURE.md` §9 into the `docs/adr/` log.

## Context

The `tuples` table is the hot path. Row size and index efficiency directly affect
performance.

## Decision

Store type and relation names as `smallint` IDs (2 bytes). The public API accepts
text and resolves it internally.

## Consequences

Significantly smaller rows and indexes. One extra lookup per API call (cached by
the buffer cache after the first call).
