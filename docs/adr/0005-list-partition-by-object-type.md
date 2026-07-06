# ADR 0005 — LIST partitioning by object type

- **Status:** Accepted (foundational)
- **Date:** 2026-07-06 (recorded; the decision predates the ADR log)
- **Deciders:** maintainers

> Consolidated from `ARCHITECTURE.md` §9 into the `docs/adr/` log.

## Context

`check_access` always targets a specific object type. Without partitioning, every
query scans the full `tuples` table.

## Decision

LIST-partition `tuples` by `object_type`. Each type gets its own partition.
High-volume types can add HASH sub-partitioning.

## Consequences

Partition pruning ensures only the relevant type's partition is scanned. Adding a
new type requires creating a new partition (handled by `model_register_type`).
