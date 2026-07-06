# ADR 0002 — Pure PostgreSQL over an external authorization service

- **Status:** Accepted (foundational)
- **Date:** 2026-07-06 (recorded; the decision predates the ADR log)
- **Deciders:** maintainers

> Consolidated from `ARCHITECTURE.md` §9 into the `docs/adr/` log.

## Context

The system needs to answer permission queries with minimal operational overhead.
External services (SpiceDB, OpenFGA) add deployment complexity, network latency,
and a separate data store to manage.

## Decision

Implement the full Zanzibar model as PL/pgSQL functions inside PostgreSQL.

## Consequences

No additional services to deploy for the core engine. Applications can call
`check_access` directly via SQL. Trade-off: no gRPC and no SDK ecosystem.
(Consistency tokens/zookies were later added — see [ADR 0009](0009-freshness-tokens.md)
and the read-your-writes discussion in `ARCHITECTURE.md` §7.)
