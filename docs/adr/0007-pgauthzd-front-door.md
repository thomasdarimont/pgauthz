# ADR 0007 — pgauthzd is the front door; OPA is an internal policy sidecar

- **Status:** Accepted
- **Date:** 2026-07-06
- **Deciders:** maintainers
- **Supersedes:** the PostgREST read/write bridge + the Nginx write gateway

> Consolidated from `ARCHITECTURE.md` §9 (was "ADR-6") into the `docs/adr/` log.

## Context

PostgREST exposed REST endpoints for all tables and leaked function signatures in
error responses (no built-in "RPC-only" mode), and it could only verify a *static*
JWK/JWKS — it could not fetch a rotating `jwks_uri`. Earlier versions placed an
Nginx reverse proxy in front of the writer that allowlisted `POST /rpc/*`. The
engine's HTTP bridge is now **pgauthzd**, a single Go daemon exposing the native
`/pgauthz/v1` API (and AuthZEN 1.0) over a pgx pool.

## Decision

Make **pgauthzd the front door** for both reads and writes, and demote OPA to an
**internal policy sidecar that only pgauthzd calls**.

- Clients speak AuthZEN 1.0 (`/access/v1`) / native `/pgauthz/v1` to pgauthzd,
  which **validates the JWT** (multi-issuer via `JWT_ISSUERS`) and resolves the
  subject + roles.
- **Reads:** a `decision-only` pgauthzd answers straight from the graph via pgx.
  An OPA-fronted pgauthzd (`OPA_URL` set) consults OPA, which re-validates the
  forwarded token (`FORWARD_TOKEN_TO_OPA`), evaluates Rego, and calls **back** into
  pgauthzd's native `/pgauthz/v1` callback (shared service token — pgauthzd
  `INTERNAL_SERVICE_TOKEN` ↔ OPA `NATIVE_SERVICE_TOKEN`, optional mTLS) for graph
  data. OPA has no independent path to the database.
- **Writes:** the pgauthzd `full`/writer instance is the write front door. It
  validates the JWT, **authorizes the write itself** by requiring the `WRITER_ROLE`
  claim (within `JWT_ROLES_CLAIM`), records the subject as audit author, and applies
  the write natively via pgx under a fixed `authz_writer` role. OPA is not on the
  native write path. (An OPA `write.rego` policy remains available as an
  *alternative* for deployments that deliberately front writes through OPA's data
  API to layer extra Rego write policy.)
- The native `/pgauthz/v1` surface is exposed on the public listener only when the
  instance is **not** fronting OPA, so the raw API can never be used to sidestep
  OPA policy.
- Fronting OPA is orthogonal to the DB-capability profile (`decision-only` |
  `full`) — it is the `OPA_URL` flag, not a separate profile (superseding the
  former `compat-opa` profile). Reader/writer separation follows the instance
  profile, not two PostgREST services.

PostgREST has been removed from the project entirely — the native `/pgauthz/v1`
callback is the only backend; there is no fallback.

## Consequences

One place — pgauthzd, the front door — owns JWT validation and `jwks_uri` /
`JWT_ISSUERS` rotation (no JWKS to sync into a separate bridge). No write endpoint
is host-exposed, and the native API is RPC-shaped by design (no table/schema
leakage) — no extra proxy container. OPA, when enabled, is reachable only by
pgauthzd. Tuple writes only — admin/model ops use a separate `authz_admin`
channel. A read-only deployment omits the `full` instance; native writes then
return 501/403.
