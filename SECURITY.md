# Security Policy

pgauthz is an authorization engine — security issues in it can translate
directly into access-control failures (a wrongful allow or a denial-of-service
on the decision path). Please treat findings accordingly and report them
privately.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

- Preferred: GitHub **private vulnerability reporting** — on the repository's
  **Security** tab, choose **“Report a vulnerability.”**
- Alternatively, email the maintainer: **security contact — _set in repo
  settings_** (replace with a monitored address before publishing).

Please include: affected component(s) and version/commit, a description, and a
minimal reproduction (SQL, model, tuples, request). We aim to acknowledge within
a few business days and to agree a coordinated disclosure timeline; please give
us a reasonable window to remediate before public disclosure.

## Supported versions

The project is pre-1.0 and does not ship backports. The supported line is the
**latest tagged release** (currently **v0.1.0**) and the **default branch
(`main`)**; fixes land on `main` and ship in the next tag. Per semver, 0.x
releases may carry breaking changes between minor versions — review the
[CHANGELOG](CHANGELOG.md) before upgrading. Pin to a tag (or a specific commit)
for reproducible deployments.

## Scope

**In scope** — anything that lets a caller obtain an authorization decision they
should not, escape an isolation boundary, or break the decision path:

- Bypassing the `SECURITY DEFINER` boundary (app roles reaching tables directly,
  or a function leaking more authority than intended).
- Escaping the condition sandbox: `lang='sql'` conditions run as the
  zero-privilege `authz_eval` role (no table/function access) — any read or write
  of data from inside a condition is a vulnerability.
- Cross-store or namespace isolation failures (reading/writing tuples for a store
  or object-type namespace the caller isn't granted).
- Privileged-grant escalation (object wildcards / `allow_object_wildcard`,
  contextual-tuple injection outside `authz_contextual_reader`).
- Incorrect resolution that yields a wrong allow/deny (model semantics,
  exclusion/intersection, conditions, time-travel).
- Tampering with the immutable audit trail.

**Out of scope / operator responsibility** — these are deployment choices the
docs call out, not engine vulnerabilities:

- Exposing the **read** PostgREST endpoint without the OPA/authenticating front
  door (it is unauthenticated by design and given no host port; see the trust
  boundary note in the README and `docs/PRODUCTION.md`).
- Granting `authz_contextual_reader`, `authz_writer`, or `authz_admin` to
  untrusted callers.
- Eventual-consistency staleness on read replicas / embedded read-only engines
  (route revocation-sensitive checks to the primary — see `docs/PRODUCTION.md`
  → *Replica consistency*).
- Operating an outdated PostgreSQL/PostgREST/OPA (see the compatibility matrix
  in the README).

## Hardening references

- README — *Access control roles*, the PostgREST trust-boundary note, and the
  *Compatibility* matrix.
- `docs/PRODUCTION.md` — production hardening checklist, role recipes, replica
  consistency.
- `docs/ARCHITECTURE.md` — security model and design decision records.
