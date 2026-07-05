# Security Policy

pgauthz is an authorization engine — security issues in it can translate
directly into access-control failures (a wrongful allow or a denial-of-service
on the decision path). Please treat findings accordingly and report them
privately.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

- **GitHub private vulnerability reporting** is the channel — on the
  repository's **Security** tab, choose **“Report a vulnerability.”** It opens a
  private advisory thread with the maintainers.
- If private reporting is unavailable to you, reach the maintainer via their
  GitHub profile to arrange a private channel — do **not** post details in a
  public issue or pull request.

Please include: affected component(s) and version/commit, a description, and a
minimal reproduction (SQL, model, tuples, request). We aim to acknowledge within
a few business days and to agree a coordinated disclosure timeline; please give
us a reasonable window to remediate before public disclosure.

## Supported versions

The project is pre-1.0 and does not ship backports. The supported line is the
**latest tagged release** (see the [CHANGELOG](CHANGELOG.md) / the repository's
Releases) and the **default branch (`main`)**; fixes land on `main` and ship in
the next tag. Per semver, 0.x
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

- Exposing pgauthzd's internal native callback listener (the read/write
  callback OPA calls back into) without its service token / network isolation
  (it does not re-verify the end-user JWT — it trusts the OPA sidecar — and is
  given no host port; see the trust boundary note in the README and
  `docs/PRODUCTION.md`).
- Granting `authz_contextual_reader`, `authz_writer`, or `authz_admin` to
  untrusted callers.
- Eventual-consistency staleness on read replicas / embedded read-only engines
  (route revocation-sensitive checks to the primary — see `docs/PRODUCTION.md`
  → *Replica consistency*).
- Operating an outdated PostgreSQL/pgauthzd/OPA (see the compatibility matrix
  in the README).

## Hardening references

- [`docs/SECURITY-AUDIT.md`](docs/SECURITY-AUDIT.md) — first-party security
  self-audit: threat model, the verified defense-in-depth mechanisms, findings,
  and a hardening checklist (prep for an external review).
- README — *Access control roles*, the pgauthzd callback trust-boundary note,
  and the *Compatibility* matrix.
- `docs/PRODUCTION.md` — production hardening checklist, role recipes, replica
  consistency.
- `docs/ARCHITECTURE.md` — security model and design decision records.
