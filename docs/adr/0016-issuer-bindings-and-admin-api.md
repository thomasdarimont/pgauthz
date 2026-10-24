# ADR 0016 — Issuer bindings in the database, and the admin API

- **Status:** Accepted (implemented 2026-10-23)
- **Date:** 2026-10-23
- **Deciders:** maintainers
- **Relates to:** [0007](0007-pgauthzd-front-door.md) (pgauthzd validates
  the tokens), [0014](0014-subject-assertion-policy.md) (`pep_clients`, a
  binding this ADR moves into the database), `pgauthzd/README.md` →
  Configuration and Admin API, `console/README.md` → Platform → Issuers,
  `pgauthzctl/README.md` → Issuer bindings as code,
  `docs/PRODUCTION.md` → Issuer bindings and the admin API

## Context

pgauthzd trusts identity providers through `JWT_ISSUERS`: per issuer the
**anchors** — issuer URL, audience, signing keys — and the **bindings** —
the stores its tokens may reach, the DB roles they may claim, the client
roles, the clients that may assert subjects (ADR 0014). Both lived in one
environment variable, so every binding change was a deploy of every
instance: onboarding an application to a tenant's store, pausing a
compromised identity provider, narrowing a client. The management console
needed a Platform → Issuers tab, and the stated longer-term goal is
configuration as code — Terraform, like a Keycloak realm — which needs a
privileged, token-authenticated management API in pgauthzd rather than
the console's session-bound BFF.

Two questions decided the shape: *what may move out of the environment*,
and *who may manage it in a multi-tenant fleet*.

## Decision

**Anchors stay in the environment; bindings move to the database.** Trust
(who signs tokens we accept) is the operator's, rare, deploy-time, adjacent
to secrets. What a trusted issuer's tokens may do is an authorization
decision that changes with every application onboarded. So:

- `authz.issuer_bindings` (migration 0023) holds one row per issuer:
  `stores`, `db_roles`, `client_db_roles`, `pep_clients`, `enabled`,
  `description`, `created_at/by`, `updated_at/by`; an append-only audit
  table and a revision singleton bumped and `NOTIFY`ed by trigger. SQL:
  `set_issuer_binding` / `delete_issuer_binding` (admin tier, validated as
  the daemon validates), `list_issuer_bindings` (reader),
  `list_issuer_bindings_audit` / `count_issuer_bindings_audit` (auditor).
- `ISSUERS_SOURCE=env` (default) keeps `JWT_ISSUERS` the whole truth.
  `env+db` merges a row over the environment's entry of the same issuer at
  start and on every change (poll every `ISSUERS_POLL_INTERVAL` seconds,
  `LISTEN` on a primary), swapped atomically into one immutable issuer set
  the JWT middleware and the handlers share.
- **The database can only narrow, never add trust.** A row for an issuer
  the environment does not trust is ignored; a row that unbinds or widens
  `stores` beyond the environment's patterns is rejected and logged
  (`pgauthzd_issuers_reloads_total{result="rejected"}`); on a bad row the
  set in force does not change. `enabled=false` refuses every token of an
  issuer while its trust stays configured — incident response without a
  deploy.

**A management API, off by default, scoped per tenant.**
`ADMIN_API_ENABLED=true` serves `/pgauthz/v1/admin/…` on a `full`
instance whose DB role holds `authz_admin` (`pgauthzd_admin`, asserted at
startup); with `ADMIN_LISTEN_ADDR` on its own listener, which is what
production should do (the public listener then has no `/admin/` route and
its OpenAPI document omits them — the served document stays
instance-accurate). The gate is per issuer: an `admin` binding in
`JWT_ISSUERS` (`scopes`, `claims`, `clients` a token must carry) or the
single-issuer shorthand `ADMIN_ROLE`. The database never grants
management; admin bindings are the environment's.

Management is **scoped** because a fleet trusts one identity provider per
tenant and a tenant must never see, let alone pause, another's: an admin
binding manages the issuer's own binding by default (`scope: issuer`);
`scope: platform` and `ADMIN_ROLE` reach every issuer. The read-only
`GET /pgauthz/v1/issuers` follows the same rule — a caller sees its own
issuer; the internal callback listener (OPA, the console) the whole set.
First resources: `GET /admin/issuers`, `GET|PUT|DELETE
/admin/issuer-bindings`; stores, models, conditions follow in the same
shape (PUT as upsert, read-back), so a Terraform provider can be generated
from the OpenAPI document and every console management feature gets its
endpoint here.

**Machines authenticate with certificates (added 2026-10-24).** The admin
listener can terminate mTLS (`ADMIN_TLS_CERT/KEY`, `ADMIN_CLIENT_CA`); a
verified client certificate mapped by `ADMIN_CLIENT_CERTS` (`cn`, SAN `uri`
or full `subject` → `scope`) is a credential of its own — no token — and
its identity is the recorded actor (`cert:…`). This is the credential for
CI and Terraform runners, and for bootstrap before an admin identity
provider is bound; people keep using tokens so the audit names a person.
The mapping is the environment's, like the admin bindings. Revocation is
the CA's (short-lived certificates); the public listener never accepts a
certificate as a credential. `pgauthzctl --server` uses either; the direct
database connection is kept for installation-time work and break-glass and
is on its way out for routine operations.

**Stores and models followed (2026-10-24).** `GET|PUT|DELETE
/admin/stores/{store}` (create or update as an upsert, retire, delete),
`GET|PUT …/stores/{store}/model` (the canonical definition and the managed
state; apply a registry version plan-first, 409 with the plan on
blockers), `GET /admin/models`, `POST /admin/models/{name}/versions`
(publish from a store, from a definition — `publish_model_definition`, the
model file in git — or from an OpenFGA model converted through an
ephemeral store — `publish_model_openfga`), `GET /admin/models/{name}/rollout`.
Recorder allowlists and namespace grants followed the same day as
sub-resources of a store. The tenant scope carries over: a tenant admin
reaches the stores its issuer is bound to; the registry needs platform
scope. With that,
pgauthzctl's model verbs run over the API too; `--dsn` remains for
`model import`, `model test`, installation and break-glass.

**Three ways to manage, one truth.** The console's Platform → Issuers tab
(writes through SQL as the person; reads the set in force over the
callback), the admin API (tokens of a trusted admin identity provider),
and `pgauthzctl issuers export | import --prune` (the rows as a JSON file
in git) all edit the same rows; every write lands in
`authz.issuer_bindings_audit` with its actor, and every instance applies
the next revision within its poll interval.

## Addendum (2026-10-24): the console over the admin API

With `PGAUTHZD_ADMIN_URL` the console's Platform → Issuers tab reads and
writes the bindings through the admin API instead of the engine functions,
presenting **the signed-in person's own token** — the console's OIDC client
already issues tokens pgauthzd accepts (the API audience, `subject_type`) for
the Test tab's "as me" mode — so pgauthzd's gate and tenant scoping decide
what the person sees and may change, exactly as for `pgauthzctl`; the local
admin, having no token, uses the console's client certificate (the admin
listener's mTLS). The console still gates on `platform#can_manage_issuers`
first and records every write in its action log; pgauthzd records the row's
`performed_by` from the credential. The admin API gained the history
(`GET /pgauthz/v1/admin/issuer-bindings/audit`, scoped) and the list's
`revision` for it. Without the URL the tab works as before (engine functions
+ the callback's effective set), which is what the console-local dev stack
uses — the local admin has no token and the dev stack no certificates.

## Consequences

- Onboarding, narrowing and pausing an identity provider no longer need a
  deploy; adding one still does (trust is deliberate).
- A full instance that serves the admin API runs management on a second
  pool as the admin tier (`ADMIN_DATABASE_URL`, `pgauthzd_admin`); its main
  pool stays `pgauthzd_rw`, so the decision and write paths never run with
  admin rights. Without the second pool the main pool must hold the tier.
- `ISSUERS_SOURCE=env+db` adds one poll per interval and a `LISTEN`
  connection per instance on the primary; a hot standby relies on the poll.
- The rejection of a widening row is visible to the writer only through
  the instances (logs, metric, the console's *not applied* badge, the
  callback's `binding_source`); the admin API checks the narrowing rule
  against the environment of the instance it runs on before storing, so
  a PUT a fleet would reject fails there instead of silently falling back.
- The one-issuer demo keeps working unchanged (`env`); the demo stack runs
  `env+db` with the admin API on its own port.

## Alternatives considered

- **Everything in the database, anchors included** (`ISSUERS_SOURCE=db`):
  the console admin becomes root for every store — adding an identity
  provider is adding trust. Rejected for now; `anchor_source` could be a
  later, explicitly enabled mode. `db` is refused by the configuration.
- **Environment only, console read-only:** safe but every binding change
  stays a deploy; kept as `env`, the default, and as phase 1 of this ADR.
- **Management through the console's BFF only:** session-bound, no path
  for Terraform or CI; the BFF keeps its own gate but the endpoints that
  matter for configuration as code live in pgauthzd.
- **A resource-scoped admin gate** (per endpoint family rather than per
  tenant): deferred until more admin resources exist; tenant scope was the
  property that mattered first.

## Non-goals

- Rotating or distributing signing keys; JWKS stays the identity
  provider's and the environment's.
- A dedicated engine role per management resource; the admin tier is one
  tier.
- Replacing `JWT_ISSUERS` validation at startup: the environment's
  bindings are still validated and may still be made mandatory
  (`REQUIRE_STORE_BINDING`).
