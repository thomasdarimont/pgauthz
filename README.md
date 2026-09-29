# PostgreSQL Authorization Engine

[![CI](https://github.com/thomasdarimont/pgauthz/actions/workflows/ci.yml/badge.svg)](https://github.com/thomasdarimont/pgauthz/actions/workflows/ci.yml)

An authorization engine that lives in PostgreSQL, plus a small daemon that
puts it on the network.

The engine implements the [Google Zanzibar](https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/) /
[OpenFGA](https://openfga.dev/) relationship model — tuples, models,
conditions, temporal gates, audit and time travel — as SQL functions. An
application that shares the database authorizes with a query: no network
hop, no second data store, and filtering is a JOIN. **pgauthzd**, a
stateless Go daemon, serves the same engine over HTTP for everyone else:
[AuthZEN 1.0](docs/ARCHITECTURE.md#authzen-10-api), a native check/search/write API, JWT
validation, and an opt-in OPA sidecar for policy-as-code. Either way the
data and the decisions stay in your PostgreSQL; there is no separate
authorization database to run.

## Features

- **Relationship-based access control (ReBAC)** — Zanzibar/OpenFGA model with direct, computed, and tuple-to-userset rules
- **Wildcard tuples** — `user:*` grants a relation to all users of a type (public/anonymous access)
- **Object wildcards** — `object_id: *` grants a relation on every object of a type (superuser/auditor-style); default-deny, models opt in — see [Object Wildcards](docs/MODEL_DESIGN.md#object-wildcards-privileged-grants)
- **Intersection and exclusion** — rule groups with AND and BUT NOT semantics
- **Attribute-based access control (ABAC)** — per-tuple conditions (time windows, IP ranges, quotas) evaluated at check time, in SQL or [CEL](docs/MODEL_DESIGN.md#condition-languages-lang)
- **Relationship expiration** — `expires_at` on tuples, enforced structurally on every check and search path; time-travel-aware, garbage-collected with audit history
- **Contextual tuples** — ephemeral per-request relationships that are never persisted (VPN context, org selection)
- **Multi-store** — independent authorization namespaces with isolated types, relations, models, and tuples
- **Model registry** — named, immutable model versions shared across tenant stores: publish, canary, roll out, detect drift, dry-run applies — see [MODEL_DESIGN §16](docs/MODEL_DESIGN.md#16-sharing-one-model-across-stores-model-registry)
- **Model-as-code toolchain (`pgauthzctl`)** — OpenFGA DSL in git, CI tests with YAML fixtures, registry publish and rollout — see [`pgauthzctl/`](pgauthzctl/README.md)
- **Batch operations** — `write_tuples` / `delete_tuples` for bulk changes
- **Conditional / atomic writes** — `write_tuples_checked`: preconditions (stored-tuple `exists`/`absent`, or an access check `allowed`/`denied`: "grant only if the granter may") plus deletes and writes in one transaction (optimistic concurrency)
- **Strict revocation & per-write consistency** — acked revokes are applied on every synchronous replica (`remote_apply`), with per-write opt-down and a per-request cache bypass
- **Read-your-writes freshness tokens** — opt-in signed watermark tokens: reads are served only by replicas that caught up to your write — see [ADR 0009](docs/adr/0009-freshness-tokens.md)
- **Full audit trail** — immutable, monthly-partitioned audit log with application user tracking (`performed_by`)
- **Time-travel queries** — `audit_check_access` reconstructs permissions at any past point in time
- **Watch / changefeed** — cursored, filterable stream of tuple changes plus a `NOTIFY` doorbell, for cache invalidation and sync
- **Action log** — `record_event` / `list_events`: a per-store, per-principal record of what subjects *actually did* (reported by your PEP, never inferred from decisions) — see [ADR 0012](docs/adr/0012-action-log.md)
- **Temporal gates** — centrally managed, history-dependent veto rules over trusted recorded actions (Dogwood-inspired, not Dogwood-compatible; not a workflow engine): rate limits, spend caps, prior approval, step-up freshness, lockouts, agent guardrails (`count_within`, `sum_within`, `formerly_within`, `count_distinct_within`), applied on every check, listing, explain and time-travel path; `reserve_event` for concurrency-exact caps — see [MODEL_DESIGN §17](docs/MODEL_DESIGN.md#17-temporal-gates-history-dependent-rules)
- **Agentic authorization** — every tool call a check with the agent as principal, planning via the search API instead of policy residuals, task scope as expiring or contextual tuples, sequencing and budgets as temporal gates, delegation as data with evaluation-time attenuation, RAG authorize-before-retrieval — see [AGENTIC-AUTHORIZATION.md](docs/AGENTIC-AUTHORIZATION.md) and `examples/models/agents/`
- **Search API** — `list_objects`, `list_subjects`, `list_actions` for discovery queries
- **OpenFGA import** — import existing OpenFGA JSON models and tuples directly
- **Namespace-based access control** — per-application isolation of object types within a shared store, database-enforced end to end
- **pgauthzd front door, OPA opt-in** — one Go daemon validates JWTs and serves AuthZEN + the native API directly from PostgreSQL; OPA is an optional internal policy sidecar — see [ADR 0008](docs/adr/0008-opa-is-opt-in.md)
- **Policy hooks (OPA overlay)** — mount your own veto-only Rego rules, global or per-store, with a verified-claims actor, shared helper libraries, and hook-consistent (filtered or refused) search — see [ADR 0011](docs/adr/0011-opa-policy-hooks.md) / [`examples/opa-hooks/`](examples/opa-hooks)
- **AuthZEN 1.0 API** — the standard [AuthZEN](https://openid.net/specs/authorization-api-1_0.html) surface, multi-tenant ready: store-scoped routes, multiple trusted issuers, per-issuer store/DB-role bindings
- **Playground (web UI)** — browse stores, run access queries, and visualize the `explain_access` resolution path ([`playground/`](playground/README.md))
- **Performance** — integer IDs, LIST partitioning by object type, covering partial indexes, store-scoped index pruning

## Why PostgreSQL?

Authorization data is relational data: tuples, a small rule set, and a
recursive walk over both. Keeping it in the database you already run means
one system of record, transactions and backups you already have, checks that
are a query away for co-located applications, filtering that is a JOIN
against your own tables, and an audit log that time-travels because it is
just more rows. The long form — why not a separate service, what PostgreSQL
partitioning and indexes buy, and where the limits are — is in
[DESIGN.md → Why PostgreSQL?](docs/DESIGN.md#why-postgresql).

## Who is it for?

Primarily **enterprise platform teams** — the people who operate authorization as
shared infrastructure rather than wire it into a single application. The natural
users are:

- **IAM / authorization architects** designing the relationship model
- **central platform engineering teams** operating it as a service
- **security engineering teams** that need explainable, auditable decisions
- **PostgreSQL-focused SaaS vendors** embedding authz in a Postgres-native stack
- **regulated organisations** that must answer "who could do what, when, and why"

It is **less suited to an ordinary application team looking for a drop-in
library**. Those teams are usually better served consuming pgauthz through a
centrally operated service or an opinionated internal SDK than by running the
engine themselves.

The intended adoption model is **central operation, federated ownership**: a
platform team runs pgauthz (schema, upgrades, replication, the pgauthzd front door),
while domain teams own their authorization models and relationship data within
governed boundaries — which **multi-store** isolation and **namespace-based write
control** make enforceable rather than a matter of convention.

## Setup

```bash
cd authz/pgauthz
./bootstrap.sh
```

`bootstrap.sh` starts PostgreSQL, pgauthzd, and OPA via docker compose,
installs the engine, loads the **demo** example model, and runs all tests.

To install **only the engine** — schema, functions, OpenFGA import, audit
partitions, and security roles, with no example stores — run `./init.sh`
instead. Example models live in [`examples/`](examples/models/README.md#example-models) and are
loaded separately (see below).

## Connecting

```bash
docker exec -it $(docker compose ps -q authz-db) psql -U authz -d authz
```

## Compatibility

Versions the stack is built and tested against (the pinned versions in
`compose*.yml` / the build files). The engine is pure PL/pgSQL with no
extensions on the default path, so the only hard requirement is PostgreSQL; the
rest are the components of the reference deployment.

| Component | Version                   | Required? | Notes |
|---|---------------------------|---|---|
| **PostgreSQL** | 18.4                      | **required** | The engine. Uses partitioning, generated identity, and JSONB; developed and tested on 18.x. |
| pgauthzd | —                         | optional | Single Go daemon exposing the engine over HTTP (native `/pgauthz/v1` + AuthZEN 1.0 API); capability profiles `decision-only` (read-only DB role) / `full` (read+write); fronting OPA is the orthogonal `OPA_URL` flag (not a third profile). OPA's Rego calls back into it for reads and writes. |
| OPA | 1.18.2                    | optional | Internal policy-as-code sidecar (Rego) that only pgauthzd calls (when `OPA_URL` is set); not a client-facing entry point. |
| Go (pgauthzd) | 1.27.1                    | optional | One `pgauthzd` binary; demo services `pgauthzd-decision` / `pgauthzd-opa` / `pgauthzd-full`. |
| `sqlx-cli` | 0.9.0                     | install/upgrade | Applies the structural migrations in [`db/migrations/`](db/migrations) (tracked in `public._sqlx_migrations`). Slim Postgres-only build — `cargo install sqlx-cli --no-default-features --features rustls,postgres`. Baked into the [migration image](deploy/migrations/Dockerfile); `init*.sh` use a local install. Not needed at query time. |
| `pg_cel` extension | pgrx 0.19.2, `cel` 0.14.5 | optional | Only for `lang='cel'` conditions; built per PostgreSQL major (see [`extensions/pg-cel`](extensions/pg-cel)). |

Pre-1.0 — pin to a tag (latest in the [CHANGELOG](CHANGELOG.md) / Releases) or a
specific commit for reproducible deployments; per semver, 0.x releases may carry
breaking changes between minor versions, so review the CHANGELOG before
upgrading. See [`SECURITY.md`](SECURITY.md) for the supported line.

## A complete example

The full lifecycle in one copy-pasteable psql session — store, model, write,
check, explain, search, revoke. It is self-contained (creates its own store; no
demo fixture needed), so a fresh `./init.sh` stack is enough — connect as shown
in [Connecting](#connecting). The same example ships as loadable files under
[`examples/models/helloworld/`](examples/models/helloworld)
(`model.sql`, `seed.sql`, `demo.sql`). The tour deletes its store at the end;
if a `helloworld` store already exists (e.g. from those files), drop it first:
`SELECT authz.delete_store('helloworld', p_purge_audit => true);`

```sql
-- 1. A store: an isolated authorization namespace (tenant, app, or experiment).
SELECT authz.create_store('helloworld');

-- 2. A minimal model: documents have editors and viewers; both may read,
--    only editors may write.
SELECT authz.model_register_type('helloworld', 'user');
SELECT authz.model_register_type('helloworld', 'document');
SELECT authz.model_register_relation('helloworld', 'viewer');
SELECT authz.model_register_relation('helloworld', 'editor');
SELECT authz.model_register_relation('helloworld', 'can_read');
SELECT authz.model_register_relation('helloworld', 'can_write');

SELECT authz.model_add_rule('helloworld', 'document', 'viewer',    'direct');              -- granted by tuple
SELECT authz.model_add_rule('helloworld', 'document', 'editor',    'direct');              -- granted by tuple
SELECT authz.model_add_rule('helloworld', 'document', 'can_read',  'computed', 'viewer');  -- viewers can read
SELECT authz.model_add_rule('helloworld', 'document', 'can_read',  'computed', 'editor');  -- editors can read
SELECT authz.model_add_rule('helloworld', 'document', 'can_write', 'computed', 'editor');  -- editors can write

-- Render what we just built as OpenFGA-style DSL text:
SELECT authz.describe_model('helloworld');
--  store: helloworld
--
--  type document
--    relations
--      define can_read: viewer or editor
--      define can_write: editor
--      define editor: [any]
--      define viewer: [any]
--
--  type user

-- 3. Write relationship tuples: alice edits, bob views.
SELECT authz.write_tuple('helloworld', 'user', 'alice', 'editor', 'document', 'readme');
SELECT authz.write_tuple('helloworld', 'user', 'bob',   'viewer', 'document', 'readme');

-- 4. Check access.
SELECT authz.check_access('helloworld', 'user', 'alice', 'can_write', 'document', 'readme');
-- => true   (editor → can_write)
SELECT authz.check_access('helloworld', 'user', 'bob',   'can_read',  'document', 'readme');
-- => true   (viewer → can_read)
SELECT authz.check_access('helloworld', 'user', 'bob',   'can_write', 'document', 'readme');
-- => false  (viewers don't write)

-- 5. Explain WHY (full trace tree in the JSON; 'summary' is the short form).
SELECT authz.explain_access('helloworld', 'user', 'bob', 'can_read', 'document', 'readme')->>'summary';
--  user:bob → can_read → document:readme = ALLOWED (computed)
--    ✓ [direct_tuple] viewer on document:readme — tuple found (0.8 ms)
--  ✓ [computed] can_read on document:readme — can_read ← viewer (1.2 ms)

-- 6. Search in both directions.
SELECT * FROM authz.list_objects('helloworld', 'user', 'alice', 'can_read', 'document');
--  object_id | is_wildcard          ("which documents can alice read?")
--  readme    | f
SELECT * FROM authz.list_subjects('helloworld', 'user', 'can_read', 'document', 'readme');
--  subject_id | is_wildcard         ("who can read readme?")
--  alice      | f
--  bob        | f

-- 7. Revoke: delete the tuple, and the permission is gone.
SELECT authz.delete_tuple('helloworld', 'user', 'bob', 'viewer', 'document', 'readme');
SELECT authz.check_access('helloworld', 'user', 'bob', 'can_read', 'document', 'readme');
-- => false

-- 8. Clean up the tour store (audit history included — it's a sandbox).
SELECT authz.delete_store('helloworld', p_purge_audit => true);
```

That's the whole engine in miniature: **models** define which relations exist
and how they compose (`direct` = granted by a tuple, `computed` = implied by
another relation; [`ttu`](docs/ARCHITECTURE.md#how-check_access-resolves-permissions) walks
object-to-object references like folder→parent), **tuples** are the data, and
every read answers from the same recursive resolution. Each function —
including group/userset subjects, contextual tuples, conditions/ABAC, batch
writes and time travel — is documented in [`docs/API.md`](docs/API.md), and
richer models live in [`examples/models/`](examples/models/README.md).

## Documentation map

Each topic has exactly one owner. Read the owner, not this file, for detail.

| File | Owns | Read when … |
|---|---|---|
| [`docs/API.md`](docs/API.md) | SQL function reference + recipes | you need a signature, return shape or error |
| [`docs/MODEL_DESIGN.md`](docs/MODEL_DESIGN.md) | modelling: types, relations, rules, wildcards, conditions, gates, registry, OpenFGA import | you are writing or changing an authorization model |
| [`docs/AUDIT.md`](docs/AUDIT.md) | audit trail, time travel, changefeed | you need history, replay or change notifications |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | how it works and how it is deployed (arc42) | you are integrating, scaling or reviewing the design |
| [`docs/DESIGN.md`](docs/DESIGN.md) | why PostgreSQL, security model, performance, where permissions belong | you are evaluating the approach |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | day-to-day operations, HTTP write API, integration, debugging, repository layout | you are building against it or on it |
| [`docs/PRODUCTION.md`](docs/PRODUCTION.md) | checklist, roles, network, secrets, replicas, HA, retention, upgrades | you are going live |
| [`docs/AGENTIC-AUTHORIZATION.md`](docs/AGENTIC-AUTHORIZATION.md) | AI agents: tool calls, planning, delegation, RAG | your principal is an agent |
| [`docs/COMPARISON.md`](docs/COMPARISON.md) | feature comparison with OpenFGA | you are choosing |
| [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) | numbers, methodology, regressions found | you need latency figures |
| [`docs/SECURITY-AUDIT.md`](docs/SECURITY-AUDIT.md) | threat model, findings, hardening checklist | you are assessing risk |
| [`docs/adr/`](docs/adr) | architecture decision records | you want to know why something is the way it is |
| [`pgauthzd/README.md`](pgauthzd/README.md) | the HTTP daemon: profiles, env, AuthZEN, native API, JWT | you deploy or call pgauthzd |
| [`pgauthzctl/README.md`](pgauthzctl/README.md) | model-as-code CLI: import, test, publish, roll out | your models live in git |
| [`playground/README.md`](playground/README.md) | the web UI | you want to see a resolution path |
| [`examples/models/README.md`](examples/models/README.md) | the example models and what each shows | you want a starting point |
| [`examples/filtering/README.md`](examples/filtering/README.md) | authorization as a JOIN (data filtering) | you list what a user may see |
| [`opa/README.md`](opa/README.md) | the optional OPA overlay and policy hooks | you need policy-as-code on top |
| [`CHANGELOG.md`](CHANGELOG.md) | what changed per version | you are upgrading (read one version block, not the file) |
| [`AGENTS.md`](AGENTS.md) | conventions for coding agents and contributors | you are changing this repository |

## Guides

### SQL API

Checks (`check_access`, `check_access_with_context`, contextual tuples,
`check_access_detailed`), search (`list_objects` / `list_subjects` /
`list_actions`), `explain_access`, writes (single, batch, conditional
`write_tuples_checked`, offboarding), the audit and action-log functions —
one section each, with recipes, in [`docs/API.md`](docs/API.md).

### Modelling

Types, relations and the three rule kinds; rule groups (intersection and
exclusion); subject wildcards and privileged object wildcards; conditions in
SQL or CEL, including what happens when context is missing; temporal gates
over the action log; sharing one model across tenant stores through the
registry; importing OpenFGA models. All in
[`docs/MODEL_DESIGN.md`](docs/MODEL_DESIGN.md) — start with the
[decision guide](docs/MODEL_DESIGN.md#15-decision-guide----which-relationship-type).

### Data filtering: authorization as a JOIN

`list_objects` returns the objects a subject may act on, or the typed
wildcard row when the answer is "all of them", so a listing query joins
against it instead of checking row by row. The pattern, its cost bounds and
a runnable showcase: [`examples/filtering/`](examples/filtering/README.md).

### Audit, time travel and the changefeed

Every change is captured with the acting application user;
`audit_check_access` answers "could X do Y on Z at time T" by replaying the
log; `watch_changes` streams changes with a cursor for caches and sync.
[`docs/AUDIT.md`](docs/AUDIT.md).

### Multi-store and namespaces

A store is an isolated model plus data (one per tenant is the usual shape);
namespaces restrict which application roles may read or write which object
types within a shared store, enforced in the database. Both in
[`docs/MODEL_DESIGN.md`](docs/MODEL_DESIGN.md) (§2 and §10);
per-app role recipes in [`docs/PRODUCTION.md`](docs/PRODUCTION.md#role-recipes).

### Architecture and deployment

This section is a quick overview. For the full picture — component and
sequence diagrams, deployment scenarios, the security model, design decision
records, and PostgreSQL tuning — see **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.
See also [docs/DESIGN.md](docs/DESIGN.md) for design rationale,
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the operations/integration guide, and
[docs/PRODUCTION.md](docs/PRODUCTION.md) for the production hardening checklist
and role recipes.

```
authz.stores             Independent authorization namespaces
authz.types              Type name -> smallint ID (per store), optional namespace
authz.relations          Relation name -> smallint ID (per store)
authz.conditions         Named SQL condition expressions (per store)
authz.conditions_audit   Immutable condition-expression history (for time-travel)
authz.models             Model resolution rules (per store)
authz.models_audit       Immutable model-rule history (for time-travel)
authz.namespace_access   Namespace -> DB role grants with can_read/can_write flags
authz.tuples             Relationship tuples (per store, partitioned by object type)
authz.tuples_audit       Immutable tuple audit trail (partitioned by month)
```

How `check_access` resolves a request, the deployment topologies (co-located
SQL, pgauthzd front door, OPA overlay), the AuthZEN surface, read replicas
and the access-control roles are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (§6–§8).

### Playground

A web UI to browse stores, run access queries and visualise the
`explain_access` resolution path against the real production path:
[`playground/`](playground/README.md).

### Example models

`helloworld`, `demo`, `gdrive`, `github`, `todo`, `aia-acme`, `agents` and
`fourquestions`, each with a model, seed data and a walkthrough, most with
tests that run in CI: [`examples/models/`](examples/models/README.md).

### Comparison with OpenFGA

Model parity, what this engine adds (JOIN filtering, time travel, temporal
gates, one system of record) and what OpenFGA has that it does not (SDKs,
gRPC, a hosted service): [`docs/COMPARISON.md`](docs/COMPARISON.md).
