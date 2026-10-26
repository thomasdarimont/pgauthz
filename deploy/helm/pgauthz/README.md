# pgauthz Helm chart

Deploys pgauthz on Kubernetes with [CloudNativePG](https://cloudnative-pg.io/)
as the database layer. pgauthzd is the front door for reads **and** writes; OPA
is an internal Rego policy sidecar that only pgauthzd calls — it evaluates policy
and calls **back** into pgauthzd's native `/pgauthz/v1` API (over a
service-token-guarded callback listener) for graph data. The pgauthzd
reader/writer callbacks and PostgreSQL are internal-only and locked down with
NetworkPolicies.

```
   Ingress ──▶ pgauthzd-opa (OPA-fronted front door) ──▶ OPA (internal Rego sidecar) ──┐
               validates JWT, consults OPA                                              │ OPA calls back
                                                                                        ▼ into the callbacks
                                        ┌─reads──▶ pgauthzd-reader (decision-only) ─▶ CNPG -ro / pooler
                                        └─writes─▶ pgauthzd-writer (full)          ─▶ CNPG -rw
   (optional) …-authzen ─▶ the reader pods' AuthZEN :8080 (decision-only) ─▶ CNPG -ro
```

All three surfaces are the ONE `pgauthzd` image, capability-scoped per Deployment
by `PGAUTHORIZER_PROFILE` (`decision-only` | `full` — DB capability only); fronting
OPA is the orthogonal `OPA_URL` flag, not a third profile (the OPA gateway is a
`decision-only`/DB-less instance with `OPA_URL` set). The
decision-only reader runs two listeners in one process: the OPA callback (`:8081`)
and the AuthZEN 1.0 API (`:8080`), so there is no separate `authzen-direct`
deployment.

## Architecture

| Component | Kind | Exposure | Notes |
|---|---|---|---|
| `…-db` | CloudNativePG `Cluster` | internal | primary `-rw`, replicas `-ro`; PITR-capable |
| `…-db-pooler-ro` | CloudNativePG `Pooler` | internal | PgBouncer over the replicas |
| `…-opa` | Deployment + HPA | **Ingress** | internal Rego policy sidecar (JWT authn + policy); the OPA-fronted front consults it, and it calls back into the reader/writer callbacks |
| `…-reader` | Deployment + HPA | internal | pgauthzd `decision-only`; `authzen_direct` (read-only); native READ callback (`:8081`) + AuthZEN 1.0 API (`:8080`); NetworkPolicy: `:8081` OPA-only |
| `…-writer` | Deployment | internal | pgauthzd `full`; `pgauthzd_rw` (writer); native WRITE callback (`:8081`); NetworkPolicy: OPA only |
| `…-authzen` | Service | optional | publishes the reader pods' AuthZEN `:8080` (`authzen.direct.enabled`) |
| `…-pgauthzd-opa` | Deployment | optional Ingress | pgauthzd `decision-only`/DB-less with `OPA_URL` set (OPA-fronted AuthZEN gateway); AuthZEN 1.0 API fronting OPA (`authzen.opa.enabled`) |
| `…-migrate-N` | Job (Helm hook) | — | installs/upgrades the engine SQL |
| `…-derived-worker` | Deployment | optional, internal | `derivedRelations.enabled`: the derived-relations refresh worker (one pod, migrations image), see below |
| `…-console` | Deployment + `Database` | optional, **Ingress** `/console` | `console.enabled`: the management console (Lit SPA + Go BFF), its sessions database in the cluster, see below |

OPA reaches the callbacks via `NATIVE_URL` (reader) and `NATIVE_WRITE_URL`
(writer), authenticating with the shared `NATIVE_SERVICE_TOKEN` (matching each
instance's `INTERNAL_SERVICE_TOKEN`). For this internal callback OPA is the
trusted upstream policy sidecar — the external front door (the OPA-fronted pgauthzd)
already validated the JWT — so the callback listener does **not** re-verify it;
it trusts OPA's asserted subject (body) + per-app role (`X-PGAuthz-Role`), and is
service-token guarded and reachable only by OPA.

## Prerequisites

1. **CloudNativePG operator** (cluster-scoped, install once):
   ```bash
   kubectl apply --server-side -f \
     https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.27/releases/cnpg-1.27.0.yaml
   kubectl -n cnpg-system rollout status deploy/cnpg-controller-manager
   ```
2. **Images** — the migrations + pgauthzd images are built from this repo
   (plus the console image when `console.enabled`):
   ```bash
   # from the repo root
   docker build -f deploy/migrations/Dockerfile -t pgauthz-migrations:0.1.0 .
   docker build -f pgauthzd/Dockerfile -t pgauthz-pgauthzd:0.1.0 .
   docker build -f console/Dockerfile -t pgauthz-console:0.1.0 .
   ```
   The single `pgauthz-pgauthzd` image serves every role — the reader
   (decision-only) + AuthZEN API, the writer (full), and the OPA-fronted AuthZEN
   gateway (`decision-only`/DB-less + `OPA_URL`) — selected per Deployment by
   `PGAUTHORIZER_PROFILE` + the orthogonal `OPA_URL` flag (no `BINARY`
   build-arg). Push it to a registry your cluster can pull from, or import into a
   local cluster (k3d shown below).

## Quick start on k3d

```bash
# 1. operator (see above), then build the two images (see above)

# 2. import the locally-built images into the k3d cluster
k3d image import pgauthz-migrations:0.1.0 pgauthz-pgauthzd:0.1.0 -c <your-k3d-cluster>

# 3. install (small-footprint local profile)
./deploy/helm/pgauthz/sync-files.sh        # embed OPA policies into the chart
helm install pgauthz ./deploy/helm/pgauthz -f ./deploy/helm/pgauthz/values-k3d.yaml

# 4. watch it converge
kubectl get cluster,pods
kubectl logs -l job-name=pgauthz-migrate-1 -f

# 5. reach OPA
kubectl port-forward svc/pgauthz-opa 8181:8181
# or via Traefik: add "127.0.0.1 pgauthz.local" to /etc/hosts → http://pgauthz.local/
```

## How schema install / upgrade works

The schema SQL (`db/migrations`, `db/engine`, `db/openfga`, `db/security`) is
baked into the `pgauthz-migrations` image and run by a Helm
`post-install,post-upgrade` hook Job — the same migrate-then-load flow, same
order, as `init.sh`. Structure comes from **forward-only migrations** in
`db/migrations/`, applied by `sqlx migrate run` and tracked in
`public._sqlx_migrations` (only pending ones run); the engine code
(`db/engine`, functions/views/triggers) is idempotent (`CREATE OR REPLACE …`,
incl. `CREATE OR REPLACE TRIGGER`), and roles are `IF NOT EXISTS`. It is
**non-destructive** — no `DROP SCHEMA`, stores/tuples/audit are preserved — so
the same Job safely runs on a fresh install **and** on every upgrade
(`migrations.runOnUpgrade`, default `true`). The Job
connects to the primary as the CloudNativePG superuser (the only role that can
`CREATE ROLE` and replace functions across the schema); set
`database.enableSuperuserAccess=false` and use
`bootstrap.initdb.postInitApplicationSQLRefs` instead if your policy forbids a
superuser secret.

Service-login roles (`authzen_direct` read-only, `pgauthzd_rw` writer) are
declared as CloudNativePG **managed roles**, so their passwords come from Secrets
and are rotated by the operator; `roles.sql` still owns the privilege model
(GRANTs). The security boundary is the DB role: the reader connects as
`authzen_direct` (which physically cannot write and asserts so at startup), the
writer as `pgauthzd_rw`.

## Production profile

`deploymentEnvironment: production` (or `prod`) is forwarded to every pgauthzd
instance as `DEPLOYMENT_ENVIRONMENT` and switches on the **production
profile**: the discovery/diagnostic surfaces must be role-gated or the chart
**refuses to render** — and, as a second line, pgauthzd refuses to start —
because reverse search enumerates the access graph, explain reveals model
structure and resolution traces, and watch streams every grant/revoke:

```yaml
deploymentEnvironment: production
diagnostics:
  searchRequiredRole:  authz_auditor   # SEARCH_REQUIRED_ROLE
  explainRequiredRole: authz_auditor   # EXPLAIN_REQUIRED_ROLE
  watchRequiredRole:   authz_auditor   # WATCH_REQUIRED_ROLE (unset = watch disabled)
```

`values-production.yaml` is exactly this overlay. The runtime defaults stay
open for development and back-compat; `diagnostics.allowOpenInProduction:
true` (→ `ALLOW_OPEN_DIAGNOSTICS=true`) is the deliberately alarming override.

## Read freshness

`reader.target` chooses where reads go: `pooler-ro` / `ro` (scale-out
on replicas, accepting bounded lag) or `rw` (read-your-writes off the primary).
pgauthz deliberately has no consistency tokens — replica lag plus the OPA cache
TTL (`opa.defaultCacheTtlSeconds`) is the staleness window. Route
freshness-sensitive checks to `rw`.

## Read replicas for AuthZEN (and the reader)

CloudNativePG makes a replica a one-line change — bump the instance count and the
operator clones a hot standby and publishes a replicas-only Service:

```bash
helm upgrade pgauthz ./deploy/helm/pgauthz -f values-k3d.yaml \
  --set database.instances=2 \          # 1 primary + 1 replica
  --set reader.target=ro                # AuthZEN-direct + the reader read the replica
```

`database.instances=N` → CNPG runs 1 primary + (N-1) replicas and exposes
`<cluster>-rw` (primary), `<cluster>-ro` (replicas only), `<cluster>-r` (any).
`reader.target` (`rw` / `ro` / `pooler-ro`) selects where the pgauthzd reader
(which also serves the AuthZEN direct API) sends reads; point it at `ro` to
offload reads to replicas. `check_access` is read-only, so it runs unmodified on
a hot standby.

A few things that bite in practice (all handled by the chart, learned the hard way):

- **Role memberships must be declared in `inRoles`.** CloudNativePG owns its
  managed roles and reconciles away any membership it didn't grant — so the
  `GRANT authz_reader TO authzen_direct` that `roles.sql` issues gets stripped on
  the next reconcile, and the service starts returning 500s. The chart declares
  the memberships in `spec.managed.roles[].inRoles` so the operator maintains
  them.
- **PgBouncer + prepared statements.** The pgauthzd services (pgx) use prepared
  statements, which the pooler's default **transaction** pooling mode rejects.
  Either send reads straight to `-ro` (no pooler — the default when
  `target: ro`), use `poolMode: session`, or disable client-side prepared
  statements. The pooler is most useful for the high-connection reader fleet.
- **Read freshness.** Replicas lag the primary; pgauthz has no consistency
  tokens, so a check immediately after a write may be stale on `ro`. Route
  freshness-sensitive checks to `rw`; the staleness window is replication lag
  plus the OPA cache TTL.
- **Time-travel is primary-only — route it to `-rw`.** `audit_check_access` /
  `audit_list_actions` rebuild the as-of state into temp tables before
  resolving, so they need a *writable* transaction and fail on a hot standby
  (`-ro`) with `cannot execute CREATE TABLE in a read-only transaction`. They
  fail loudly, never silently wrong. (Live `check_access` is unaffected — its
  memo falls back to a read-only-safe backend on replicas.) If you want to
  offload forensic queries off the primary, don't promote a streaming standby
  (that forks the timeline and needs a re-clone to reattach); instead run a
  dedicated **writable logical-replication subscriber** — a full primary that
  pulls the audit data via a subscription, so its temp-table snapshot build
  works. Staleness is fine there, since time-travel reads the past. See
  [`db/replication/`](../../../db/replication/) for the logical-replication
  tooling.

## High availability & failover (the write path)

The same `instances >= 2` topology that gives you read replicas also gives you
**automatic write failover** — CloudNativePG promotes a healthy standby to
primary on failure and **repoints the `-rw` Service**, so the migrations Job and
the pgauthzd writer (both use `-rw`) reconnect to the new primary transparently. PostgreSQL is single-primary: a standby is read-only
**until promoted**, so this is failover, not active-active.

Two things to decide:

- **Clients must retry writes** during the promotion window (seconds) — see the
  retry note in
  [PRODUCTION.md → High availability & failover](../../../docs/PRODUCTION.md#high-availability--failover-the-write-path).
- **RPO** — the default is asynchronous replication (fast, but a tiny window of
  acked-but-unreplicated writes can be lost on failover). For an authorization
  store, prefer **synchronous** replication so an acked grant/revoke is never
  lost. Enable it with the `values-ha.yaml` overlay (a pure sync overlay — it
  inherits `instances` from the file it's layered on):

  ```bash
  # production base (instances: 3)
  helm upgrade pgauthz ./deploy/helm/pgauthz \
    -f deploy/helm/pgauthz/values.yaml \
    -f deploy/helm/pgauthz/values-ha.yaml      # + sync replication (RPO 0)

  # on k3d via start.sh (layers values-k3d.yaml + values-ha.yaml → instances: 2)
  HA=1 ./deploy/helm/pgauthz/start.sh
  ```

  Or directly: `--set database.replication.synchronous.enabled=true`
  (`maxSyncReplicas` must be `< database.instances`; `minSyncReplicas: 1` makes
  RPO 0 *strict*, blocking writes rather than acking un-replicated data). Pair
  with `database.backup` — failover survives node loss, backups survive
  corruption.

### Testing failover (game-day)

**One command:** [`failover-test.sh`](failover-test.sh) drives a handover and
verifies the RPO-0 guarantee end to end (sync status → probe write → trigger →
confirm it survived + the new primary is writable → cleanup):

```bash
./deploy/helm/pgauthz/failover-test.sh                 # graceful switchover (cnpg promote)
MODE=failover ./deploy/helm/pgauthz/failover-test.sh   # simulate primary loss (pod kill)
```

`MODE=switchover` (default) is non-destructive and needs the `cnpg` kubectl
plugin; `MODE=failover` needs no plugin and auto-handles the single-node-k3d
stuck-`Terminating` case. Knobs: `RELEASE`, `NAMESPACE`, `CLUSTER`, `TARGET`,
`TIMEOUT`, `KEEP=1`. The manual steps it automates are below.

> Validated live on k3d (both modes pass, RPO 0 preserved): a graceful
> **switchover completes in ~5s**, while an unplanned **failover can take a
> couple of minutes** on a freshly-built cluster — CNPG waits for WAL receivers
> to drain before electing — hence the 300s default `TIMEOUT`. Prefer
> `switchover` for routine drills.

First confirm synchronous replication is actually engaged (with `HA=1` /
`values-ha.yaml`) — `synchronous_standby_names` must be non-empty and the standby
`sync_state` should be `quorum`/`sync`:

```bash
kubectl exec pgauthz-db-1 -c postgres -- \
  psql -U postgres -d authz -tAc "SHOW synchronous_standby_names;"        # ANY 1 ("pgauthz-db-2")
kubectl exec pgauthz-db-1 -c postgres -- \
  psql -U postgres -d authz -c "SELECT application_name, sync_state FROM pg_stat_replication;"
```

**Preferred drill — planned switchover** (clean, non-destructive; uses the
`cnpg` kubectl plugin):

```bash
kubectl cnpg promote pgauthz-db pgauthz-db-2     # promote the standby; -rw repoints
kubectl get cluster pgauthz-db -w                # watch PRIMARY flip to pgauthz-db-2
```

**Unplanned-loss drill — kill the primary pod:**

```bash
kubectl delete pod pgauthz-db-1                  # CNPG promotes db-2, repoints -rw
# Verify which pod backs the writable service before/after:
kubectl get endpoints pgauthz-db-rw -o jsonpath='{.subsets[*].addresses[*].targetRef.name}'
```

Verify the **RPO 0** guarantee — a write acknowledged *before* the failover must
exist on the promoted primary, and new writes must succeed:

```bash
# before: write something through the engine on the old primary
kubectl exec pgauthz-db-1 -c postgres -- psql -U postgres -d authz -tAc \
  "SELECT authz.create_store('failover_before');"
# after promotion: it survived, and the new primary is writable
kubectl exec pgauthz-db-2 -c postgres -- psql -U postgres -d authz -tAc "SELECT pg_is_in_recovery();"  # f
kubectl exec pgauthz-db-2 -c postgres -- psql -U postgres -d authz -c "SELECT name FROM authz.stores;"  # failover_before present
kubectl exec pgauthz-db-2 -c postgres -- psql -U postgres -d authz -tAc \
  "SELECT authz.create_store('failover_after');"   # write path recovered
```

> **Single-node k3d gotcha.** Deleting the primary pod can leave it stuck
> `Terminating`, and CNPG **will not promote the standby until the old primary is
> confirmed gone** (split-brain protection) — so the cluster sits in
> `Failing over` and the standby logs
> `failed to connect to user=streaming_replica …` (a *symptom* of the wait, not a
> fault). Unblock it with `kubectl delete pod pgauthz-db-1 --grace-period=0
> --force`. On a real multi-node cluster a genuine node failure is detected
> without this; the `cnpg promote` switchover avoids the stuck-`Terminating` path
> entirely, so prefer it for routine drills.

After the drill, CNPG re-clones the old primary as a standby and the cluster
returns to a healthy `2/2` with the **roles swapped** (the old standby stays
primary) and synchronous replication re-established.

## Derived relations for application databases

[DESIGN.md → Integration patterns](../../../docs/DESIGN.md#integration-patterns-for-application-databases)
describes a precomputed `(subject, relation, object)` table that other
databases subscribe to over logical replication, instead of calling pgauthz.
The chart installs and runs it with one switch:

```yaml
derivedRelations:
  enabled: true
  stores: [demo]              # registered (initial snapshot) when the worker starts
  publication:
    enabled: true             # subscribers in other databases
```

`enabled` adds `db/replication/materialized_relations.sql` to the migration
Job (`DERIVED_RELATIONS=1`), declares the managed role
`pgauthz_derived_worker` (inheriting `authz_derived_worker`: the worker, the
registration and the status function, plus namespace bypass for the engine's
reverse expansion — nothing else), and runs **one** `…-derived-worker` pod: a
loop around `authz.refresh_materialized_relations()` from the migrations
image, connected to the primary. A grant or revoke reaches the table about
`derivedRelations.lag` (1 s) after it commits. Status:

```bash
kubectl exec pgauthz-db-1 -c postgres -- psql -U postgres -d authz   -c "SELECT * FROM authz.materialized_relations_status();"
kubectl logs deploy/pgauthz-derived-worker
```

A store listed in `stores` that does not exist yet is retried at the worker's
next start (`kubectl rollout restart deploy/pgauthz-derived-worker` after
loading it), or register by hand with
`SELECT authz.refresh_all_materialized_relations('<store>')`.

`publication.enabled` sets `wal_level=logical` (plus slots and senders — a
restart parameter, which CloudNativePG applies as a rolling restart), declares
the managed `replicator` role with the `REPLICATION` attribute (Secret
`<release>-replicator`), and the Job creates publication `authz_derived` over
the four derived tables. A subscriber is any PostgreSQL that can reach
`<release>-db-rw:5432` (in-cluster, or through a Service/LoadBalancer you add;
with `database.networkPolicy.enabled` label its pods as allowed clients):

```sql
\i db/replication/schema-derived.sql     -- the four tables + check_permission()
CREATE SUBSCRIPTION authz_derived
  CONNECTION 'host=pgauthz-db-rw port=5432 dbname=authz user=replicator password=…'
  PUBLICATION authz_derived;
```

One application's namespace only: add a row-filtered publication like
`authz_derived_dms` in `db/replication/setup-publication.sql` (by hand or via
`bootstrap.initdb.postInitApplicationSQLRefs`). Upgrading an existing
subscriber across a shape change follows
`db/replication/upgrade-derived-tables.sql`.

## The admin API (configuration as code)

The writer can serve pgauthzd's management API ([ADR 0016](../../../docs/adr/0016-issuer-bindings-and-admin-api.md)):
issuer bindings, stores and the model lifecycle for Terraform, pgauthzctl
and the console, on its own port behind a gate.

```yaml
admin:
  enabled: true
  role: pgauthz_admin                 # or per-issuer admin bindings in opa.jwtIssuers
  # machines authenticate with client certificates (mTLS), people with tokens
  tlsSecret: pgauthz-admin-tls        # kubernetes.io/tls — cert-manager issues it
  clientCASecret: pgauthz-admin-ca    # key ca.crt: the CA that signs the clients
  clientCerts:
    - { cn: terraform, scope: platform }
    - { uri: "spiffe://acme/ci/tenant-a", scope: issuer, issuer: "https://idp.tenant-a" }
```

With `admin.enabled` the writer keeps its main pool at the writer tier and
runs management on a second pool as `pgauthzd_admin` (a managed role
inheriting `authz_admin`, password `secrets.pgauthzdAdminPassword`,
`ADMIN_DATABASE_URL`), and the Service gains an `admin` port (8082); restrict it with a NetworkPolicy to the
management clients. `pgauthzctl --server https://<writer>:8082 --cert … --key
… --ca …` (or `--token`) then operates without database credentials.

## Management console

[`console/README.md`](../../../console/README.md): the web UI for the people
who run pgauthz — models, data, tests, rollout, access — whose own access is
decided by a pgauthz store. One switch:

```yaml
console:
  enabled: true
  issuer: https://id.example.com/realms/pgauthz   # your OpenID Provider
secrets:
  consoleClientSecret: "…"                       # the confidential client console-bff
```

The chart then declares two managed roles — `authz_console` (the BFF's
engine login: admin tier, contextual checks, metadata SELECT; the console
store gates it) and `console` (owner of the sessions database) — creates the
sessions database as a CloudNativePG `Database` resource in the same cluster
(`console.sessionsDatabase`, CNPG 1.25+), has the migration Job create the
console's own store once from `examples/models/console` (`console.initStore`;
it is data afterwards: never re-applied), and routes `ingress.host` +
`console.basePath` to the console pod. Register the client at your IdP with
redirect URI `<baseUrl><basePath>/auth/callback` (`baseUrl` defaults to the
ingress host). A private issuer CA goes in `console.tlsCaConfigMap` (key
`ca.crt`).

`console.providerLabel` names the sign-in button (default: the issuer's
host); `console.autoLogin: "true"` sends a signed-out visitor straight to
the provider — an internal deployment with one IdP needs no sign-in page
(the chooser stays at `<console>/?login=select` and after a sign-out).

**Without an IdP** — a first look, a test cluster — enable the local admin
sign-in instead (or in addition):

```yaml
console:
  enabled: true
  localAdmin: { user: admin, password: "…" }     # or secrets.existingSecret key console-local-admin-password
```

The person signs in as `user:admin` with the memberships in
`console.localAdmin.teams` (default `role_console_admin`, the platform admin
of the seed). Clear `user`/`password` and upgrade to deactivate it: every
local session is rejected at once. One shared password: the chart refuses
it under `deploymentEnvironment=production` unless
`console.localAdmin.allowInProduction` is set deliberately.

The console shows the writer's readiness (Settings) through the writer's
`:8080`, which the chart publishes and NetworkPolicy-restricts to the console
pods; the Test tab's "as me" mode uses the AuthZEN front door; with
`authzen.opa.enabled` the Policies tab reads OPA with the admin token.

## Direct SQL access for applications (`extraRoles`)

Some apps need to talk to PostgreSQL directly (SQL) instead of going through the
pgauthzd HTTP front door — e.g. a backend that calls `authz.check_access(...)` over a
JDBC/pgx connection, or a sync job that writes tuples. The `authzen_direct`
role already works this way; `extraRoles` lets you declare more such roles in
`values.yaml` without hand-editing the Cluster template.

**Security:** a direct DB connection bypasses the pgauthzd front door's JWT
verification and OPA's Rego policy, so these roles are for **trusted services
that do their own authn/authz**. Never give DB credentials to untrusted/end-user
clients — route those through the front door (pgauthzd). Even so, the roles are
confined to the `SECURITY DEFINER`
function API: they get `EXECUTE` on `authz.*` but **no raw table access**, so
audit, namespace enforcement and the condition sandbox still apply.

### Declare the roles

```yaml
# values.yaml
extraRoles:
  - name: reporting_app        # read-only SQL client
    access: read               # read | readwrite | audit | admin
    password: "change-me"      # chart creates a kubernetes.io/basic-auth Secret
  - name: sync_worker          # read/write client
    access: readwrite
    existingSecret: sync-worker-db   # OR reference an existing basic-auth Secret
```

Access tier → privileges (the role the app inherits):

| `access` | inherits | can call |
|---|---|---|
| `read` | `authz_reader` | `check_access`, `list_objects`, `list_subjects`, `list_actions`, `explain_access` |
| `readwrite` | `authz_writer` | the reads above **plus** `write_tuple`, `delete_tuple`, `write_tuples_*`, `delete_user_tuples` |
| `audit` | `authz_auditor` | reads + `audit_check_access`, `audit_list_*` (time-travel) |
| `admin` | `authz_admin` | writes + store/model management |

CloudNativePG creates each role at the database, sets its password from the
Secret (and rotates it on change), and **maintains the membership** (via
`inRoles`) so it isn't reconciled away. Role names may use `_` (e.g.
`reporting_app`); the generated Secret name sanitizes it to `-`.

### Connect from the app

Point the app at the right Service for its workload — **`<release>-db-ro`** for
read-only, **`<release>-db-rw`** for read/write — using the username + password
from the Secret. For the example above:

```
# reporting_app (read-only) → replicas
postgres://reporting_app:<pw>@pgauthz-db-ro:5432/authz
# in SQL: SELECT authz.check_access('store','user','alice','can_read','doc','d1');

# sync_worker (read/write) → primary
postgres://sync_worker:<pw>@pgauthz-db-rw:5432/authz
# in SQL: SELECT authz.write_tuple('store','user','alice','viewer','doc','d1');
```

The chart-created Secret is `kubernetes.io/basic-auth` named
`<release>-extrarole-<sanitized-name>` (here `pgauthz-extrarole-reporting-app`)
with `username` / `password` keys — mount it into your app or build the DSN from
it. See [`examples/rw-split/`](examples/rw-split/) for a working write-to-primary
/ read-from-replica Job using exactly this pattern.

### Optionally gate DB access (NetworkPolicy)

By default the database Service is reachable by any in-cluster pod (the role +
password is the gate). To also restrict at the network layer, enable the DB
NetworkPolicy and label your client pods:

```yaml
database:
  networkPolicy:
    enabled: true
    allowedClientSelectors:
      - matchLabels: { pgauthz.io/db-client: "true" }   # add this label to your app pods
```

It allows the chart's own components and the selectors above to reach `5432`,
and permits the CloudNativePG operator namespace + same-cluster instances on all
ports (replication/status/metrics). **Test it in your environment** — if your
CNI enforces policies on kubelet/operator traffic you may need to widen the
allow-list, which is why it's off by default.

## Security defaults (keep these)

- Only the front door (the OPA-fronted pgauthzd / OPA's policy API, and optionally
  the AuthZEN direct API) is exposed; the pgauthzd reader/writer callbacks +
  Postgres are ClusterIP + default-deny NetworkPolicy.
- `opa.requireTokenForReads=true`, AuthZEN `ALLOW_SUBJECT_OVERRIDE=false`,
  `contextualTuples: trusted-peps` (→ `CONTEXTUAL_TUPLES`; `off` to refuse
  what-if tuples on the public listeners entirely, `any` is refused in
  production).
- Override `secrets.*` (dev defaults) and `opa.jwks` before real use; prefer
  `secrets.existingSecret` backed by a secret store.

## Notable values

See [`values.yaml`](values.yaml). Most-used: `database.instances`,
`database.backup.*`, `pooler.enabled`, `reader.target`,
`opa.{jwtIssuer,jwtAudience,writerRole,jwtRolesClaim,dbRoleClaim}`,
`authzen.*.enabled`, `derivedRelations.*`, `console.*`, `ingress.*`.
