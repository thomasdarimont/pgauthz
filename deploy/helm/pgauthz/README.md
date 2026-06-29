# pgauthz Helm chart

Deploys pgauthz on Kubernetes with [CloudNativePG](https://cloudnative-pg.io/)
as the database layer. OPA is the single front door for reads **and** writes;
PostgREST (reader + writer) and PostgreSQL are internal-only and locked down
with NetworkPolicies.

```
            Ingress ──▶ OPA ──┬─reads──▶ postgrest  ─▶ CNPG -ro / pooler
                              └─writes─▶ postgrest-writer ─▶ CNPG -rw
   (optional) Ingress ──▶ authzen-direct ─▶ CNPG -ro     authzen-opa ─▶ OPA
```

## Architecture

| Component | Kind | Exposure | Notes |
|---|---|---|---|
| `…-db` | CloudNativePG `Cluster` | internal | primary `-rw`, replicas `-ro`; PITR-capable |
| `…-db-pooler-ro` | CloudNativePG `Pooler` | internal | PgBouncer over the replicas |
| `…-opa` | Deployment + HPA | **Ingress** | the only front door; JWT authn + policy |
| `…-postgrest` | Deployment + HPA | internal | reader; `api_anon`; NetworkPolicy: OPA only |
| `…-postgrest-writer` | Deployment | internal | fixed `authz_writer`; NetworkPolicy: OPA only |
| `…-authzen-direct` / `-opa` | Deployment | optional Ingress | AuthZEN 1.0 API |
| `…-migrate-N` | Job (Helm hook) | — | installs/upgrades the engine SQL |

## Prerequisites

1. **CloudNativePG operator** (cluster-scoped, install once):
   ```bash
   kubectl apply --server-side -f \
     https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.27/releases/cnpg-1.27.0.yaml
   kubectl -n cnpg-system rollout status deploy/cnpg-controller-manager
   ```
2. **Images** — the migrations + AuthZEN images are built from this repo:
   ```bash
   # from the repo root
   docker build -f deploy/migrations/Dockerfile -t pgauthz-migrations:0.1.0 .
   docker build -f authzen/Dockerfile --build-arg BINARY=authzen-direct -t pgauthz-authzen-direct:0.1.0 ./authzen
   docker build -f authzen/Dockerfile --build-arg BINARY=authzen-opa    -t pgauthz-authzen-opa:0.1.0    ./authzen
   ```
   Push them to a registry your cluster can pull from, or import into a local
   cluster (k3d shown below).

## Quick start on k3d

```bash
# 1. operator (see above), then build the three images (see above)

# 2. import the locally-built images into the k3d cluster
k3d image import pgauthz-migrations:0.1.0 pgauthz-authzen-direct:0.1.0 \
                 pgauthz-authzen-opa:0.1.0 -c <your-k3d-cluster>

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

Service-login roles (`authz_authenticator`, `authzen_direct`) are declared as
CloudNativePG **managed roles**, so their passwords come from Secrets and are
rotated by the operator; `roles.sql` still owns the privilege model (GRANTs).

## Read freshness

`postgrestReader.target` chooses where reads go: `pooler-ro` / `ro` (scale-out
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
  --set postgrestReader.target=ro       # AuthZEN-direct + the reader read the replica
```

`database.instances=N` → CNPG runs 1 primary + (N-1) replicas and exposes
`<cluster>-rw` (primary), `<cluster>-ro` (replicas only), `<cluster>-r` (any).
`postgrestReader.target` (`rw` / `ro` / `pooler-ro`) selects where both the OPA
reader **and** `authzen-direct` send reads; point it at `ro` to offload reads to
replicas. `check_access` is read-only, so it runs unmodified on a hot standby.

A few things that bite in practice (all handled by the chart, learned the hard way):

- **Role memberships must be declared in `inRoles`.** CloudNativePG owns its
  managed roles and reconciles away any membership it didn't grant — so the
  `GRANT authz_reader TO authzen_direct` that `roles.sql` issues gets stripped on
  the next reconcile, and the service starts returning 500s. The chart declares
  the memberships in `spec.managed.roles[].inRoles` so the operator maintains
  them.
- **PgBouncer + prepared statements.** Both PostgREST and the AuthZEN Go service
  (pgx) use prepared statements, which the pooler's default **transaction**
  pooling mode rejects. Either send AuthZEN straight to `-ro` (no pooler — the
  default when `target: ro`), use `poolMode: session`, or disable client-side
  prepared statements. The pooler is most useful for the high-connection
  PostgREST reader fleet, not the low-pool AuthZEN service.
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
primary on failure and **repoints the `-rw` Service**, so the migrations Job,
`postgrest-writer`, and the OPA write front door (all use `-rw`) reconnect to the
new primary transparently. PostgreSQL is single-primary: a standby is read-only
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

## Direct SQL access for applications (`extraRoles`)

Some apps need to talk to PostgreSQL directly (SQL) instead of going through the
OPA HTTP front door — e.g. a backend that calls `authz.check_access(...)` over a
JDBC/pgx connection, or a sync job that writes tuples. `authzen-direct` already
works this way; `extraRoles` lets you declare more such roles in `values.yaml`
without hand-editing the Cluster template.

**Security:** a direct DB connection bypasses OPA's JWT verification and Rego
policy, so these roles are for **trusted services that do their own
authn/authz**. Never give DB credentials to untrusted/end-user clients — route
those through OPA. Even so, the roles are confined to the `SECURITY DEFINER`
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

- Only OPA (and optionally AuthZEN) is exposed; PostgREST + Postgres are
  ClusterIP + default-deny NetworkPolicy.
- `opa.requireTokenForReads=true`, AuthZEN `ALLOW_SUBJECT_OVERRIDE=false`.
- Override `secrets.*` (dev defaults) and `opa.jwks` before real use; prefer
  `secrets.existingSecret` backed by a secret store.

## Notable values

See [`values.yaml`](values.yaml). Most-used: `database.instances`,
`database.backup.*`, `pooler.enabled`, `postgrestReader.target`,
`opa.{jwtIssuer,jwtAudience,writerRole,jwtRolesClaim,writerDbRoleClaim}`,
`authzen.*.enabled`, `ingress.*`.
