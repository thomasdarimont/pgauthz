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

The engine SQL (`db/engine`, `db/openfga`, `db/security`) is baked into the
`pgauthz-migrations` image and run by a Helm `post-install,post-upgrade` hook
Job — the same SQL, same order, as `init.sh`. It is idempotent (`CREATE OR
REPLACE` functions, `IF NOT EXISTS` roles), so upgrades just re-run it. The Job
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

Three things that bite in practice (all handled by the chart, learned the hard way):

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
