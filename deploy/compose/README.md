# pgauthz with Docker Compose

A deployment of pgauthz for one host: PostgreSQL (the engine) behind two
`pgauthzd` instances, a read-only one for decisions and a writer, configured
through `.env`. For Kubernetes use the [Helm chart](../helm/pgauthz/README.md).
The compose files in the repository root are the **development** stack (demo
passwords, bind mounts, published internals); this directory is meant to be
copied to a server and run as is.

```
clients ──▶ pgauthzd-decision :8080  (AuthZEN 1.0 + native reads, JWT)   ─┐
clients ──▶ pgauthzd-full     :8082  (native writes, JWT + WRITER_ROLE)  ─┼─▶ db (PostgreSQL)
            derived-worker   [profile derived]  refresh loop             ─┘
            opa + pgauthzd-opa [profile opa]     Rego in front of AuthZEN
            migrate (one-shot, idempotent, runs on every `up`)
```

## Run it

```bash
cd deploy/compose
cp .env.example .env            # passwords, your IdP's issuer / audience / JWKS
docker compose build            # pgauthz-pgauthzd + pgauthz-migrations from this checkout
docker compose up -d --wait     # migrate installs the schema first; pgauthzd waits for it
curl -s localhost:8080/readyz   # the decision instance; the writer is on :8082
```

Both instances listen on loopback by default (`READ_BIND`, `WRITE_BIND`); put
a TLS-terminating reverse proxy in front and set `TRUST_FORWARDED_HEADERS=true`
or `BASE_URL` so discovery advertises the right base. PostgreSQL is not
published at all: `docker compose exec db psql -U authz -d authz` for
administration, and the application's models load the same way
(`docker compose exec -T db psql -U authz -d authz < model.sql`).

Images come from this checkout (`docker compose build`) or from your registry:
tag them `<PGAUTHZ_IMAGE_PREFIX>-pgauthzd:<PGAUTHZ_VERSION>` and
`<PGAUTHZ_IMAGE_PREFIX>-migrations:<PGAUTHZ_VERSION>`.

### What `migrate` does

The migrations image carries the engine SQL. On every `up` it applies pending
forward-only migrations (`sqlx`, tracked in `public._sqlx_migrations`), reloads
the idempotent engine code and roles, and sets the **service-role passwords**
from `.env` (`AUTHZEN_DIRECT_PASSWORD`, `PGAUTHZD_RW_PASSWORD`, …). Change a
password in `.env` and `up` again to rotate it — the pgauthzd instances are
recreated with the new value. Nothing is dropped; stores, tuples and the audit
trail survive every run, which is what makes the upgrade below safe.

### Upgrade

```bash
# edit .env: PGAUTHZ_VERSION=<new tag>, then
docker compose build && docker compose up -d --wait
```

`migrate` brings the schema to the new version, then the instances restart on
the new image. Read the version's [CHANGELOG](../../CHANGELOG.md) block first:
pre-1.0 minors may carry breaking changes.

### Verify

```bash
docker compose run --rm --no-deps pgauthzd-decision doctor --profile production   # preflight
TOKEN=...   # a token from your IdP, or for a demo stack: ../../scripts/mint-demo-token.sh
curl -s -X POST localhost:8080/access/v1/evaluation -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"readme"}}'
```

`tests/test-deploy-compose.sh` runs exactly this deployment with the demo JWKS
and the `derived` and `console` profiles (readiness, a decision, the doctor, a
write reaching the derived table, a local-admin sign-in to the console) and
tears it down again.

## Profiles

**`derived`** — the derived-relations worker
([DESIGN.md → Integration patterns](../../docs/DESIGN.md#integration-patterns-for-application-databases)):
a precomputed `(subject, relation, object)` table other databases subscribe to.
Set `DERIVED_RELATIONS=1`, `DERIVED_WORKER_PASSWORD` and the stores to register
(`DERIVED_STORES=demo,…`) in `.env`, then

```bash
docker compose --profile derived up -d --wait
docker compose exec db psql -U authz -d authz -c "SELECT * FROM authz.materialized_relations_status();"
```

The worker is one loop around `authz.refresh_materialized_relations()` from the
migrations image (`db/replication/worker.sh`), connecting as
`pgauthz_derived_worker`. A grant or revoke reaches the table about
`WORKER_LAG` (1 s) after it commits. A store not yet registered when the worker
starts is retried at its next start, or register by hand:
`SELECT authz.refresh_all_materialized_relations('<store>')`.

To let other databases **subscribe**, layer `compose.logical.yml`: it sets
`wal_level=logical`, publishes PostgreSQL on `DB_BIND:DB_PORT`, and `migrate`
creates publication `authz_derived` plus the `replicator` role
(`REPLICATOR_PASSWORD`):

```bash
docker compose -f compose.yml -f compose.logical.yml --profile derived up -d --wait
```

On the subscriber (any PostgreSQL 16+, no pgauthz needed):

```sql
\i db/replication/schema-derived.sql      -- the four tables + check_permission()
CREATE SUBSCRIPTION authz_derived
  CONNECTION 'host=<pgauthz host> port=5432 dbname=authz user=replicator password=…'
  PUBLICATION authz_derived;
SELECT authz.check_permission('demo','internal_user','eva','can_read','document','doc_acc_001');
```

Restrict `DB_BIND` to a private interface and add TLS (`sslmode=verify-full`
in the subscription's connection string) for anything beyond a private
network; a publication is a volume boundary, not a security one.

**`console`** — the management console
([console/README.md](../../console/README.md)) at `BASE_URL/console`, behind
your reverse proxy on `CONSOLE_PORT` (8083). In `.env`: `BASE_URL`, the
sign-in — an OpenID Provider (`CONSOLE_ISSUER`, `CONSOLE_CLIENT_SECRET`;
redirect URI `<BASE_URL>/console/auth/callback`) and/or the **local admin**
(`CONSOLE_LOCAL_ADMIN_USER` + `_PASSWORD`, for a first look and tests; refused
with `DEPLOYMENT_ENVIRONMENT=production` unless
`CONSOLE_LOCAL_ADMIN_ALLOW_IN_PRODUCTION=true`) — plus
`CONSOLE_ENGINE_PASSWORD`, `CONSOLE_SESSIONS_DB` + `_PASSWORD` (a database
`migrate` creates in this instance for the BFF's sessions) and
`CONSOLE_STORE_INIT=1` (creates the console's own store once from
`examples/models/console`; it is data afterwards).

```bash
docker compose --profile console up -d --wait
```

**`opa`** — policy-as-code in front of the AuthZEN surface: the OPA sidecar and
an OPA-fronted `pgauthzd-opa` gateway on `OPA_GATEWAY_PORT` (8081). Needs
`OPA_ADMIN_TOKEN` and `NATIVE_SERVICE_TOKEN` in `.env`; the Rego policies and
OPA's JWKS are mounted from the repository's `opa/` directory
([opa/README.md](../../opa/README.md)).

## Hardening

The defaults here are already the production profile
(`DEPLOYMENT_ENVIRONMENT=production`, search and explain gated by
`authz_auditor`, the changefeed disabled, token-only subjects). The rest of the
checklist — secrets, TLS, backups, audit retention, replicas — is
[PRODUCTION.md](../../docs/PRODUCTION.md). Back up the `db-data` volume (or run
`pg_dump` / WAL archiving): the audit log is the system of record.
