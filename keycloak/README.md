# keycloak/ — demo OIDC issuer for pgauthz

An **opt-in** local Keycloak (26.8.1) that issues the JWTs OPA verifies, so the
"bring your own OIDC provider" story is runnable end-to-end. Real deployments
drop this entirely and point OPA's `JWT_ISSUER` / `JWKS_URL` at their own OAuth2
AS / OIDC OP. The fast self-minted test tokens (`tests/test-authzen.sh`) are
unaffected — this changes nothing about the engine or the test path.

## Layout

```
keycloak/
  themes/            → mounted to /opt/keycloak/themes   (custom login themes)
  extensions/        → mounted to /opt/keycloak/providers (SPI JARs)
  config/
    keycloak.conf            # http behind the proxy, proxy-headers, health
    .env                     # KEYCLOAK_VERSION=26.8.1, bootstrap admin, db password
    generate-mkcerts.sh      # mkcert *.pgauthz.test → certs/
    certs/                   # cert.pem/key.pem/rootCA.pem (gitignored)
    proxy/                   # nginx: TLS termination + host routing
  terraform/                 # realm, authz-api client, mappers, roles, users,
                             # pgauthz:* client scopes (scopes.pgauthz.tf: test/read/manage/admin,
                             # each carrying the client-id AND the URI audience), the ci client
  get-token.sh               # fetch a real token (password / client_credentials)
```

Provisioning is **declarative via Terraform** (`keycloak/keycloak` provider),
mirroring the `keycloak-dev-training` conventions. An nginx proxy terminates TLS
for `*.pgauthz.test` (mkcert) and routes by hostname:

| Host | Upstream |
|---|---|
| `id.pgauthz.test`, `admin.pgauthz.test` | Keycloak (issuer + admin console) |
| `api.pgauthz.test`, `pgauthz.test` | OPA (the pgauthz API front door) |

## Quick start

```bash
# 0. these must resolve to loopback (add to /etc/hosts if needed):
#    127.0.0.1 pgauthz.test id.pgauthz.test admin.pgauthz.test api.pgauthz.test

# 1. local TLS cert (once)
./keycloak/config/generate-mkcerts.sh

# 2. bring up the stack + Keycloak overlay
docker compose -f compose.yml -f compose-keycloak.yml --env-file keycloak/config/.env up -d

# 3. provision the realm (alice/bob/carol/eva, authz-api client, mappers, roles)
cd keycloak/terraform && terraform init && terraform apply && cd ../..

# 4. get a real token and call the API through the proxy
eval "$(./keycloak/get-token.sh bob)"        # bob has the writer role
curl -sk https://api.pgauthz.test/health -H "Authorization: Bearer $TOKEN"
```

Admin console: `https://admin.pgauthz.test` (admin / admin — change for anything
real). Issuer: `https://id.pgauthz.test/realms/pgauthz`.

## How OPA trusts it

`compose-keycloak.yml` sets, on the OPA service:

```
JWT_ISSUER=https://id.pgauthz.test/realms/pgauthz
JWKS_URL=http://keycloak:8080/realms/pgauthz/protocol/openid-connect/certs
JWT_ROLES_CLAIM=realm_access.roles,resource_access.authz-api.roles
WRITER_ROLE=authz_writer
```

With `JWKS_URL` set, `authn.rego` fetches the signing keys **live** (cached) from
Keycloak's certs endpoint over the internal `keycloak:8080` backchannel — so OPA
needs no mkcert-CA trust, while tokens still carry the public
`https://id.pgauthz.test` issuer. Unset `JWKS_URL` → OPA falls back to the
static `opa/data/jwks.json` (the default for tests and the no-Keycloak demo).

**Troubleshooting "everything denies".** A token whose `iss`/`aud` doesn't match
OPA's `JWT_ISSUER`/`JWT_AUDIENCE` is rejected silently (fail-closed) — a common,
hard-to-spot misconfiguration. With `TOKEN_DEBUG=true` (set in the demo overlay),
`data.authz.token_debug` explains why:

```bash
eval "$(./keycloak/get-token.sh alice)"
curl -s --cacert keycloak/config/certs/rootCA.pem \
  https://api.pgauthz.test/v1/data/authz/token_debug \
  -H 'Content-Type: application/json' -d "{\"input\":{\"token\":\"$TOKEN\"}}" | jq .result
# → per-claim issuer/audience/expiry/signature checks + a likely_cause string.
```

It decodes claims **unverified** purely to diagnose config and grants nothing —
keep it **off** (unset `TOKEN_DEBUG`) in production.

## Demo subjects

| User | subject_type | Writer role | Notes |
|---|---|---|---|
| `alice` | internal_user | — | read-only |
| `bob` | internal_user | realm role | writer via `realm_access.roles` |
| `carol` | client_user | — | client subject type |
| `eva` | internal_user | client role | writer via `resource_access.authz-api.roles` |
| `platform-admin`, `auditor`, `iam-dev`, `app-dev`, `app-secarch`, `support` | internal_user | — | console personas (`keycloak/terraform/users.console.tf`), one `console_*` realm role each — see [console/README.md](../console/README.md) |

bob and eva together exercise OPA's role aggregation across **both** claim paths.
Password for all: `password` (override `demo_user_password`).

### A tenant's realm: `acme`

[`terraform/realm.acme.tf`](terraform/realm.acme.tf) provisions a second
realm — the identity provider of the **ACME tenant**, issuer
`https://id.pgauthz.test/realms/acme` — with its own `authz-api` audience
client, the `pgauthz:*` scopes, a `console-bff` client the management
console registers as a sign-in provider, and four people (`acme-admin`,
`acme-iam`, `acme-auditor`, `acme-dev`; one realm role each, password
`password`). pgauthz trusts it as a *group issuer* of the store group
`acme`: [`examples/tenants/acme`](../examples/tenants/acme/README.md) sets
the group, its stores and models, the binding (alias `acme`) and the
people's console access up. `REALM=acme ./keycloak/get-token.sh acme-dev`
mints a token of that realm.

### App-as-a-service: the `app-dms` client

A second client, **`app-dms`**, demonstrates an application accessing data with
**no human** via the `client_credentials` grant (it has *only* that grant — no
standard/password flow). Its identity is fixed on the **client** (the app), not a
user: hardcoded claim mappers set `subject_type=service_account` and the per-app
`db_role=app_dms`. Its service account is `viewer` of `document:*` in the demo
store, so:

```bash
eval "$(./keycloak/get-token.sh --service app-dms)"   # client_credentials token
# subject_type=service_account, db_role=app_dms, aud=authz-api → can read documents
```

`examples/keycloak/query-demo.sh` ends with this exact call. The `authz-api`
client also has its own service account (`get-token.sh --service`), but it has no
`subject_type`, so — by the fail-closed rule — it is **denied** until granted one.

### Swagger UI login: `swagger-ui`

A **public** client (`terraform/client.swagger-ui.tf`) for pgauthzd's embedded
Swagger UI (`/pgauthz/v1/docs`, `SWAGGER_UI_ENABLED`): authorization code +
PKCE (S256 enforced) from the browser, redirect URIs the UI's own
`oauth2-redirect.html` on `pgauthzd-opa` (:8091, also `api.pgauthz.test`) and
`pgauthzd-full` (:8092), the `authz-api` audience and the `subject_type` claim
like every other client. The overlay points those instances at it
(`SWAGGER_UI_OIDC_ISSUER` / `SWAGGER_UI_OIDC_CLIENT_ID`), so **Authorize** in
the UI opens the Keycloak login (`alice` / `password`) instead of asking for a
pasted token.

### Agent delegation: `acme-app`, `acme_assist`, `acme-other-agent`

Three more clients (`terraform/client.agentic.tf`) back
[`examples/agentic/`](../examples/agentic/README.md), where alice lets the
**acme_assist** agent act on her behalf via Keycloak's **token-exchange
delegation** (preview in 26.8 — `compose-keycloak.yml` sets
`KC_FEATURES=token-exchange-delegation,parameterized-scopes`):

| Client | Role in the demo |
|---|---|
| `acme-app` | the app alice logs in to (device grant, **consent required**); requests `delegation:client:acme_assist` so her token carries `may_act`. Its service account is the PEP (`authz_writer` + `authz_recorder`). Also holds the **CIBA grant**: the PEP asks alice out of band for a renewed consent (`…/ext/ciba/auth`); Keycloak delivers the request over its HTTP authentication channel to the URI `compose-keycloak.yml` sets (the demo script, on the docker host) |
| `acme_assist` | the agent: service account + standard token exchange; exchanges alice's token + its own for a **delegated** token (`sub`=alice, `act.client_id`=`acme_assist`). Holds the FGAP v2 `delegate` permission on Users (`admin_permissions_enabled` on the realm) |
| `acme-other-agent` | an actor without that permission — Keycloak drops the scope / refuses the exchange |

All three stamp `subject_type=user` (the `agents` store's human type) and the
`authz-api` audience; the delegated token's claims come from the **actor**
client's mappers. pgauthzd and OPA map `act.client_id` to the principal
`agent:<client_id>` (`ACTOR_CLAIM` / `ACTOR_SUBJECT_TYPE`, set in
`compose-keycloak.yml`), so the client is named like the seeded agent.

## Per-app DB role (namespace isolation)

pgauthz can scope writes to a per-app namespace via a Postgres role that OPA
forwards from a token claim (`DB_ROLE_CLAIM`). That per-app role is a
property of the **OIDC client (the app)**, not the user — so it's modelled as a
**hardcoded claim mapper on the client**, which stamps `db_role` onto *every*
token the client issues: interactive user logins **and** the client's service
account (`client_credentials`) alike. No user attribute, no escalation surface.

To enable it for a client:

1. uncomment the `keycloak_openid_hardcoded_claim_protocol_mapper "db_role"` in
   [`terraform/client.authz-api.tf`](terraform/client.authz-api.tf) and set its
   `claim_value` to the app's namespace,
2. create a matching Postgres role with the appropriate `namespace_access`, and
3. set `DB_ROLE_CLAIM=db_role` on OPA (`compose-keycloak.yml`).

It's off in the demo because the demo store isn't namespaced (a `SET LOCAL ROLE`
to a non-existent role would fail writes). Different apps = different clients,
each with its own hardcoded `db_role` → clean per-tenant isolation, and a
service account representing an app gets the same namespace as its client.

## TLS notes

The proxy uses an mkcert cert for `*.pgauthz.test`; `mkcert -install` trusts the
local CA on your machine, so `curl` / browsers / terraform work without `-k`.
Keycloak trusts the same CA (rootCA.pem mounted into its truststore) so it can
reach itself via the frontend URL. `certs/*.pem` is gitignored — never commit it.
