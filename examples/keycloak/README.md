# examples/keycloak — query the demo store with real Keycloak tokens

Shows the full PEP→PDP path end to end: **Keycloak issues a JWT → pgauthzd (the
AuthZEN 1.0 front door) validates it and consults its internal OPA sidecar → OPA
calls back into pgauthzd's native `/pgauthz/v1` callback → the PostgreSQL engine
(`check_access`)**. The subject is never passed in the request — pgauthzd derives
it from the token, exactly as a real Policy Enforcement Point would call it. OPA
is internal: the gateway (`api.pgauthz.test`) routes to **pgauthzd**, never to OPA.

This is a usage example for the optional bundled IdP under [`keycloak/`](../../keycloak/);
real deployments add their own OIDC provider to pgauthzd's `JWT_ISSUERS` (and
OPA's `JWKS_URL`) and the same queries work unchanged.

## Prerequisites

```bash
./keycloak/config/generate-mkcerts.sh                          # once (mkcert *.pgauthz.test)
./start.sh --keycloak                                          # stack + Keycloak (+ --cel if used)
(cd keycloak/terraform && terraform init && terraform apply)   # realm, users, mappers
# /etc/hosts: 127.0.0.1 pgauthz.test id.pgauthz.test admin.pgauthz.test api.pgauthz.test
```

The `demo` store must be loaded (it is by `./bootstrap.sh` / `tests/test.sh`).

## Run

```bash
examples/keycloak/query-demo.sh
```

Expected output (decisions derived from each user's Keycloak token):

```
SUBJECT (from JWT)         ACTION    RESOURCE                  DECISION
alice (payroll team)       can_read  document:doc_payroll_001  ALLOW
alice (payroll team)       can_read  document:doc_tax_001      DENY
eva (accounting team)      can_read  document:doc_acc_001      ALLOW
eva (accounting team)      can_read  document:doc_payroll_001  DENY
carol (client: acme)       can_read  document:doc_client_001   ALLOW
carol (client: acme)       can_read  document:doc_payroll_001  DENY
```

plus an **action search** for alice (what may she do on the doc?) and a
**resource search** for bob (which documents can he read?).

## How it works

Each request is a standard **AuthZEN 1.0** call to pgauthzd with the user JWT in
the `Authorization: Bearer` header and **no subject** in the body — e.g. an
evaluation:

```
POST https://api.pgauthz.test/access/v1/evaluation
Authorization: Bearer <JWT>

{"action":{"name":"can_read"},"resource":{"type":"document","id":"doc_payroll_001"}}
```

(action search is `/access/v1/search/action`, resource search is
`/access/v1/search/resource`.) pgauthzd validates the token (issuer + audience +
signature via the live JWKS; multi-issuer via `JWT_ISSUERS`), derives the subject
(`preferred_username` → id, `subject_type` → type), and consults OPA, whose policy
calls back into the engine. TLS is the mkcert cert for `*.pgauthz.test`, verified
against `keycloak/config/certs/rootCA.pem`.
