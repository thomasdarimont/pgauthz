# examples/keycloak — query the demo store with real Keycloak tokens

Shows the full PEP→PDP path end to end: **Keycloak issues a JWT → OPA verifies it
and derives the subject from the claims → PostgREST → the PostgreSQL engine
(`check_access`)**. The subject is never passed in the request — it comes from the
token, exactly as a real Policy Enforcement Point would call it.

This is a usage example for the optional bundled IdP under [`keycloak/`](../../keycloak/);
real deployments point OPA's `JWT_ISSUER`/`JWKS_URL` at their own OIDC provider
and the same queries work unchanged.

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

plus `permitted_actions` for alice and `accessible_objects` (resource search) for bob.

## How it works

Each request is `POST https://api.pgauthz.test/v1/data/authz/allow` with the user
JWT in `input.token` and **no subject**:

```json
{"input":{"token":"<JWT>","action":"can_read","resource":{"type":"document","id":"doc_payroll_001"}}}
```

OPA's `authn.rego` verifies the token (issuer + audience + signature via the live
JWKS), extracts `preferred_username` → subject id and `subject_type` → subject
type, then the policy calls the engine. TLS is the mkcert cert for `*.pgauthz.test`,
verified against `keycloak/config/certs/rootCA.pem`.
