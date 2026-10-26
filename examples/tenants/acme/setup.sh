#!/usr/bin/env bash
# Set the ACME tenant up on a running demo stack (./start.sh --console, the
# Keycloak overlay, the example models loaded by tests/test.sh, and the realm
# provisioned: cd keycloak/terraform && terraform apply):
#   1. setup.sql — the store group, its stores and models, the group issuer
#      binding (alias acme), the console grants of its personas
#   2. seed.sql — test data: the example seeds replayed into the stores, plus
#      the tenant's people
#   3. the console's sign-in registration at the realm (what Platform →
#      Issuers → "Console sign-in through this provider" writes): the
#      console-bff client of the ACME realm, its secret from terraform
# Idempotent. The sign-in page then offers "Sign in with ACME".
set -euo pipefail
cd "$(dirname "$0")/../../.."

# The engine database and the console's own database, as the demo stack
# names them (docker exec: no host ports, no env.sh side effects).
authz_db="${AUTHZ_DB_CONTAINER:-pgauthz-authz-db-1}"
console_db="${CONSOLE_DB_CONTAINER:-pgauthz-console-db-1}"

echo "==> ACME: store group, stores, models, group issuer, console grants (setup.sql)"
docker exec -i "$authz_db" psql -U authz -d authz -v ON_ERROR_STOP=1 -q < examples/tenants/acme/setup.sql

echo "==> ACME: test data — the example seeds replayed into the tenant's stores, plus its people (seed.sql)"
docker exec -i "$authz_db" psql -U authz -d authz -v ON_ERROR_STOP=1 -q < examples/tenants/acme/seed.sql

secret="${ACME_CONSOLE_BFF_CLIENT_SECRET:-}"
if [ -z "$secret" ] && [ -d keycloak/terraform/.terraform ]; then
  secret="$(cd keycloak/terraform && terraform output -raw acme_console_bff_client_secret 2>/dev/null || true)"
fi
secret="${secret:-acme-console-bff-demo-secret}"
echo "==> ACME: the console's sign-in registration (console_providers in $console_db)"
docker exec -i "$console_db" psql -U console -d pgauthz_console -v ON_ERROR_STOP=1 -q <<SQL
INSERT INTO console_providers (issuer, label, store_group, client_id, client_secret, enabled, auto_login, created_by, updated_by)
VALUES ('https://id.pgauthz.test/realms/acme', 'ACME', 'acme', 'console-bff', '$secret', true, false, 'examples/tenants/acme', 'examples/tenants/acme')
ON CONFLICT (issuer) DO UPDATE SET label = EXCLUDED.label, store_group = EXCLUDED.store_group, client_id = EXCLUDED.client_id,
    client_secret = EXCLUDED.client_secret, enabled = true, updated_at = now(), updated_by = EXCLUDED.updated_by;
SQL
echo "==> ACME is set up: https://app.pgauthz.test/console/?login=acme (acme-admin / acme-iam / acme-auditor / acme-dev, password 'password')"
