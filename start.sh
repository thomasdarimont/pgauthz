#!/usr/bin/env bash
#
# Start the full pgauthz stack (database, PostgREST, OPA, AuthZEN services).
# Builds images if needed. Waits until all services are healthy.
#
# Options:
#   --cel       Build the Postgres image with the pg_cel extension (CEL
#               conditions). Equivalent to PGAUTHZ_CEL=1; run ./init.sh after.
#   --keycloak  Also start the demo Keycloak OIDC issuer (compose-keycloak.yml)
#               and point OPA at it. Run ./keycloak/config/generate-mkcerts.sh
#               first to create the *.pgauthz.test TLS certs.
#   --playground  Also start the playground (Lit SPA + Go BFF) at
#                 https://app.pgauthz.test. Implies --keycloak; run terraform
#                 apply afterwards to provision the playground-bff client.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KEYCLOAK=0
PLAYGROUND=0
for arg in "$@"; do
  case "$arg" in
    --cel)        export PGAUTHZ_CEL=1 ;;
    --keycloak)   KEYCLOAK=1 ;;
    --playground) PLAYGROUND=1 ;;
    -h|--help)    sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done
# The playground depends on the keycloak overlay (proxy, realm, OPA).
if [ "$PLAYGROUND" = 1 ]; then KEYCLOAK=1; fi

# Compose files — base stack + optional authzen overlay
COMPOSE_FILES=(-f "$SCRIPT_DIR/compose.yml")
if [ -f "$SCRIPT_DIR/compose-authzen.yml" ]; then
  COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-authzen.yml")
fi

# Optional CEL overlay (see env.sh / extensions/pg-cel).
case "${PGAUTHZ_CEL:-}" in
  1|true|yes|on)
    COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-cel.yml")
    echo "==> CEL enabled (building pg_cel into the Postgres image)"
    ;;
esac

# Optional Keycloak demo issuer overlay (see keycloak/README.md).
if [ "$KEYCLOAK" = 1 ]; then
  certs="$SCRIPT_DIR/keycloak/config/certs"
  if [ ! -s "$certs/cert.pem" ] || [ ! -s "$certs/key.pem" ] || [ ! -s "$certs/rootCA.pem" ]; then
    echo "!! --keycloak needs TLS certs that don't exist yet." >&2
    echo "   Run ./keycloak/config/generate-mkcerts.sh first (it runs 'mkcert -install')." >&2
    exit 1
  fi
  COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-keycloak.yml")
  echo "==> Keycloak demo issuer enabled (compose-keycloak.yml)"
fi

# Optional playground overlay (Lit SPA + Go BFF; needs the keycloak overlay).
if [ "$PLAYGROUND" = 1 ]; then
  COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-playground.yml")
  echo "==> Playground enabled (compose-playground.yml)"
fi

echo "==> Starting pgauthz stack..."
docker compose "${COMPOSE_FILES[@]}" up -d --build --wait

echo "==> Stack is running."
docker compose "${COMPOSE_FILES[@]}" ps

if [ "$KEYCLOAK" = 1 ]; then
  echo ""
  echo "==> Keycloak issuer: https://id.pgauthz.test   admin: https://admin.pgauthz.test"
  echo "    Provision realm:  (cd keycloak/terraform && terraform init && terraform apply)"
  echo "    Get a token:      eval \"\$(./keycloak/get-token.sh bob)\""
fi

if [ "$PLAYGROUND" = 1 ]; then
  echo ""
  echo "==> Playground: https://app.pgauthz.test  (add app.pgauthz.test to /etc/hosts)"
  echo "    Provision the BFF client first: (cd keycloak/terraform && terraform apply)"
fi
