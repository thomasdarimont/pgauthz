#!/usr/bin/env bash
#
# Generate a local TLS cert for *.pgauthz.test via mkcert, for the nginx proxy
# in front of the demo Keycloak. Run once. Requires mkcert (and certutil for
# browser trust). https://github.com/FiloSottile/mkcert
#
#   ./keycloak/config/generate-mkcerts.sh
set -euo pipefail

command -v mkcert >/dev/null 2>&1 || {
  echo "!! mkcert not found — install it: https://github.com/FiloSottile/mkcert" >&2
  exit 1
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
certs="$script_dir/certs"
mkdir -p "$certs"

# Wildcard plus the loopback hostnames the proxy serves.
mkcert -cert-file "$certs/cert.pem" -key-file "$certs/key.pem" \
  '*.pgauthz.test' 'pgauthz.test' 'id.pgauthz.test' 'admin.pgauthz.test' 'api.pgauthz.test'

# Trust the mkcert root CA (system + browsers) and stage it for the Keycloak
# truststore (Keycloak must trust the proxy to reach itself via the frontend URL).
mkcert -install
cp "$(mkcert -CAROOT)/rootCA.pem" "$certs/rootCA.pem"

echo "==> wrote $certs/{cert.pem,key.pem,rootCA.pem}"
echo "    Ensure these resolve to loopback (e.g. /etc/hosts):"
echo "      127.0.0.1 pgauthz.test id.pgauthz.test admin.pgauthz.test api.pgauthz.test"
