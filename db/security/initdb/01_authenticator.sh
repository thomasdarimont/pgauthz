#!/bin/bash
# Runs once on first database initialization (docker-entrypoint-initdb.d).
#
# Creates the service LOGIN roles before the services first connect — they exit
# at startup if their login role is missing, and init.sh (which loads
# db/security/roles.sql) only runs after the stack is up:
#   authz_authenticator — PostgREST connects, then SET ROLE per request
#                         (NOINHERIT; SET ROLE targets granted in roles.sql)
#   authzen_direct      — the AuthZEN Go service connects and calls the read
#                         API directly (INHERIT; granted authz_reader in
#                         roles.sql). Read-only, non-superuser.
#
# Passwords come from the environment, defaulting to the dev password 'authz'.
# Set AUTHZ_AUTHENTICATOR_PASSWORD / AUTHZEN_DIRECT_PASSWORD (e.g. via .env, see
# .env.example) for production — they must match the connection strings the
# services use (compose passes the same variables to PostgREST / AuthZEN).
set -euo pipefail

AUTH_PW="${AUTHZ_AUTHENTICATOR_PASSWORD:-authz}"
AZD_PW="${AUTHZEN_DIRECT_PASSWORD:-authz}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v authpw="$AUTH_PW" -v azdpw="$AZD_PW" <<'EOSQL'
CREATE ROLE authz_authenticator LOGIN NOINHERIT PASSWORD :'authpw';
CREATE ROLE authzen_direct       LOGIN          PASSWORD :'azdpw';
EOSQL
