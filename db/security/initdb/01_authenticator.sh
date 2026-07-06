#!/bin/bash
# Runs once on first database initialization (docker-entrypoint-initdb.d).
#
# Creates the pgauthzd service LOGIN roles before the services first connect —
# they exit at startup if their login role is missing, and init.sh (which loads
# db/security/roles.sql) only runs after the stack is up:
#   authzen_direct — pgauthzd decision-only connects and calls the read API
#                    directly (INHERITs authz_reader in roles.sql). Read-only.
#   pgauthzd_rw    — pgauthzd full connects for the read+write path (INHERITs
#                    authz_writer in roles.sql). Only the full instance uses it.
#
# Passwords come from the environment, defaulting to the dev password 'authz'.
# Set AUTHZEN_DIRECT_PASSWORD / PGAUTHZD_RW_PASSWORD (e.g. via .env, see
# .env.example) for production — they must match the DATABASE_URLs the pgauthzd
# instances connect with (compose passes the same variables through).
set -euo pipefail

AZD_PW="${AUTHZEN_DIRECT_PASSWORD:-authz}"
RW_PW="${PGAUTHZD_RW_PASSWORD:-authz}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v azdpw="$AZD_PW" -v rwpw="$RW_PW" <<'EOSQL'
CREATE ROLE authzen_direct LOGIN PASSWORD :'azdpw';
CREATE ROLE pgauthzd_rw    LOGIN PASSWORD :'rwpw';
EOSQL
