#!/usr/bin/env bash
#
# Installs the pgauthz engine inside a CloudNativePG database. Mirrors init.sh's
# load order, connecting over the network via libpq env vars (PGHOST/PGUSER/...).
#
# IMPORTANT: db/engine/schema.sql begins with `DROP SCHEMA authz CASCADE`, so
# this is a full (re)install, NOT an incremental migration — running it wipes
# all stores/tuples/audit. It is wired to the chart's post-install hook only.
# Incremental schema changes need bespoke migration SQL (the engine ships a
# full-reset installer, not versioned migrations); the function/roles files are
# all idempotent (CREATE OR REPLACE / IF NOT EXISTS) and safe to re-run.
#
# The engine expects to be installed by a role named `authz` (in docker-compose
# that is POSTGRES_USER=authz, the superuser). CloudNativePG's superuser is
# `postgres`, so we connect as the CNPG superuser, ensure an `authz` superuser
# role exists, and run the install under `SET ROLE authz` in a single session —
# so SECURITY DEFINER objects are owned by `authz` and then transferred to the
# non-superuser `authz_owner` by roles.sql, exactly as in the compose install.
set -euo pipefail

SQL=/sql/db
PSQL=(psql -v ON_ERROR_STOP=1 --no-psqlrc -q)

echo "==> pgauthz install against ${PGHOST:?}:${PGPORT:-5432}/${PGDATABASE:?} as ${PGUSER:?}"

for i in $(seq 1 60); do
  if pg_isready -q; then break; fi
  echo "    waiting for database ($i)..."; sleep 2
done

echo "==> Ensuring superuser role 'authz' exists (engine install identity)..."
"${PSQL[@]}" -c "DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='authz') THEN
    CREATE ROLE authz SUPERUSER;
  END IF;
END \$\$;"

# Build the ordered file list from the engine manifest (identical to init.sh:
# the full profile = substrate + read + write + audit), then the OpenFGA import
# and security roles.
source "$SQL/engine/manifest.sh"
FILES=()
while IFS= read -r f; do
  FILES+=("$SQL/engine/$f")
done < <(engine_files_for substrate read write audit)
FILES+=(
  "$SQL/openfga/functions_openfga.sql"
  "$SQL/security/roles.sql"
)

echo "==> Installing engine (schema + functions + roles) as role authz..."
# One session so `SET ROLE authz` applies to every statement, and the trailing
# operations (audit partitions, optional knobs, schema-cache reload) run too.
{
  echo "SET ROLE authz;"
  for f in "${FILES[@]}"; do
    echo "-- >>> $f"
    cat "$f"
    echo ";"
  done
  echo "SELECT authz.ensure_audit_partitions();"
  if [ -n "${CONDITION_STATEMENT_TIMEOUT:-}" ]; then
    echo "ALTER ROLE authz_authenticator SET statement_timeout = '${CONDITION_STATEMENT_TIMEOUT}';"
    echo "ALTER ROLE authzen_direct      SET statement_timeout = '${CONDITION_STATEMENT_TIMEOUT}';"
  fi
  echo "NOTIFY pgrst, 'reload schema';"
} | "${PSQL[@]}" -f -

echo "==> pgauthz engine installed."
