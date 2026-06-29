#!/usr/bin/env bash
#
# Installs OR upgrades the pgauthz engine inside a CloudNativePG database.
# Mirrors init.sh's load order, connecting over the network via libpq env vars
# (PGHOST/PGUSER/...).
#
# Non-destructive: structural changes are forward-only migrations in
# db/migrations/, applied by `sqlx migrate run` (only pending ones run, tracked
# in public._sqlx_migrations); the engine function/view/trigger files and
# roles.sql are all idempotent (CREATE OR REPLACE / IF NOT EXISTS). Safe on a
# fresh database AND on an existing one — no DROP SCHEMA, no data loss — so it
# can run from the chart's install hook on every deploy.
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

# Apply structural migrations with sqlx (non-destructive: only pending
# migrations run, tracked in public._sqlx_migrations). We connect as the cluster
# superuser; the baseline's `SET LOCAL ROLE authz` makes the structural objects
# authz-owned, matching the engine code loaded below.
#
# NOTE: this CNPG path is not exercised by the local test suite — validate in a
# real CloudNativePG cluster (auth/ownership, sqlx-cli in the image).
echo "==> Applying structural migrations (sqlx)..."
DBURL="postgresql://${PGUSER}"
[ -n "${PGPASSWORD:-}" ] && DBURL="${DBURL}:${PGPASSWORD}"
DBURL="${DBURL}@${PGHOST}:${PGPORT:-5432}/${PGDATABASE}"
DATABASE_URL="$DBURL" sqlx migrate run --source "$SQL/migrations"

# Build the engine CODE list from the manifest (functions/views/triggers; the
# structure was applied above), then the OpenFGA import and security roles.
source "$SQL/engine/manifest.sh"
FILES=()
while IFS= read -r f; do
  FILES+=("$SQL/engine/$f")
done < <(engine_files_for substrate read write audit)
FILES+=(
  "$SQL/openfga/functions_openfga.sql"
  "$SQL/security/roles.sql"
)

echo "==> Loading engine code (functions + roles) as role authz..."
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
