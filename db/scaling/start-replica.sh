#!/usr/bin/env bash
# Initializes the replica from the primary using pg_basebackup,
# then starts PostgreSQL in hot_standby mode.
set -e

PGDATA=/var/lib/postgresql/data

# Only run pg_basebackup if the data directory is empty (first start).
if [ ! -s "$PGDATA/PG_VERSION" ]; then
    echo "==> Taking base backup from primary..."
    rm -rf "$PGDATA"/*

    pg_basebackup \
        --host=authz-primary \
        --port=5432 \
        --username=replicator \
        --pgdata="$PGDATA" \
        --wal-method=stream \
        --write-recovery-conf \
        --checkpoint=fast

    # Ensure hot_standby is enabled, and pin the parameters a standby requires
    # to be >= the primary. The primary sets these via -c flags (not in the
    # replicated postgresql.conf), so a standby started with defaults would
    # FATAL: "max_connections = 100 is a lower setting than on the primary,
    # where its value was 250". Keep these in sync with compose-scaling.yml.
    cat >> "$PGDATA/postgresql.auto.conf" <<-CONF
	hot_standby = on
	max_connections = 250
	CONF

    chown -R postgres:postgres "$PGDATA"
    chmod 700 "$PGDATA"
fi

echo "==> Starting replica..."
exec gosu postgres postgres -D "$PGDATA"
