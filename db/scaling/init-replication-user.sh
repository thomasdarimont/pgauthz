#!/usr/bin/env bash
# Creates a replication user and grants replication access.
# Mounted into /docker-entrypoint-initdb.d/ so it runs on first init.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
    CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'replicator';
SQL

# Allow replication connections from the Docker network.
echo "host replication replicator all md5" >> "$PGDATA/pg_hba.conf"
