#!/usr/bin/env bash
# Creates a replication user with the permissions needed for logical replication.
# Mounted into /docker-entrypoint-initdb.d/ so it runs on first init.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
    CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'replicator';
SQL

# Logical replication needs regular connections (not just replication protocol).
echo "host all replicator all md5" >> "$PGDATA/pg_hba.conf"
