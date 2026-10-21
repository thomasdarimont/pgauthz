# pgauthz schema installer / migrator image.
#
# Bakes the engine SQL (db/) plus sqlx-cli into an image with psql, so a
# Kubernetes Job can install or upgrade the schema against a CloudNativePG
# cluster — the same migrations + code that init.sh runs locally.
#
# Build from the REPO ROOT so the COPY paths resolve:
#   docker build -f deploy/migrations/Dockerfile -t <registry>/pgauthz-migrations:<tag> .
#
# Non-destructive: structural changes are forward-only migrations applied by
# sqlx (tracked in public._sqlx_migrations); the engine code is CREATE OR REPLACE
# and roles.sql guards every CREATE ROLE with IF NOT EXISTS — safe on first
# install and on every upgrade.

# ── sqlx-cli (slim, Postgres-only, rustls so no openssl dep) ────────────────
FROM rust:1-bookworm AS sqlx-build
RUN cargo install sqlx-cli --version 0.9.0 \
    --no-default-features --features rustls,postgres --locked

# ── installer image ─────────────────────────────────────────────────────────
FROM postgres:18.6

COPY --from=sqlx-build /usr/local/cargo/bin/sqlx /usr/local/bin/sqlx

# Only the SQL the installer needs — keep the image small and auditable.
COPY db/migrations /sql/db/migrations
COPY db/engine     /sql/db/engine
COPY db/openfga    /sql/db/openfga
COPY db/security   /sql/db/security
# Derived relations for application databases (opt-in at run time, see
# run-migrations.sh DERIVED_RELATIONS) and the refresh worker loop that the
# deployments run from this same image (`derived-worker.sh`).
COPY db/replication /sql/db/replication
# The management console's own authorization store (examples/models/console),
# created once by run-migrations.sh when CONSOLE_STORE_INIT=1 and it is missing.
COPY examples/models/console /sql/examples/console
COPY deploy/migrations/run-migrations.sh /usr/local/bin/run-migrations.sh
COPY db/replication/worker.sh            /usr/local/bin/derived-worker.sh

RUN chmod +x /usr/local/bin/run-migrations.sh /usr/local/bin/derived-worker.sh

# Connection is taken entirely from libpq env (PGHOST/PGUSER/PGPASSWORD/...),
# injected by the Job from the CloudNativePG-generated secret; run-migrations.sh
# builds DATABASE_URL from them for sqlx.
# The worker is the same image with `command: ["derived-worker.sh"]`.
ENTRYPOINT ["/usr/local/bin/run-migrations.sh"]
