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
FROM postgres:18.4

COPY --from=sqlx-build /usr/local/cargo/bin/sqlx /usr/local/bin/sqlx

# Only the SQL the installer needs — keep the image small and auditable.
COPY db/migrations /sql/db/migrations
COPY db/engine     /sql/db/engine
COPY db/openfga    /sql/db/openfga
COPY db/security   /sql/db/security
COPY deploy/migrations/run-migrations.sh /usr/local/bin/run-migrations.sh

RUN chmod +x /usr/local/bin/run-migrations.sh

# Connection is taken entirely from libpq env (PGHOST/PGUSER/PGPASSWORD/...),
# injected by the Job from the CloudNativePG-generated secret; run-migrations.sh
# builds DATABASE_URL from them for sqlx.
ENTRYPOINT ["/usr/local/bin/run-migrations.sh"]
