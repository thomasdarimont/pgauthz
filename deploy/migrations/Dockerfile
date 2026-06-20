# pgauthz schema installer / migrator image.
#
# Bakes the canonical engine SQL (db/) into an image with psql, so a
# Kubernetes Job can install or upgrade the schema against a CloudNativePG
# cluster — the same SQL, in the same order, that init.sh runs locally.
#
# Build from the REPO ROOT so the COPY paths resolve:
#   docker build -f deploy/migrations/Dockerfile -t <registry>/pgauthz-migrations:<tag> .
#
# The image is idempotent: every public function is CREATE OR REPLACE and
# roles.sql guards every CREATE ROLE with IF NOT EXISTS, so it is safe to run
# on first install and on every upgrade.
FROM postgres:18.4

# Only the SQL the installer needs — keep the image small and auditable.
COPY db/engine   /sql/db/engine
COPY db/openfga  /sql/db/openfga
COPY db/security /sql/db/security
COPY deploy/migrations/run-migrations.sh /usr/local/bin/run-migrations.sh

RUN chmod +x /usr/local/bin/run-migrations.sh

# Connection is taken entirely from libpq env (PGHOST/PGUSER/PGPASSWORD/...),
# injected by the Job from the CloudNativePG-generated secret.
ENTRYPOINT ["/usr/local/bin/run-migrations.sh"]
