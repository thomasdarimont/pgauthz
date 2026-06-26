# syntax=docker/dockerfile:1
#
# Builds the pg_cel (CEL) extension with cargo-pgrx and bakes it into the stock
# postgres image, so lang='cel' conditions can be evaluated in-database.
#
# Build from the REPOSITORY ROOT (the build context needs extensions/pg-cel):
#   docker build -f extensions/pg-cel/Dockerfile -t pgauthz-postgres-cel:18.4 .
#
# Or via the compose overlay (preferred):
#   docker compose -f compose.yml -f compose-cel.yml up -d --build
#
# Note: pg_cel is built against PGDG's postgresql-server-dev-${PG_MAJOR}, which
# shares the ABI of the official `postgres` image (also PGDG). Keep PG_MAJOR /
# POSTGRES_TAG in step with compose.yml, and PGRX_VERSION in step with the
# pgrx dependency in Cargo.toml.

ARG PG_MAJOR=18
ARG POSTGRES_TAG=18.4
ARG PGRX_VERSION=0.19.1

# ---- build stage -----------------------------------------------------------
FROM rust:1-bookworm AS build
ARG PG_MAJOR
ARG PGRX_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates gnupg lsb-release wget \
        build-essential clang libclang-dev pkg-config \
        libreadline-dev zlib1g-dev \
 && wget -qO /usr/share/keyrings/pgdg.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc \
 && echo "deb [signed-by=/usr/share/keyrings/pgdg.asc] http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list \
 && apt-get update && apt-get install -y --no-install-recommends \
        postgresql-server-dev-${PG_MAJOR} \
 && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-pgrx --version ${PGRX_VERSION} --locked

# Point pgrx at the system (PGDG) PostgreSQL so the artifact is ABI-compatible
# with the official postgres image we copy into below.
RUN cargo pgrx init --pg${PG_MAJOR} "$(which pg_config)"

COPY extensions/pg-cel /src/pg-cel
WORKDIR /src/pg-cel
RUN cargo pgrx package --pg-config "$(which pg_config)"
# Packaged layout (mirrors pg_config's install prefix):
#   target/release/pg_cel-pg${PG_MAJOR}/usr/lib/postgresql/${PG_MAJOR}/lib/pg_cel.so
#   target/release/pg_cel-pg${PG_MAJOR}/usr/share/postgresql/${PG_MAJOR}/extension/pg_cel*

# ---- runtime stage ---------------------------------------------------------
FROM postgres:${POSTGRES_TAG}
ARG PG_MAJOR

COPY --from=build \
     /src/pg-cel/target/release/pg_cel-pg${PG_MAJOR}/usr/lib/postgresql/${PG_MAJOR}/lib/pg_cel.so \
     /usr/lib/postgresql/${PG_MAJOR}/lib/
COPY --from=build \
     /src/pg-cel/target/release/pg_cel-pg${PG_MAJOR}/usr/share/postgresql/${PG_MAJOR}/extension/ \
     /usr/share/postgresql/${PG_MAJOR}/extension/

# The extension is now available; enable it per-database with
#   CREATE EXTENSION pg_cel;
# (init.sh does this automatically when the extension is present.)
