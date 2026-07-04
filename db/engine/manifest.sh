#!/usr/bin/env bash
#
# Engine CODE load order, grouped by deployment profile. Single source of truth
# for the function/view/trigger files (all CREATE OR REPLACE, idempotent),
# sourced by init.sh, init-readonly.sh, deploy/migrations/run-migrations.sh, and
# db/replication/init-replication.sh.
#
# Structural DDL is NOT here — it lives in db/migrations/ and is applied by
# `sqlx migrate run` BEFORE these files load (migrations-only model; see
# docs/adr/0001-schema-migrations.md). These files re-apply on every deploy.
#
# Profiles:
#   substrate — core internals + condition evaluation. Every deployment.
#   read      — access checks, search (list_*), explain, condition validation.
#   write     — tuple / model / store / condition management + maintenance.
#   audit     — audit triggers/functions, time-travel, changefeed.
#
# Read-only deployment loads: substrate + read   (see init-readonly.sh).
# Full deployment loads:      substrate + read + write + audit (see init.sh).
#
# The list below is an authoritative, valid load order; engine_files_for
# preserves that order while filtering to the requested profiles.

ENGINE_MANIFEST=(
  "core_internal.sql:substrate"
  "conditions.sql:substrate"
  "model_constraints.sql:substrate"
  "views.sql:substrate"
  "access_internal.sql:read"
  "access.sql:read"
  "explain.sql:read"
  "store.sql:write"
  "tuples.sql:write"
  "maintenance.sql:write"
  "model.sql:write"
  "conditions_admin.sql:write"
  "model_registry.sql:write"
  "audit_triggers.sql:audit"
  "audit_internal.sql:audit"
  "audit.sql:audit"
  "watch.sql:audit"
)

# engine_files_for <profile> [<profile>...]
#   Prints the matching engine filenames, one per line, in load order.
engine_files_for() {
  local entry file prof want=" $* "
  for entry in "${ENGINE_MANIFEST[@]}"; do
    file="${entry%%:*}"
    prof="${entry##*:}"
    case "$want" in
      *" $prof "*) printf '%s\n' "$file" ;;
    esac
  done
}
