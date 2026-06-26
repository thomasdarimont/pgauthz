#!/usr/bin/env bash
#
# Engine file load order, grouped by deployment profile. Single source of truth
# for which SQL files make up the engine, sourced by init.sh, init-readonly.sh,
# and db/replication/init-replication.sh.
#
# Profiles:
#   substrate — DDL (read tables, partitions, constraints) + core internals.
#               Every deployment needs it.
#   read      — access checks, search (list_*), explain, condition validation.
#               Read-only and full deployments.
#   write     — tuple / model / store / condition management + maintenance.
#               Full deployments only.
#   audit     — audit tables & triggers, time-travel, changefeed.
#               Full deployments (and time-travel reads).
#
# Read-only deployment loads: substrate + read   (see init-readonly.sh).
# Full deployment loads:      substrate + read + write + audit (see init.sh).
#
# The list below is an authoritative, valid full-load order; engine_files_for
# preserves that order while filtering to the requested profiles.

ENGINE_MANIFEST=(
  "schema.sql:substrate"
  "schema_audit.sql:audit"
  "core_internal.sql:substrate"
  "conditions.sql:substrate"
  "access_internal.sql:read"
  "audit_internal.sql:audit"
  "store.sql:write"
  "access.sql:read"
  "explain.sql:read"
  "tuples.sql:write"
  "maintenance.sql:write"
  "audit.sql:audit"
  "watch.sql:audit"
  "model.sql:write"
  "conditions_admin.sql:write"
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
