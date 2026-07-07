#!/usr/bin/env bash
#
# Scaffold a policy hook (ADR 0011): emits a correctly-packaged skeleton that
# passes scripts/validate-hooks.sh out of the box.
#
# Usage:
#   scripts/new-hook.sh global  <name>            [target-dir]
#   scripts/new-hook.sh store   <store> <name>    [target-dir]
#
# Examples:
#   scripts/new-hook.sh global business_hours ./hooks/global
#   scripts/new-hook.sh store  tenant_a quota ./hooks/stores/tenant_a
set -euo pipefail

TIER="${1:-}"
case "$TIER" in
    global) NAME="${2:-}"; DIR="${3:-.}"; PKG="authz.hooks.v1.global.${NAME}" ;;
    store)  STORE="${2:-}"; NAME="${3:-}"; DIR="${4:-.}"; PKG="authz.hooks.v1.stores.${STORE}.${NAME}" ;;
    *) sed -n '3,13p' "$0"; exit 2 ;;
esac
[ -n "${NAME:-}" ] || { echo "missing hook name" >&2; exit 2; }

# Same rules as the validator: identifier, no Rego keywords, <=63 chars.
for seg in ${STORE:-} $NAME; do
    case "$seg" in
        as|contains|default|else|every|false|if|import|in|not|null|package|some|true|with|input|data)
            echo "'$seg' is a reserved Rego keyword" >&2; exit 2 ;;
    esac
    echo "$seg" | grep -Eq '^[a-zA-Z_][a-zA-Z0-9_]*$' || { echo "'$seg' is not a valid identifier ([a-zA-Z_][a-zA-Z0-9_]*)" >&2; exit 2; }
    [ "${#seg}" -le 63 ] || { echo "'$seg' exceeds 63 characters" >&2; exit 2; }
done

mkdir -p "$DIR"
FILE="$DIR/${NAME}.rego"
[ -e "$FILE" ] && { echo "$FILE already exists" >&2; exit 1; }

cat > "$FILE" <<EOF
# Policy hook '$NAME' (ADR 0011) — veto-only: a hook can deny, never allow.
# Evaluated against the normalized hook ABI (api_version pgauthz.hooks/v1);
# see examples/opa-hooks/README.md for the input document and dev tips
# (query data.authz._decision_hook_input to see exactly what you receive).
#
# Validate before mounting:
#   scripts/validate-hooks.sh --${TIER}${STORE:+ ${STORE}} $DIR
package $PKG

import future.keywords.contains
import future.keywords.if

# Deny a DECISION (check / batch / permitted_actions filtering).
# A denial is a string, or {"code": ..., "message": ...} for structured
# results. Delete this rule if the hook only governs writes.
deny contains {"code": "example_denied", "message": "explain why"} if {
	input.action == "some_action_to_restrict"
	# your conditions here — e.g. time gates use input.evaluated_at (ns),
	# environment gates use input.deployment.environment (allowlist-style!)
	false # remove: scaffold is inert until you write a real condition
}

# Deny a WRITE (tuple create/delete). input carries operation, actor (the
# authenticated caller), and tuple/tuples/writes/deletes. Delete if unused.
deny_write contains {"code": "example_write_denied", "message": "explain why"} if {
	input.operation == "write"
	false # remove: scaffold is inert until you write a real condition
}
EOF
echo "created $FILE (package $PKG)"
echo "next: scripts/validate-hooks.sh --${TIER}${STORE:+ ${STORE}} $DIR"
