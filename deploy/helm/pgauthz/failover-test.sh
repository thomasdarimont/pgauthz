#!/usr/bin/env bash
#
# failover-test.sh — exercise a pgauthz / CloudNativePG primary handover and
# verify the RPO-0 guarantee: an acknowledged write made *before* the handover
# survives on the new primary, the new primary is writable, and fresh writes
# work. Leaves the cluster healthy. See the chart README "Testing failover".
#
# Modes:
#   MODE=switchover  (default) graceful `kubectl cnpg promote` — non-destructive,
#                    nothing is killed; the preferred routine game-day. Needs the
#                    `cnpg` kubectl plugin (https://cloudnative-pg.io/ → kubectl plugin).
#   MODE=failover    simulate primary loss by deleting the primary pod; CNPG
#                    detects, fences, promotes. Force-deletes the old primary if
#                    it gets stuck `Terminating` (the single-node-k3d gotcha).
#
# Usage:
#   ./failover-test.sh
#   MODE=failover ./failover-test.sh
#   RELEASE=pgauthz NAMESPACE=default TARGET=pgauthz-db-1 ./failover-test.sh
#
# Env knobs (with defaults):
#   RELEASE    helm release name (→ cluster <RELEASE>-db)     (pgauthz)
#   NAMESPACE  kubernetes namespace                            (default)
#   CLUSTER    CloudNativePG cluster name                      (<RELEASE>-db)
#   DBNAME     database to write the probe store into          (authz)
#   MODE       switchover | failover                           (switchover)
#   TARGET     standby to promote (switchover)   (auto: first non-primary instance)
#   TIMEOUT    seconds to wait for the handover                (300)
#              (an unplanned failover on a freshly-built cluster can take a
#              couple of minutes while CNPG waits for WAL receivers to drain;
#              a graceful switchover is much faster)
#   KEEP       set to 1 to keep the probe stores (skip cleanup)
set -euo pipefail

RELEASE="${RELEASE:-pgauthz}"
NAMESPACE="${NAMESPACE:-default}"
CLUSTER="${CLUSTER:-${RELEASE}-db}"
DBNAME="${DBNAME:-authz}"
MODE="${MODE:-switchover}"
TIMEOUT="${TIMEOUT:-300}"
K="kubectl -n $NAMESPACE"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
grn()   { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()   { printf '\033[33m%s\033[0m\n' "$*"; }
step()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die()   { red "!! $*"; exit 1; }

command -v kubectl >/dev/null || die "'kubectl' not found in PATH"
$K get cluster "$CLUSTER" >/dev/null 2>&1 || die "cluster '$CLUSTER' not found in namespace '$NAMESPACE' (set RELEASE/NAMESPACE/CLUSTER)"

cfield()  { $K get cluster "$CLUSTER" -o jsonpath="{$1}" 2>/dev/null; }
rw_pod()  { $K get endpoints "${CLUSTER}-rw" -o jsonpath='{.subsets[*].addresses[*].targetRef.name}' 2>/dev/null; }
psqlc()   { $K exec "$1" -c postgres -- psql -U postgres -d "$DBNAME" -tAc "$2"; }

# Poll until the handover lands and the -rw endpoint follows it (or timeout).
#   want != ""  → expect that specific pod (switchover, explicit target)
#   want == ""  → expect ANY new primary that isn't $old (failover; CNPG picks
#                 the most-advanced standby, which we don't predict)
wait_primary() {
  local want="$1" old="$2" forced="" t=0
  while [ "$t" -lt "$TIMEOUT" ]; do
    local prim ep phase; prim="$(cfield .status.currentPrimary)"; ep="$(rw_pod)"; phase="$(cfield .status.phase)"
    printf '   t=%3ds  primary=%-16s  -rw→%-16s  %s\n' "$t" "${prim:-?}" "${ep:-none}" "$phase"
    if [ -n "$want" ]; then
      [ "$prim" = "$want" ] && [ "$ep" = "$want" ] && return 0
    else
      [ -n "$prim" ] && [ "$prim" != "$old" ] && [ "$ep" = "$prim" ] && return 0
    fi
    # Failover only: a deleted pod keeps status.phase=Running while it drains, so
    # detect "stuck Terminating" via metadata.deletionTimestamp. Force-delete once
    # so CNPG can finish promotion (its split-brain guard waits for the old
    # primary to be gone — the single-node-k3d gotcha).
    if [ "$MODE" = failover ] && [ -z "$forced" ] && [ "$t" -ge 20 ] \
       && [ -n "$($K get pod "$old" -o jsonpath='{.metadata.deletionTimestamp}' 2>/dev/null)" ]; then
      ylw "   old primary '$old' stuck Terminating — force-deleting so promotion can proceed"
      $K delete pod "$old" --grace-period=0 --force >/dev/null 2>&1 || true
      forced=1
    fi
    sleep 5; t=$((t+5))
  done
  return 1
}

# ── Pre-flight ───────────────────────────────────────────────────────────────
PRIMARY="$(cfield .status.currentPrimary)"
[ -n "$PRIMARY" ] || die "could not determine current primary"
mapfile -t INSTANCES < <(cfield '.status.instanceNames[*]' | tr ' ' '\n' | grep -v '^$' | sort)
[ "${#INSTANCES[@]}" -ge 2 ] || die "need >= 2 instances for a handover; cluster has ${#INSTANCES[@]} (scale database.instances up)"

if [ "$MODE" = switchover ]; then
  if ! command -v kubectl-cnpg >/dev/null 2>&1 && ! kubectl cnpg version >/dev/null 2>&1; then
    red "!! MODE=switchover needs the 'cnpg' kubectl plugin, which isn't installed."
    echo "   Install it one of these ways, then re-run:"
    echo "     • krew:   kubectl krew install cnpg"
    echo "     • binary: https://github.com/cloudnative-pg/cloudnative-pg/releases  (kubectl-cnpg_<ver>_<os>_<arch>)"
    echo "   …or run the no-plugin path:  MODE=failover $0"
    exit 1
  fi
fi

# Pick the promotion target (switchover): first instance that isn't the primary.
TARGET="${TARGET:-}"
if [ -z "$TARGET" ]; then
  for i in "${INSTANCES[@]}"; do [ "$i" != "$PRIMARY" ] && { TARGET="$i"; break; }; done
fi
[ -n "$TARGET" ] && [ "$TARGET" != "$PRIMARY" ] || die "could not pick a standby target distinct from primary '$PRIMARY'"

step "pgauthz failover test  (mode=$MODE, cluster=$CLUSTER, ns=$NAMESPACE)"
echo "   current primary : $PRIMARY"
echo "   instances       : ${INSTANCES[*]}"
[ "$MODE" = switchover ] && echo "   promote target  : $TARGET"

# ── Sync-replication status (RPO 0 only holds with synchronous replication) ──
step "Replication mode (RPO-0 requires synchronous replication)"
SSN="$(psqlc "$PRIMARY" 'SHOW synchronous_standby_names;' | tr -d '\r')"
if [ -n "$SSN" ]; then
  grn "   synchronous: $SSN  → acked writes are guaranteed on a standby (RPO 0)"
else
  ylw "   asynchronous (synchronous_standby_names empty) → RPO is > 0; the probe"
  ylw "   write will *usually* survive but is NOT guaranteed. Enable values-ha.yaml / HA=1."
fi

# ── Baseline probe write on the current primary ─────────────────────────────
RUN="$($K get cluster "$CLUSTER" -o jsonpath='{.metadata.uid}' | cut -c1-6)$$"
BEFORE="fotest_before_${RUN}"
AFTER="fotest_after_${RUN}"
cleanup() {
  [ "${KEEP:-}" = 1 ] && return 0
  local p; p="$(cfield .status.currentPrimary)"; [ -n "$p" ] || return 0
  # Delete only stores that actually exist — a single batch like
  # "delete_store('before'); delete_store('after')" runs as ONE transaction, so
  # if the script failed early (AFTER never created) delete_store() would raise
  # and roll back the whole batch, orphaning BEFORE. Driving the call off a row
  # filter calls delete_store() zero times for a missing name → no error.
  $K exec "$p" -c postgres -- psql -U postgres -d "$DBNAME" -tAc \
    "SELECT authz.delete_store(name) FROM authz.stores WHERE name IN ('$BEFORE','$AFTER');" >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "Baseline: write an acked store '$BEFORE' on the current primary"
psqlc "$PRIMARY" "SELECT authz.create_store('$BEFORE');" >/dev/null
psqlc "$PRIMARY" "SELECT 'present on primary: '||EXISTS(SELECT 1 FROM authz.stores WHERE name='$BEFORE');"

# ── Trigger the handover ────────────────────────────────────────────────────
if [ "$MODE" = switchover ]; then
  step "Switchover: kubectl cnpg promote $CLUSTER $TARGET (graceful, non-destructive)"
  # NB: the cnpg plugin rejects kubectl flags placed *before* the plugin name
  # ("flags cannot be placed before plugin name"), so -n goes after the subcommand.
  kubectl cnpg promote "$CLUSTER" "$TARGET" -n "$NAMESPACE"
  EXPECT="$TARGET"          # we name the target, so expect exactly it
else
  step "Failover: deleting primary pod '$PRIMARY' to simulate node loss"
  $K delete pod "$PRIMARY" --wait=false
  EXPECT=""                 # CNPG picks the most-advanced standby — accept any new primary
fi

step "Waiting for promotion + -rw repoint (timeout ${TIMEOUT}s)"
wait_primary "$EXPECT" "$PRIMARY" || die "handover did not complete within ${TIMEOUT}s (check 'kubectl get cluster $CLUSTER')"
NEWPRIM="$(cfield .status.currentPrimary)"
grn "   handover complete: primary is now $NEWPRIM, -rw → $(rw_pod)"

# ── Verify RPO 0 + write-path recovery on the new primary ───────────────────
step "Verifying RPO 0 and write-path recovery on $NEWPRIM"
fail=0
[ "$(psqlc "$NEWPRIM" 'SELECT pg_is_in_recovery();' | tr -d '\r')" = "f" ] \
  && grn "   ✓ new primary is writable (pg_is_in_recovery = f)" \
  || { red "   ✗ new primary still in recovery"; fail=1; }

[ "$(psqlc "$NEWPRIM" "SELECT EXISTS(SELECT 1 FROM authz.stores WHERE name='$BEFORE');" | tr -d '\r')" = "t" ] \
  && grn "   ✓ RPO 0: pre-handover acked write '$BEFORE' survived" \
  || { red "   ✗ pre-handover write '$BEFORE' is MISSING (data loss!)"; fail=1; }

if psqlc "$NEWPRIM" "SELECT authz.create_store('$AFTER');" >/dev/null 2>&1 \
   && [ "$(psqlc "$NEWPRIM" "SELECT EXISTS(SELECT 1 FROM authz.stores WHERE name='$AFTER');" | tr -d '\r')" = "t" ]; then
  grn "   ✓ write-path recovered: new write '$AFTER' succeeded on the new primary"
else
  red "   ✗ could not write to the new primary"; fail=1
fi

step "Result"
if [ "$fail" = 0 ]; then
  grn "PASS — $MODE handover preserved acked writes (RPO 0) and recovered the write path."
  echo "CNPG will re-clone the old primary as a standby; the cluster returns to healthy with roles swapped."
  exit 0
else
  red "FAIL — see the ✗ lines above. Inspect: kubectl get cluster $CLUSTER; kubectl get pods -n $NAMESPACE"
  exit 1
fi
