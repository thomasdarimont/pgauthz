#!/usr/bin/env bash
#
# Stop pgauthz on Kubernetes: uninstall the Helm release. By default the
# database PVCs are KEPT (data survives a restart). Use --clean to remove them.
#
# Usage:
#   ./stop.sh                 # uninstall the release, keep DB volumes
#   ./stop.sh --clean         # uninstall + delete PVCs (DESTROYS all data)
#
# Env knobs (with defaults):
#   RELEASE     helm release name   (pgauthz)
#   NAMESPACE   kubernetes namespace (default)
set -euo pipefail

RELEASE="${RELEASE:-pgauthz}"
NAMESPACE="${NAMESPACE:-default}"

command -v helm >/dev/null 2>&1 || { echo "!! 'helm' not found in PATH" >&2; exit 1; }

echo "==> Uninstalling release '$RELEASE' (namespace: $NAMESPACE)..."
helm uninstall "$RELEASE" --namespace "$NAMESPACE" 2>/dev/null || echo "   (release not found — nothing to uninstall)"

# Helm does not delete a hook Job's pods or the CloudNativePG PVCs; tidy leftovers.
kubectl -n "$NAMESPACE" delete job -l "app.kubernetes.io/instance=$RELEASE" --ignore-not-found >/dev/null 2>&1 || true

if [ "${1:-}" = "--clean" ]; then
  echo "==> Removing database PVCs (this DESTROYS all stores/tuples/audit)..."
  # CloudNativePG PVCs are labelled with the cluster name (<release>-db).
  kubectl -n "$NAMESPACE" delete pvc -l "cnpg.io/cluster=${RELEASE}-db" --ignore-not-found
  echo "==> Volumes removed."
else
  echo "==> Database PVCs kept. Re-run ./start.sh to resume, or ./stop.sh --clean to wipe."
fi

echo "==> Done."
