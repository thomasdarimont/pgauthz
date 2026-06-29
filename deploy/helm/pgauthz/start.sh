#!/usr/bin/env bash
#
# Start pgauthz on Kubernetes (k3d-friendly): install the CloudNativePG
# operator, build + import the images, and helm-install the chart. Idempotent —
# safe to re-run (uses `helm upgrade --install`).
#
# Usage:
#   ./start.sh                  # build images, install operator + chart
#   K3D_CLUSTER=mycluster ./start.sh
#   SKIP_BUILD=1 ./start.sh     # skip docker build (images already imported)
#   VALUES=path/to/values.yaml ./start.sh
#
# Env knobs (with defaults):
#   K3D_CLUSTER   k3d cluster name to import images into       (pgauthz-demo)
#   RELEASE       helm release name                             (pgauthz)
#   NAMESPACE     kubernetes namespace                          (default)
#   IMAGE_TAG     tag for the locally built images             (0.1.2)
#   CNPG_VERSION  CloudNativePG version ("" = latest release)  (auto)
#   VALUES        extra helm values file                       (values-k3d.yaml)
#   SKIP_BUILD    set to 1 to skip docker build + k3d import
set -euo pipefail

CHART_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$CHART_DIR/../../.." && pwd)"

K3D_CLUSTER="${K3D_CLUSTER:-pgauthz-demo}"
RELEASE="${RELEASE:-pgauthz}"
NAMESPACE="${NAMESPACE:-default}"
IMAGE_TAG="${IMAGE_TAG:-0.1.2}"
VALUES="${VALUES:-$CHART_DIR/values-k3d.yaml}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "!! '$1' not found in PATH" >&2; exit 1; }; }
need kubectl; need helm

echo "==> Context: $(kubectl config current-context)"

# ── 1. CloudNativePG operator (cluster-scoped; install once) ─────────────────
if ! kubectl get crd clusters.postgresql.cnpg.io >/dev/null 2>&1; then
  ver="${CNPG_VERSION:-}"
  if [ -z "$ver" ]; then
    ver=$(curl -fsSL https://api.github.com/repos/cloudnative-pg/cloudnative-pg/releases/latest \
            | grep -m1 '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')
  fi
  branch="release-$(echo "$ver" | cut -d. -f1,2)"
  echo "==> Installing CloudNativePG operator $ver..."
  kubectl apply --server-side -f \
    "https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/${branch}/releases/cnpg-${ver}.yaml"
  kubectl -n cnpg-system rollout status deploy/cnpg-controller-manager --timeout=180s
else
  echo "==> CloudNativePG operator already installed."
fi

# ── 2. Build + import images (migrations + AuthZEN) ──────────────────────────
if [ "${SKIP_BUILD:-}" != "1" ]; then
  need docker; need k3d
  echo "==> Building images (tag $IMAGE_TAG)..."
  docker build -f "$REPO_ROOT/deploy/migrations/Dockerfile" -t "pgauthz-migrations:$IMAGE_TAG" "$REPO_ROOT"
  docker build -f "$REPO_ROOT/authzen/Dockerfile" --build-arg BINARY=authzen-direct -t "pgauthz-authzen-direct:$IMAGE_TAG" "$REPO_ROOT/authzen"
  docker build -f "$REPO_ROOT/authzen/Dockerfile" --build-arg BINARY=authzen-opa    -t "pgauthz-authzen-opa:$IMAGE_TAG"    "$REPO_ROOT/authzen"

  echo "==> Importing images into k3d cluster '$K3D_CLUSTER'..."
  k3d image import "pgauthz-migrations:$IMAGE_TAG" "pgauthz-authzen-direct:$IMAGE_TAG" \
                   "pgauthz-authzen-opa:$IMAGE_TAG" -c "$K3D_CLUSTER"
else
  echo "==> SKIP_BUILD=1 — using already-imported images."
fi

# ── 3. Embed OPA policies, then install/upgrade the chart ────────────────────
echo "==> Syncing OPA policies into the chart..."
"$CHART_DIR/sync-files.sh"

echo "==> helm upgrade --install $RELEASE ..."
# NOTE: deliberately NO --wait. The schema/roles are created by the post-install
# migration hook, and the app Deployments (PostgREST, AuthZEN) cannot become
# ready until that runs. --wait would block on those not-ready pods *before*
# running the hook → deadlock. Helm still waits for the hook Job itself, so the
# schema is loaded before this returns; we then wait for the apps to settle.
helm upgrade --install "$RELEASE" "$CHART_DIR" \
  --namespace "$NAMESPACE" --create-namespace \
  -f "$VALUES" \
  --set images.migrations.tag="$IMAGE_TAG" \
  --set images.authzenDirect.tag="$IMAGE_TAG" \
  --set images.authzenOpa.tag="$IMAGE_TAG" \
  --timeout 8m

echo ""
echo "==> Waiting for the application pods to settle (they crash-loop until the"
echo "    database, roles and schema are ready, then recover)..."
for d in opa postgrest postgrest-writer authzen-direct authzen-opa; do
  kubectl -n "$NAMESPACE" rollout status "deploy/${RELEASE}-${d}" --timeout=300s 2>/dev/null \
    || echo "   (${RELEASE}-${d} not ready yet — check 'kubectl get pods')"
done

echo ""
echo "==> Deployed. Status:"
kubectl -n "$NAMESPACE" get cluster,pods 2>/dev/null | grep -vE "Completed" || true
echo ""
echo "==> OPA is the front door. Port-forward to reach it:"
echo "      kubectl -n $NAMESPACE port-forward svc/${RELEASE}-opa 8181:8181"
