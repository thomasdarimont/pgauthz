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
#   VALUES=path/to/values.yaml ./start.sh           # one values file
#   VALUES="values-k3d.yaml extra.yaml" ./start.sh  # layered, later wins
#   HA=1 ./start.sh             # append values-ha.yaml (synchronous, zero-RPO)
#
# Env knobs (with defaults):
#   K3D_CLUSTER   k3d cluster name to import images into       (pgauthz-demo)
#   RELEASE       helm release name                             (pgauthz)
#   NAMESPACE     kubernetes namespace                          (default)
#   IMAGE_TAG     tag for the locally built images             (0.11.0)
#   CNPG_VERSION  CloudNativePG version ("" = latest release)  (auto)
#   VALUES        space-separated helm values file(s)          (values-k3d.yaml)
#   HA            set to 1 to append values-ha.yaml (sync replication, RPO 0)
#   SKIP_BUILD    set to 1 to skip docker build + k3d import
set -euo pipefail

CHART_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$CHART_DIR/../../.." && pwd)"

K3D_CLUSTER="${K3D_CLUSTER:-pgauthz-demo}"
RELEASE="${RELEASE:-pgauthz}"
NAMESPACE="${NAMESPACE:-default}"
IMAGE_TAG="${IMAGE_TAG:-0.11.0}"
VALUES="${VALUES:-$CHART_DIR/values-k3d.yaml}"
# HA=1 appends the synchronous-replication overlay (zero-RPO failover). Layered
# last so its sync settings win; it carries no instance count, inheriting it
# from the earlier file(s) (values-k3d.yaml → 2, values.yaml → 3).
[ "${HA:-}" = "1" ] && VALUES="$VALUES $CHART_DIR/values-ha.yaml"
# Expand the (possibly space-separated) list into repeated `-f <file>` args.
VALUE_ARGS=(); for _vf in $VALUES; do VALUE_ARGS+=(-f "$_vf"); done

need() { command -v "$1" >/dev/null 2>&1 || { echo "!! '$1' not found in PATH" >&2; exit 1; }; }
need kubectl; need helm

echo "==> Context: $(kubectl config current-context)"

# ── 1. CloudNativePG operator (cluster-scoped; install once) ─────────────────
if ! kubectl get crd clusters.postgresql.cnpg.io >/dev/null 2>&1; then
  ver="${CNPG_VERSION:-}"
  if [ -z "$ver" ]; then
    # Read the whole response with jq — a `grep -m1` here closes the pipe early,
    # which makes curl fail with error 56 (broken pipe) under `set -o pipefail`.
    ver=$(curl -fsSL https://api.github.com/repos/cloudnative-pg/cloudnative-pg/releases/latest \
            | jq -r '.tag_name' | sed -E 's/^v//')
  fi
  branch="release-$(echo "$ver" | cut -d. -f1,2)"
  echo "==> Installing CloudNativePG operator $ver..."
  kubectl apply --server-side -f \
    "https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/${branch}/releases/cnpg-${ver}.yaml"
  kubectl -n cnpg-system rollout status deploy/cnpg-controller-manager --timeout=180s
else
  echo "==> CloudNativePG operator already installed."
fi

# ── 2. Build + import images (migrations + pgauthzd) ─────────────────────────
if [ "${SKIP_BUILD:-}" != "1" ]; then
  need docker; need k3d
  echo "==> Building images (tag $IMAGE_TAG)..."
  docker build -f "$REPO_ROOT/deploy/migrations/Dockerfile" -t "pgauthz-migrations:$IMAGE_TAG" "$REPO_ROOT"
  # pgauthzd — the SINGLE unified daemon. One image, capability-scoped per
  # Deployment by PGAUTHORIZER_PROFILE (decision-only reader + AuthZEN API, full
  # writer, OPA-fronted AuthZEN gateway). No BINARY build-arg — the Dockerfile hardcodes
  # ./cmd/pgauthzd.
  docker build -f "$REPO_ROOT/pgauthzd/Dockerfile" --build-arg VERSION="$IMAGE_TAG" -t "pgauthz-pgauthzd:$IMAGE_TAG" "$REPO_ROOT/pgauthzd"

  echo "==> Importing images into k3d cluster '$K3D_CLUSTER'..."
  k3d image import "pgauthz-migrations:$IMAGE_TAG" "pgauthz-pgauthzd:$IMAGE_TAG" -c "$K3D_CLUSTER"
else
  echo "==> SKIP_BUILD=1 — using already-imported images."
fi

# ── 3. Embed OPA policies, then install/upgrade the chart ────────────────────
echo "==> Syncing OPA policies into the chart..."
"$CHART_DIR/sync-files.sh"

echo "==> helm upgrade --install $RELEASE ..."
# NOTE: deliberately NO --wait. The schema/roles are created by the post-install
# migration hook, and the app Deployments (pgauthzd reader/writer + OPA-fronted gateway)
# cannot become ready until that runs. --wait would block on those not-ready pods *before*
# running the hook → deadlock. Helm still waits for the hook Job itself, so the
# schema is loaded before this returns; we then wait for the apps to settle.
echo "==> Values: $VALUES"
helm upgrade --install "$RELEASE" "$CHART_DIR" \
  --namespace "$NAMESPACE" --create-namespace \
  "${VALUE_ARGS[@]}" \
  --set images.migrations.tag="$IMAGE_TAG" \
  --set images.pgauthzd.tag="$IMAGE_TAG" \
  --timeout 8m

echo ""
echo "==> Waiting for the application pods to settle (they crash-loop until the"
echo "    database, roles and schema are ready, then recover)..."
for d in opa reader writer pgauthzd-opa; do
  kubectl -n "$NAMESPACE" rollout status "deploy/${RELEASE}-${d}" --timeout=300s 2>/dev/null \
    || echo "   (${RELEASE}-${d} not ready yet — check 'kubectl get pods')"
done

echo ""
echo "==> Deployed. Status:"
kubectl -n "$NAMESPACE" get cluster,pods 2>/dev/null | grep -vE "Completed" || true
echo ""
echo "==> pgauthzd is the front door (AuthZEN 1.0). Port-forward to reach it:"
echo "      kubectl -n $NAMESPACE port-forward svc/${RELEASE}-pgauthzd-opa 8080:8080"
echo "    (OPA is internal — reached only by the pgauthzd gateway.)"
