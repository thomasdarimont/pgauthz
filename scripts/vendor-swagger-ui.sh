#!/usr/bin/env bash
#
# Vendors the Swagger UI assets pgauthzd embeds (SWAGGER_UI_ENABLED) into
# pgauthzd/internal/api/swaggerui/ from the swagger-ui-dist npm tarball — the
# UI is served from the binary, never from a CDN. The version and the tarball's
# sha256 are pinned here; bumping means: new version + new checksum (verify it
# yourself: curl -sSL <tarball> | shasum -a 256), run, review the diff, update
# VERSION and the changelog.
#
#   ./scripts/vendor-swagger-ui.sh            # re-vendor the pinned version
#
set -euo pipefail

VERSION="5.33.1"
TARBALL_SHA256="b468ff5f49451f194a739bc245c85b28c7d3d33057a8409a9b2369da37e215b9"
FILES=(swagger-ui.css swagger-ui-bundle.js swagger-ui-bundle.js.LICENSE.txt oauth2-redirect.html oauth2-redirect.js favicon-32x32.png LICENSE NOTICE)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$SCRIPT_DIR/../pgauthzd/internal/api/swaggerui"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

url="https://registry.npmjs.org/swagger-ui-dist/-/swagger-ui-dist-${VERSION}.tgz"
echo "==> Downloading $url"
curl -sSL -o "$TMP/dist.tgz" "$url"
actual="$(shasum -a 256 "$TMP/dist.tgz" | cut -d' ' -f1)"
if [ "$actual" != "$TARBALL_SHA256" ]; then
  echo "ERROR: tarball sha256 mismatch: got $actual, pinned $TARBALL_SHA256" >&2
  exit 1
fi
tar xzf "$TMP/dist.tgz" -C "$TMP"
for f in "${FILES[@]}"; do
  cp "$TMP/package/$f" "$DEST/$f"
done
{
  echo "swagger-ui-dist ${VERSION} (npm), Apache-2.0 — see LICENSE, NOTICE,"
  echo "swagger-ui-bundle.js.LICENSE.txt. Vendored by scripts/vendor-swagger-ui.sh, which pins"
  echo "the tarball's sha256; do not edit these files by hand."
  echo
  echo "tarball sha256  ${TARBALL_SHA256}"
  for f in swagger-ui.css swagger-ui-bundle.js oauth2-redirect.html oauth2-redirect.js favicon-32x32.png; do
    printf '%s  %s\n' "$f" "$(shasum -a 256 "$DEST/$f" | cut -d' ' -f1)"
  done
} > "$DEST/VERSION"
echo "==> Vendored swagger-ui-dist ${VERSION} into $DEST"
ls -la "$DEST"
