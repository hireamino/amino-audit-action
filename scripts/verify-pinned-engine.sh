#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEST="${1:-/tmp/amino-audit-engine}"
SHIPPED="$ROOT/vendor/amino-audit-engine/engine.mjs"
EXPECTED_HASH=146a91ad5dfc047e28ade78ebe5bdf8788519b8b3b29c76b192e3a32ac7657e0

"$ROOT/scripts/fetch-pinned-engine.sh" "$DEST"
SOURCE="$DEST/src/engine.mjs"
[ -f "$SOURCE" ] || { echo "::error::canonical engine artifact not found at src/engine.mjs"; exit 1; }

if ! cmp -s "$SHIPPED" "$SOURCE"; then
  echo "::error::committed engine copy differs byte-for-byte from the pinned canonical artifact"
  exit 1
fi

got=$(sha256sum "$SHIPPED" | awk '{print $1}')
[ "$got" = "$EXPECTED_HASH" ] || {
  echo "::error::shipped engine SHA-256 $got does not equal reviewed hash $EXPECTED_HASH"
  exit 1
}

echo "Pinned engine byte identity PASS: $(wc -c < "$SHIPPED" | tr -d ' ') bytes; SHA-256 $got"
