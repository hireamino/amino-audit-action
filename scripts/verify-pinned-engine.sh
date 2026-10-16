#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEST="${1:-/tmp/amino-audit-engine}"

"$ROOT/scripts/fetch-pinned-engine.sh" "$DEST"
[ -f "$DEST/scripts/verify-consumer-copy.mjs" ] || {
  echo "::error::pinned engine consumer identity verifier not found"
  exit 1
}
CONSUMER_ROOT="$ROOT" node "$DEST/scripts/verify-consumer-copy.mjs"
