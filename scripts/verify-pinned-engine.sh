#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEST="${1:-/tmp/amino-audit-engine}"
SHIPPED="$ROOT/vendor/amino-audit-engine/engine.mjs"
EXPECTED_HASH=978cd28742f3e5ab57293d76d8681fcb5ec3fa75d235929a05c19ac8db9e460e
SKILLS_PIN_FILE="${SKILLS_PIN_FILE:-$ROOT/.github/amino-skills.pin}"

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

[ -f "$SKILLS_PIN_FILE" ] || {
  echo "::error::consumer skills pin file not found: $SKILLS_PIN_FILE"
  exit 1
}
[ -f "$DEST/.github/amino-skills.pin" ] || {
  echo "::error::pinned engine skills pin file not found"
  exit 1
}
consumer_skills_pin=$(grep -v '^[[:space:]]*#' "$SKILLS_PIN_FILE" | tr -d '[:space:]' || true)
engine_skills_pin=$(grep -v '^[[:space:]]*#' "$DEST/.github/amino-skills.pin" | tr -d '[:space:]' || true)
[ "$consumer_skills_pin" = "$engine_skills_pin" ] || {
  echo "::error::consumer skills pin $consumer_skills_pin does not equal pinned engine skills pin $engine_skills_pin"
  exit 1
}

echo "Pinned engine byte identity PASS: $(wc -c < "$SHIPPED" | tr -d ' ') bytes; SHA-256 $got"
echo "Engine/consumer skills pin equality PASS: $consumer_skills_pin"
