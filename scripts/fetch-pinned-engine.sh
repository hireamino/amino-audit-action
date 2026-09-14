#!/usr/bin/env bash
# Fetch the public canonical engine at the immutable revision selected by this
# consumer. No GitHub token is accepted or required.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PIN_FILE="${PIN_FILE:-$ROOT/.github/amino-audit-engine.pin}"
DEST="${1:-/tmp/amino-audit-engine}"
REMOTE="${ENGINE_REMOTE:-https://github.com/hireamino/amino-audit-engine.git}"
GIT_BIN="${ENGINE_GIT_BIN:-git}"

fail() {
  echo "::error::$1"
  exit 1
}

[ -f "$PIN_FILE" ] || fail "engine pin file not found: $PIN_FILE"

pin=$(grep -v '^[[:space:]]*#' "$PIN_FILE" | tr -d '[:space:]' || true)
[ -n "$pin" ] || fail "no engine revision in $PIN_FILE"
case "$pin" in
  *[!0-9a-f]*) fail "engine pin '$pin' is not lowercase hex" ;;
esac
[ ${#pin} -eq 40 ] || fail "engine pin '$pin' is ${#pin} chars, expected a full 40-char SHA"

case "$DEST" in
  ""|"/") fail "unsafe engine fetch destination: '$DEST'" ;;
esac
rm -rf -- "$DEST"
mkdir -p "$DEST"

"$GIT_BIN" -C "$DEST" init -q || fail "could not initialize engine checkout at $DEST"
"$GIT_BIN" -C "$DEST" remote add origin "$REMOTE" || fail "could not configure engine remote: $REMOTE"

# The repository is public. Clear the common token variables, disable credential
# helpers and prompts, and fetch only the reviewed object.
unset GH_TOKEN GITHUB_TOKEN
GIT_TERMINAL_PROMPT=0 "$GIT_BIN" -C "$DEST" -c credential.helper= fetch -q --depth 1 origin "$pin" \
  || fail "could not fetch engine revision $pin from $REMOTE without credentials"
"$GIT_BIN" -C "$DEST" checkout -q FETCH_HEAD \
  || fail "could not checkout fetched engine revision $pin"

got=$("$GIT_BIN" -C "$DEST" rev-parse HEAD 2>/dev/null) \
  || fail "could not resolve fetched engine HEAD"
[ "$got" = "$pin" ] || fail "fetched engine HEAD $got does not equal pin $pin"

echo "amino-audit-engine pinned at $got"
