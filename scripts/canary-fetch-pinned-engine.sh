#!/usr/bin/env bash
# Exercise every reachable guard in fetch-pinned-engine.sh against a local Git
# repository. No case reaches the network.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="$ROOT/scripts/fetch-pinned-engine.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
pass=0
fail=0

record() {
  local condition="$1" name="$2" detail="${3:-}"
  if [ "$condition" = 0 ]; then
    echo "PASS  $name"
    pass=$((pass + 1))
  else
    echo "FAIL  $name${detail:+ ($detail)}"
    fail=$((fail + 1))
  fi
}

LOCAL="$TMP/engine-source"
mkdir -p "$LOCAL/src"
git -C "$LOCAL" init -q
git -C "$LOCAL" config user.email canary@hireamino.invalid
git -C "$LOCAL" config user.name canary
cp "$ROOT/vendor/amino-audit-engine/engine.mjs" "$LOCAL/src/engine.mjs"
git -C "$LOCAL" add src/engine.mjs
git -C "$LOCAL" -c commit.gpgsign=false commit -qm engine
REAL=$(git -C "$LOCAL" rev-parse HEAD)
PIN="$TMP/pin"
DEST="$TMP/dest"

run() {
  PIN_FILE="$PIN" ENGINE_REMOTE="$LOCAL" ENGINE_GIT_BIN="${ENGINE_GIT_BIN:-git}" \
    "$SCRIPT" "$DEST" 2>&1
}

expect() {
  local name="$1" wanted_status="$2" wanted_message="$3"
  local output status
  output=$(run)
  status=$?
  if [ "$status" -eq "$wanted_status" ] && { [ -z "$wanted_message" ] || printf '%s' "$output" | grep -Fq -- "$wanted_message"; }; then
    record 0 "$name"
  else
    record 1 "$name" "exit=$status; output=$output"
  fi
}

printf '%s\n' "$REAL" > "$PIN"
expect "healthy local pin is accepted" 0 "amino-audit-engine pinned at $REAL"
record "$([ "$(git -C "$DEST" rev-parse HEAD 2>/dev/null)" = "$REAL" ] && echo 0 || echo 1)" \
  "healthy fetch checks out the pinned commit"
record "$([ "$(sha256sum "$DEST/src/engine.mjs" | awk '{print $1}')" = "146a91ad5dfc047e28ade78ebe5bdf8788519b8b3b29c76b192e3a32ac7657e0" ] && echo 0 || echo 1)" \
  "healthy fetch preserves canonical engine bytes"

rm -f "$PIN"
expect "missing pin is rejected by its guard" 1 "::error::engine pin file not found:"
printf '# comment only\n' > "$PIN"
expect "comment-only pin is rejected by its guard" 1 "::error::no engine revision in"
printf 'main\n' > "$PIN"
expect "moving ref is rejected by the hex guard" 1 "::error::engine pin 'main' is not lowercase hex"
printf '%s\n' "${REAL%?}" > "$PIN"
expect "39-character pin is rejected by the length guard" 1 "expected a full 40-char SHA"
printf '%s0\n' "$REAL" > "$PIN"
expect "41-character pin is rejected by the length guard" 1 "expected a full 40-char SHA"
printf '%s\n' "$(printf '%s' "$REAL" | tr '[:lower:]' '[:upper:]')" > "$PIN"
expect "uppercase pin is rejected by the hex guard" 1 "is not lowercase hex"
printf '%040d\n' 0 > "$PIN"
expect "absent commit is rejected by the fetch guard" 1 "::error::could not fetch engine revision"

# Force the post-checkout identity branch while all repository operations still
# use the real local repository. The wrapper lies only for `rev-parse HEAD`.
FAKE_GIT="$TMP/git-head-mismatch"
printf '%s\n' '#!/usr/bin/env bash' \
  'if [[ "$*" == *"rev-parse HEAD"* ]]; then printf "%040d\\n" 0; exit 0; fi' \
  'exec git "$@"' > "$FAKE_GIT"
chmod +x "$FAKE_GIT"
printf '%s\n' "$REAL" > "$PIN"
ENGINE_GIT_BIN="$FAKE_GIT" expect "HEAD mismatch is rejected by its guard" 1 \
  "::error::fetched engine HEAD 0000000000000000000000000000000000000000 does not equal pin $REAL"

EXPECTED=11
echo
echo "engine pin canary: $pass passed, $fail failed (expected $EXPECTED cases)"
[ $((pass + fail)) -eq "$EXPECTED" ] || {
  echo "FAIL  ran $((pass + fail)) cases, expected $EXPECTED — a case vanished"
  exit 1
}
[ "$fail" -eq 0 ]
