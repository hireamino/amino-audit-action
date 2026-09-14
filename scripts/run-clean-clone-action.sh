#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
EXPECTED_HEAD="${1:-$(git -C "$ROOT" rev-parse HEAD)}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
CLONE="$TMP/amino-audit-action"

git clone --quiet --no-local "$ROOT" "$CLONE"
git -C "$CLONE" checkout -q "$EXPECTED_HEAD"
got=$(git -C "$CLONE" rev-parse HEAD)
[ "$got" = "$EXPECTED_HEAD" ] || {
  echo "::error::clean-clone HEAD $got does not equal expected PR head $EXPECTED_HEAD"
  exit 1
}
[ -z "$(git -C "$CLONE" status --porcelain)" ] || {
  echo "::error::clean clone is not clean before Action execution"
  exit 1
}
[ ! -e "$CLONE/src/engine.mjs" ] || {
  echo "::error::deleted Pages engine unexpectedly exists in clean clone"
  exit 1
}

SUMMARY="$TMP/summary.md"
OUTPUT="$TMP/output.txt"
touch "$SUMMARY" "$OUTPUT"

cd "$CLONE"
env \
  "INPUT_DOMAINS=hireamino.com" \
  "INPUT_FAIL-ON=advisory" \
  "INPUT_COMMENT-ON-PR=false" \
  "INPUT_CONTINUE-ON-AUDIT-ERROR=true" \
  "INPUT_GITHUB-TOKEN=" \
  "GITHUB_STEP_SUMMARY=$SUMMARY" \
  "GITHUB_OUTPUT=$OUTPUT" \
  node src/index.mjs

grep -Fq "Amino Email Deliverability Audit" "$SUMMARY" \
  || { echo "::error::clean-clone run did not write the Action summary"; exit 1; }
for output_name in passed audit-complete worst-severity summary; do
  grep -Fq "${output_name}<<" "$OUTPUT" \
    || { echo "::error::clean-clone run did not emit $output_name"; exit 1; }
done

hash=$(sha256sum vendor/amino-audit-engine/engine.mjs | awk '{print $1}')
echo "Clean-clone Action run PASS at $got; shipped engine SHA-256 $hash"
