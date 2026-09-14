#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
BASELINE_SHA=ae04a363f76da800ac6d98a3647cf5bf5ab7e44a
BASELINE_ENGINE="$TMP/engine-ae04a36.mjs"
BASELINE_INDEX="$TMP/index-ae04a36.mjs"
BASELINE_ACTION="$TMP/action-ae04a36.yml"
SHIPPED_ENGINE="$ROOT/vendor/amino-audit-engine/engine.mjs"
SKILLS_DIR="${SKILLS_DIR:-$TMP/amino-skills}"

cd "$ROOT"

git cat-file -e "$BASELINE_SHA:src/engine.mjs" 2>/dev/null \
  || { echo "::error::baseline engine $BASELINE_SHA:src/engine.mjs is unavailable in this checkout"; exit 1; }
git show "$BASELINE_SHA:src/engine.mjs" > "$BASELINE_ENGINE"
git show "$BASELINE_SHA:src/index.mjs" > "$BASELINE_INDEX"
git show "$BASELINE_SHA:action.yml" > "$BASELINE_ACTION"

node test/local.mjs
node test/conformance.mjs
node test/engine-source-contract.mjs
node test/action-migration-canary.mjs
node test/workflow-action-pins.mjs
BASELINE_INDEX="$BASELINE_INDEX" BASELINE_ACTION="$BASELINE_ACTION" \
  node test/host-surface-equivalence.mjs

bash scripts/canary-fetch-pinned-engine.sh
bash scripts/verify-pinned-engine.sh "$TMP/canonical-engine"

scripts/fetch-pinned-skills.sh "$SKILLS_DIR"
SURFACE=action ENGINE="$SHIPPED_ENGINE" node "$SKILLS_DIR/conformance/run.mjs"
SURFACE=action ENGINE="$SHIPPED_ENGINE" node "$SKILLS_DIR/conformance/canary.mjs"
SURFACE=action ENGINE="$SHIPPED_ENGINE" RUNNER="$SKILLS_DIR/conformance/run.mjs" \
  EXPECT_FETCH_CALLS=0 node test/engine-network-denied.mjs
PARITY_PY="$SKILLS_DIR/amino-deliverability-audit/skills/amino-deliverability-audit/scripts/audit.py" \
  PARITY_JS="$SHIPPED_ENGINE" node "$SKILLS_DIR/web-parity/inventory.mjs"

SKILLS_DIR="$SKILLS_DIR" BASELINE_ENGINE="$BASELINE_ENGINE" ENGINE="$SHIPPED_ENGINE" \
  node test/engine-equivalence.mjs
SKILLS_DIR="$SKILLS_DIR" BASELINE_ENGINE="$BASELINE_ENGINE" ENGINE="$SHIPPED_ENGINE" \
  node test/engine-boundary-canary.mjs
BASELINE_ENGINE="$BASELINE_ENGINE" ENGINE="$SHIPPED_ENGINE" node test/production-wiring.mjs
node test/engine-ssrf.mjs
ENGINE="$SHIPPED_ENGINE" node test/engine-purity.mjs

echo "ALL WHI-7 PHASE 3 MIGRATION GATES PASS"
