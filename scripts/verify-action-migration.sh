#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
BASELINE_SHA=ae04a363f76da800ac6d98a3647cf5bf5ab7e44a
BASELINE_INDEX="$TMP/index-ae04a36.mjs"
BASELINE_ACTION="$TMP/action-ae04a36.yml"
SHIPPED_ENGINE="$ROOT/vendor/amino-audit-engine/engine.mjs"
SKILLS_DIR="${SKILLS_DIR:-$TMP/amino-skills}"

cd "$ROOT"

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
(cd "$TMP/canonical-engine" && bash scripts/verify.sh)
ENGINE_CHECKOUT="$TMP/canonical-engine" node test/engine-suite-canary.mjs

scripts/fetch-pinned-skills.sh "$SKILLS_DIR"
SURFACE=action ENGINE="$SHIPPED_ENGINE" node "$SKILLS_DIR/conformance/run.mjs"
SURFACE=action ENGINE="$SHIPPED_ENGINE" node "$SKILLS_DIR/conformance/canary.mjs"
PARITY_PY="$SKILLS_DIR/amino-deliverability-audit/skills/amino-deliverability-audit/scripts/audit.py" \
  PARITY_JS="$SHIPPED_ENGINE" node "$SKILLS_DIR/web-parity/inventory.mjs"

echo "ALL WHI-125 STEP 3 ACTION MIGRATION GATES PASS"
