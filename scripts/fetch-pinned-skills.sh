#!/usr/bin/env bash
# Fetch hireamino/amino-skills at the revision pinned in .github/amino-skills.pin.
#
# WHY THIS EXISTS. security-gate.yml runs conformance/run.mjs FROM that repo, so this is
# not just "which corpus do we compare against" — it is remote code executing on this
# runner. An unpinned `git clone --depth 1 ... main` means whatever lands on that repo's
# main runs here, unreviewed, at the moment it lands. Pinning makes that an explicit,
# reviewable commit in THIS repo.
#
# Fails closed on every path: a missing pin file, a comment-only file, a malformed SHA,
# a fetch that does not succeed, or a checkout whose HEAD is not the pin.
#
# Usage: scripts/fetch-pinned-skills.sh [dest]
# Env:   PIN_FILE (default .github/amino-skills.pin) · SKILLS_REMOTE (default the public repo)
set -euo pipefail

PIN_FILE="${PIN_FILE:-.github/amino-skills.pin}"
DEST="${1:-/tmp/amino-skills}"
REMOTE="${SKILLS_REMOTE:-https://github.com/hireamino/amino-skills.git}"

[ -f "$PIN_FILE" ] || { echo "::error::pin file not found: $PIN_FILE"; exit 1; }

pin=$(grep -v '^#' "$PIN_FILE" | tr -d '[:space:]')
[ -n "$pin" ] || { echo "::error::no revision in $PIN_FILE (comments only?)"; exit 1; }
case "$pin" in
  *[!0-9a-f]*) echo "::error::pin '$pin' is not lowercase hex"; exit 1 ;;
esac
[ ${#pin} -eq 40 ] || { echo "::error::pin '$pin' is ${#pin} chars, expected a full 40-char SHA"; exit 1; }

rm -rf "$DEST"
mkdir -p "$DEST"
cd "$DEST"
git init -q
git remote add origin "$REMOTE"
git fetch -q --depth 1 origin "$pin" || { echo "::error::could not fetch $pin from $REMOTE"; exit 1; }
git checkout -q FETCH_HEAD

# Verify rather than assume the fetch produced the pin — a moved ref, a caching proxy or
# a partially-failed fetch would otherwise leave the wrong code executing on this runner.
got=$(git rev-parse HEAD)
[ "$got" = "$pin" ] || { echo "::error::checked out $got, pin is $pin"; exit 1; }
echo "amino-skills pinned at $got"
