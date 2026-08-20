#!/usr/bin/env bash
# Canary for fetch-pinned-skills.sh. Every guard in that script is asserted to REJECT the
# case it exists for, and the healthy case is asserted to be ACCEPTED — a fail-closed
# script that has stopped working at all would otherwise pass a rejection-only suite.
#
# Runs against a LOCAL clone (SKILLS_REMOTE), so it needs no network and cannot be
# perturbed by the real repo moving.
#
# ⚠️ BOUND, stated rather than implied: the final HEAD-vs-pin verification cannot be
# exercised here. git will not hand back a commit other than the one fetched, so that
# branch is unreachable from a harness. It is source-pinned below instead, which proves
# the check is present, not that it fires.
set -uo pipefail
cd "$(dirname "$0")/.."
SCRIPT=scripts/fetch-pinned-skills.sh
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0
ok(){ [ "$1" = "$2" ] && { echo "PASS  $3"; pass=$((pass+1)); } || { echo "FAIL  $3 (got exit $1, wanted $2)"; fail=$((fail+1)); }; }

# a local stand-in for the remote, with one real commit
LOCAL="$TMP/skills"; mkdir -p "$LOCAL"; cd "$LOCAL"
git init -q; git config user.email c@x; git config user.name c
echo corpus > fixtures.json; git add -A; git -c commit.gpgsign=false commit -qm one
REAL=$(git rev-parse HEAD)
cd - >/dev/null

run(){ PIN_FILE="$TMP/pin" SKILLS_REMOTE="$LOCAL" "$SCRIPT" "$TMP/dest" >/dev/null 2>&1; echo $?; }

printf '%s\n' "$REAL" > "$TMP/pin";           ok "$(run)" 0 "healthy pin is ACCEPTED (positive control)"
printf '# only a comment\n' > "$TMP/pin";     ok "$(run)" 1 "comment-only pin file is refused"
: > "$TMP/pin";                               ok "$(run)" 1 "empty pin file is refused"
printf '%s\n' "${REAL:0:39}" > "$TMP/pin";    ok "$(run)" 1 "39-char SHA is refused"
printf '%s\n' "${REAL}a" > "$TMP/pin";        ok "$(run)" 1 "41-char SHA is refused"

printf 'main\n' > "$TMP/pin";                 ok "$(run)" 1 "a branch NAME is refused"
printf '%s\n' "$(printf %s "$REAL" | tr '[:lower:]' '[:upper:]')" > "$TMP/pin"
ok "$(run)" 1 "uppercase SHA is refused"
printf '%s\n' "$(printf '0%.0s' {1..40})" > "$TMP/pin"; ok "$(run)" 1 "well-formed but absent SHA is refused"
rm -f "$TMP/pin";                             ok "$(run)" 1 "missing pin file is refused"

# and prove the healthy case did real work, not a vacuous success
printf '%s\n' "$REAL" > "$TMP/pin"; run >/dev/null
got=$(git -C "$TMP/dest" rev-parse HEAD 2>/dev/null || echo none)
ok "$([ "$got" = "$REAL" ] && echo 0 || echo 1)" 0 "healthy run actually checked out the pinned commit"

# source-pin for the branch no harness can reach (see BOUND above)
grep -q '\[ "$got" = "$pin" \]' "$SCRIPT" && ok 0 0 "HEAD-vs-pin verification is present in the script" || ok 1 0 "HEAD-vs-pin verification is present in the script"

# A case that errors (bash-4-ism on macOS, a typo, a deleted block) simply stops
# producing its line — the suite then reports fewer passes and still exits 0. That
# happened to the uppercase case while writing this file. Pin the count.
EXPECTED=11
echo; echo "canary: $pass passed, $fail failed (expected $EXPECTED cases)"
[ $((pass+fail)) -eq "$EXPECTED" ] || { echo "FAIL  ran $((pass+fail)) cases, expected $EXPECTED — a case vanished"; exit 1; }
[ "$fail" -eq 0 ]
