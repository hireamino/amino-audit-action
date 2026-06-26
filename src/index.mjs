// Amino Email Deliverability Audit — GitHub Action entrypoint.
//
// Zero third-party runtime deps. Reads action inputs from INPUT_* env vars,
// runs the vendored Amino audit engine over public DNS (read-only, no secrets),
// writes a GitHub job summary, sets outputs, optionally comments on a PR, and
// fails the build per the `fail-on` threshold (default: advisory = never fails).
//
// All logic that doesn't touch the network is exported so test/local.mjs can
// unit-test it with a stub resolver / synthetic findings.

import { auditDomain } from "./engine.mjs";

// ── Severity model ────────────────────────────────────────────────────────────
// Worst-first ordering. `pass` is not a failable severity.
export const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
export const FAIL_LEVELS = ["advisory", "low", "medium", "high", "critical"];
const MAX_DOMAINS = 50;

// ── Input parsing ─────────────────────────────────────────────────────────────

// Split on comma / whitespace / newline, trim, lowercase, dedupe, drop empties,
// drop syntactically-implausible entries, and cap the count to bound runtime.
export function parseDomains(raw, cap = MAX_DOMAINS) {
  const seen = new Set();
  const out = [];
  for (const tok of String(raw || "").split(/[\s,]+/)) {
    const d = tok.trim().replace(/^[.@]+/, "").replace(/\.+$/, "").toLowerCase();
    if (!d) continue;
    if (!looksLikeDomain(d)) continue;
    if (seen.has(d)) continue;
    seen.add(d);
    out.push(d);
    if (out.length >= cap) break;
  }
  return out;
}

// Loose syntactic gate (the engine re-validates strictly via its own DOMAIN_RE).
// Must have a dot, only DNS-legal chars, <=253 chars, labels 1..63, no leading '-'.
export function looksLikeDomain(d) {
  if (!d || d.length > 253 || !d.includes(".")) return false;
  return /^(?!-)[a-z0-9-]{1,63}(?:\.(?!-)[a-z0-9-]{1,63})+$/.test(d);
}

// Normalize the fail-on input to a known level; anything unknown → advisory.
export function normalizeFailOn(raw) {
  const v = String(raw || "").trim().toLowerCase();
  return FAIL_LEVELS.includes(v) ? v : "advisory";
}

// ── Threshold logic ───────────────────────────────────────────────────────────

// Worst (lowest-rank) failable severity present across all domains' findings,
// or null if there are no failable findings.
export function worstSeverity(results) {
  let worst = null;
  for (const r of results) {
    for (const f of r.findings || []) {
      const rank = SEV_RANK[f.severity];
      if (rank === undefined) continue; // pass / unknown
      if (worst === null || rank < SEV_RANK[worst]) worst = f.severity;
    }
  }
  return worst;
}

// Decide pass/fail. advisory never fails. Otherwise fail if any finding is
// at-or-worse-than the threshold (worse = lower rank number).
export function decide(results, failOn) {
  const level = normalizeFailOn(failOn);
  const worst = worstSeverity(results);
  if (level === "advisory") return { passed: true, worst, level, reason: advisoryReason(worst) };
  const threshold = SEV_RANK[level];
  const failed = results.some((r) =>
    (r.findings || []).some((f) => {
      const rank = SEV_RANK[f.severity];
      return rank !== undefined && rank <= threshold;
    })
  );
  return {
    passed: !failed,
    worst,
    level,
    reason: failed
      ? `Failing: found at least one finding at or worse than '${level}' (worst seen: ${worst}).`
      : `Passing: no finding at or worse than '${level}'${worst ? ` (worst seen: ${worst}).` : " (no issues)."}`,
  };
}

function advisoryReason(worst) {
  return worst
    ? `Advisory mode: never fails the build (worst seen: ${worst}). Set fail-on to enforce.`
    : "Advisory mode: never fails the build (no issues found).";
}

// ── Markdown rendering ────────────────────────────────────────────────────────

// Defang an attacker-influenced string for safe inclusion as PLAIN markdown text
// (table cells, prose). DNS-derived values are controlled by the audited domain's
// owner, and this output is also posted to PR comments under a token — so we must
// neutralize ACTIVE markdown, not just table structure: links/images (beacons),
// @mentions / #refs (notify third parties), code-span breakout, emphasis, raw
// HTML, and the table pipe. Backslash-escape every CommonMark-escapable punctuation
// that can start active syntax; strip control + zero-width chars.
export function mdCell(s) {
  return String(s == null ? "" : s)
    .replace(/[\x00-\x1f\x7f]/g, " ")
    .replace(/([\\`*_{}\[\]()#+!|<>@~])/g, "\\$1")
    .trim();
}

// Inside a backtick code span only a backtick is active; strip it (escaping won't help).
export function code(s) {
  return String(s == null ? "" : s)
    .replace(/[`\x00-\x1f\x7f]/g, " ")
    .trim();
}

const SEV_EMOJI = { critical: "🟥", high: "🟧", medium: "🟨", low: "⬜", pass: "✅" };

function verdictLine(r) {
  const s = r.summary || {};
  const counts = `critical ${s.critical || 0} · high ${s.high || 0} · medium ${s.medium || 0} · low ${s.low || 0} · pass ${s.pass || 0}`;
  const gaps = (s.critical || 0) + (s.high || 0) + (s.medium || 0) + (s.low || 0);
  const verdict = r.error
    ? "⚠️ audit error"
    : gaps === 0
      ? "✅ clean — no gaps found"
      : (s.critical || s.high)
        ? "❌ needs attention"
        : "⚠️ minor gaps";
  return { counts, verdict };
}

// Build the full job-summary markdown for all domains.
export function renderSummary(results, decision) {
  const lines = [];
  lines.push("## Amino Email Deliverability Audit");
  lines.push("");
  const badge = decision.passed ? "✅ **PASS**" : "❌ **FAIL**";
  lines.push(`${badge} — \`fail-on: ${decision.level}\`. ${decision.reason}`);
  lines.push("");

  for (const r of results) {
    const { counts, verdict } = verdictLine(r);
    lines.push(`### \`${code(r.domain)}\` — ${verdict}`);
    if (r.error) {
      lines.push("");
      lines.push(`> Audit failed: ${mdCell(r.error)}`);
      lines.push("");
      continue;
    }
    lines.push("");
    lines.push(`**${counts}**${r.primary_mx ? ` · primary MX: \`${code(r.primary_mx)}\`` : ""}`);
    lines.push("");
    const gaps = (r.findings || []).filter((f) => f.severity !== "pass");
    if (!gaps.length) {
      lines.push("_No issues found._");
      lines.push("");
      continue;
    }
    lines.push("| Severity | Area | Issue | Fix |");
    lines.push("| --- | --- | --- | --- |");
    for (const f of gaps) {
      const sev = `${SEV_EMOJI[f.severity] || ""} ${mdCell(f.severity)}`.trim();
      lines.push(`| ${sev} | ${mdCell(f.area)} | ${mdCell(f.title)} | ${mdCell(f.action || f.fix || "")} |`);
    }
    lines.push("");
  }

  lines.push("---");
  lines.push("Powered by [Amino](https://hireamino.com/audit) — read-only, no secrets. Run the full audit at [hireamino.com/audit](https://hireamino.com/audit).");
  return lines.join("\n");
}

// Compact one-line-per-domain log for the console.
export function renderConsole(results, decision) {
  const lines = [];
  for (const r of results) {
    if (r.error) {
      lines.push(`  ${r.domain}: ERROR — ${r.error}`);
      continue;
    }
    const s = r.summary || {};
    lines.push(
      `  ${r.domain}: critical=${s.critical || 0} high=${s.high || 0} medium=${s.medium || 0} low=${s.low || 0} pass=${s.pass || 0}`
    );
  }
  lines.push(`  verdict: ${decision.passed ? "PASS" : "FAIL"} (fail-on=${decision.level}, worst=${decision.worst || "none"})`);
  return lines.join("\n");
}

// Compact per-domain counts JSON for the `summary` output.
export function summaryOutput(results) {
  return JSON.stringify(
    results.map((r) => ({ domain: r.domain, ...(r.error ? { error: true } : r.summary) }))
  );
}

// ── GitHub glue (env/files only — no third-party deps) ────────────────────────

function readInput(name) {
  // GitHub maps input `foo-bar` → INPUT_FOO-BAR (uppercased; spaces → _).
  const key = "INPUT_" + name.toUpperCase().replace(/ /g, "_");
  return process.env[key] ?? "";
}

async function appendFile(envVar, text) {
  const path = process.env[envVar];
  if (!path) return;
  const { appendFile: af } = await import("node:fs/promises");
  await af(path, text);
}

async function writeSummary(md) {
  await appendFile("GITHUB_STEP_SUMMARY", md + "\n");
}

async function setOutput(name, value) {
  // Use the heredoc form so multiline/JSON values are safe.
  const delim = "EOF_" + Math.random().toString(36).slice(2);
  await appendFile("GITHUB_OUTPUT", `${name}<<${delim}\n${value}\n${delim}\n`);
}

// ── PR comment (fail-soft, contained text) ────────────────────────────────────

async function maybeCommentOnPr(md, token) {
  try {
    if (process.env.GITHUB_EVENT_NAME !== "pull_request") return;
    if (!token) return;
    const repo = process.env.GITHUB_REPOSITORY || "";
    const [owner, name] = repo.split("/");
    if (!owner || !name) return;

    let prNumber = null;
    const eventPath = process.env.GITHUB_EVENT_PATH;
    if (eventPath) {
      const { readFile } = await import("node:fs/promises");
      const payload = JSON.parse(await readFile(eventPath, "utf8"));
      prNumber = payload?.pull_request?.number ?? payload?.number ?? null;
    }
    if (!prNumber) return;

    // The body is markdown we generated from our own escaped cells; wrap is fine.
    const res = await fetch(
      `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/issues/${encodeURIComponent(String(prNumber))}/comments`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          accept: "application/vnd.github+json",
          "content-type": "application/json",
          "x-github-api-version": "2022-11-28",
          "user-agent": "amino-audit-action",
        },
        body: JSON.stringify({ body: md }),
        signal: AbortSignal.timeout(10000),
      }
    );
    if (!res.ok) {
      console.log(`  (PR comment skipped: GitHub API returned ${res.status})`);
    } else {
      console.log("  Posted audit summary as a PR comment.");
    }
  } catch (e) {
    // Fail-soft: a comment failure must never fail the action. Don't log secrets.
    console.log(`  (PR comment skipped: ${e && e.message ? e.message : "error"})`);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

export async function run() {
  const domains = parseDomains(readInput("domains"));
  const failOn = normalizeFailOn(readInput("fail-on"));
  const commentOnPr = String(readInput("comment-on-pr")).trim().toLowerCase() === "true";
  const token = readInput("github-token");

  if (!domains.length) {
    const md = "## Amino Email Deliverability Audit\n\n⚠️ No valid domains were provided in the `domains` input.";
    await writeSummary(md);
    console.log("No valid domains provided. Nothing to audit.");
    await setOutput("passed", "true");
    await setOutput("worst-severity", "none");
    await setOutput("summary", "[]");
    process.exit(0);
    return;
  }

  console.log(`Auditing ${domains.length} domain(s): ${domains.join(", ")}`);

  const results = [];
  for (const domain of domains) {
    try {
      const r = await auditDomain(domain);
      results.push(r);
    } catch (e) {
      // One bad domain must not abort the run — record an error "finding".
      results.push({
        domain,
        primary_mx: null,
        error: e && e.message ? e.message : "audit failed",
        summary: { critical: 0, high: 0, medium: 0, low: 0, pass: 0 },
        findings: [],
      });
    }
  }

  const decision = decide(results, failOn);
  const md = renderSummary(results, decision);

  await writeSummary(md);
  console.log(renderConsole(results, decision));
  console.log(decision.reason);

  await setOutput("passed", String(decision.passed));
  await setOutput("worst-severity", decision.worst || "none");
  await setOutput("summary", summaryOutput(results));

  if (commentOnPr) await maybeCommentOnPr(md, token);

  process.exit(decision.passed ? 0 : 1);
}

// Only auto-run when invoked directly as the action entrypoint — not when this
// module is imported (e.g. by the test harness). Robust to ESM import hoisting:
// compares the resolved module URL against the script path Node was launched with.
import { pathToFileURL } from "node:url";
const invokedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  run();
}
