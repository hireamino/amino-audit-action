// Local test harness — pure-logic unit tests with synthetic findings + one live
// smoke test against hireamino.com. Prints PASS/FAIL per check; exits non-zero on
// any failure. No third-party deps.
//
// index.mjs only auto-runs when invoked directly (import.meta.url check), so
// importing it here does NOT trigger the action.

import {
  parseDomains,
  looksLikeDomain,
  normalizeFailOn,
  worstSeverity,
  decide,
  mdCell,
  code,
  renderSummary,
  summaryOutput,
} from "../src/index.mjs";
import { auditDomain } from "../src/engine.mjs";

let pass = 0;
let fail = 0;
function check(name, cond) {
  if (cond) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    console.log(`  FAIL  ${name}`);
  }
}

// Synthetic results helper.
function mkResult(domain, sevs) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, pass: 0 };
  const findings = sevs.map((s, i) => {
    summary[s] = (summary[s] || 0) + 1;
    return {
      area: "SPF",
      severity: s,
      title: `synthetic ${s} #${i}`,
      detail: "d",
      action: s === "pass" ? null : `fix ${s}`,
    };
  });
  return { domain, primary_mx: "mx.example.com", summary, findings };
}

console.log("== domains parsing ==");
check("comma + space + newline split", JSON.stringify(parseDomains("a.com, b.com\nc.com d.com")) === JSON.stringify(["a.com", "b.com", "c.com", "d.com"]));
check("dedupe (case-insensitive)", JSON.stringify(parseDomains("A.com a.com a.COM")) === JSON.stringify(["a.com"]));
check("drops empties / stray separators", JSON.stringify(parseDomains(" , ,  x.com , ")) === JSON.stringify(["x.com"]));
check("strips leading @ / trailing dot", JSON.stringify(parseDomains("@x.com. ")) === JSON.stringify(["x.com"]));
check("drops bare (no-dot) tokens", parseDomains("localhost foo bar.com").join(",") === "bar.com");
check("cap is enforced", parseDomains(Array.from({ length: 80 }, (_, i) => `d${i}.com`).join(" "), 50).length === 50);
check("empty input → []", parseDomains("").length === 0);

console.log("== looksLikeDomain ==");
check("accepts normal domain", looksLikeDomain("hireamino.com") === true);
check("accepts subdomain", looksLikeDomain("mail.hireamino.com") === true);
check("rejects no-dot", looksLikeDomain("localhost") === false);
check("rejects leading dash label", looksLikeDomain("-bad.com") === false);
check("rejects spaces", looksLikeDomain("a b.com") === false);

console.log("== normalizeFailOn ==");
check("known level passes through", normalizeFailOn("HIGH") === "high");
check("unknown → advisory", normalizeFailOn("bogus") === "advisory");
check("empty → advisory", normalizeFailOn("") === "advisory");

console.log("== worstSeverity ==");
check("picks critical over high", worstSeverity([mkResult("a", ["high", "critical", "low"])]) === "critical");
check("ignores pass", worstSeverity([mkResult("a", ["pass", "low"])]) === "low");
check("null when no failable findings", worstSeverity([mkResult("a", ["pass"])]) === null);
check("aggregates across domains", worstSeverity([mkResult("a", ["low"]), mkResult("b", ["high"])]) === "high");

console.log("== fail-on threshold logic ==");
// advisory never fails
check("advisory never fails (even with critical)", decide([mkResult("a", ["critical"])], "advisory").passed === true);
check("advisory never fails (clean)", decide([mkResult("a", ["pass"])], "advisory").passed === true);
// high
check("high fails when a high finding exists", decide([mkResult("a", ["high"])], "high").passed === false);
check("high fails when a critical exists (worse than threshold)", decide([mkResult("a", ["critical"])], "high").passed === false);
check("high passes when only low/medium exist", decide([mkResult("a", ["low", "medium"])], "high").passed === true);
check("high passes when only low exists", decide([mkResult("a", ["low"])], "high").passed === true);
// medium
check("medium fails on a medium finding", decide([mkResult("a", ["medium"])], "medium").passed === false);
check("medium passes when only low", decide([mkResult("a", ["low"])], "medium").passed === true);
// low
check("low fails on a low finding", decide([mkResult("a", ["low"])], "low").passed === false);
check("low passes when clean", decide([mkResult("a", ["pass"])], "low").passed === true);
// critical
check("critical fails only on critical", decide([mkResult("a", ["critical"])], "critical").passed === false);
check("critical passes on high", decide([mkResult("a", ["high"])], "critical").passed === true);
// reason string present
check("decision carries a reason", typeof decide([mkResult("a", ["high"])], "high").reason === "string" && decide([mkResult("a", ["high"])], "high").reason.length > 0);

console.log("== mdCell / code: comment-grade defanging (SEC) ==");
check("escapes pipe", mdCell("a|b") === "a\\|b");
check("strips control chars (newline → space)", mdCell("a\nb") === "a b");
check("backslash-escapes angle brackets (no raw HTML)", mdCell("<x>") === "\\<x\\>");
// HIGH fix: attacker-controlled DNS values must not yield ACTIVE markdown in a PR comment.
check("defangs image beacon", mdCell("![x](https://evil.tld/b.png)").startsWith("\\!\\["));
check("defangs link", mdCell("[a](javascript:alert(1))").startsWith("\\["));
check("escapes @mention", mdCell("@octocat") === "\\@octocat");
check("escapes #ref", mdCell("#1") === "\\#1");
check("escapes backtick", mdCell("`x`") === "\\`x\\`");
// code() is for values inside a backtick code span — it STRIPS backticks (escaping won't help there).
check("code() strips backticks (no span breakout)", !code("a`b`c").includes("`"));
check("code() leaves a plain host intact", code("mx1.example.com") === "mx1.example.com");
// render-level guard: a malicious finding title cannot emit an active image into the summary/comment.
check("renderSummary defangs a malicious finding title", !renderSummary([
  { domain: "evil.test", summary: { critical: 0, high: 0, medium: 1, low: 0, pass: 0 },
    findings: [{ severity: "medium", area: "SPF", title: "![beacon](https://evil.tld/x.png)", action: "fix" }] },
], { passed: true, level: "advisory", reason: "advisory" }).includes("![beacon]"));

console.log("== job-summary markdown ==");
{
  const results = [mkResult("a.com", ["high", "medium", "pass"])];
  const decision = decide(results, "advisory");
  const md = renderSummary(results, decision);
  check("summary has a table header", md.includes("| Severity | Area | Issue | Fix |"));
  // one row per non-pass finding (2 here)
  const rows = md.split("\n").filter((l) => l.startsWith("| ") && !l.includes("Severity") && !l.includes("---"));
  check("one row per non-pass finding", rows.length === 2);
  check("row contains the fix text", md.includes("fix high"));
  check("clean domain renders 'no issues'", renderSummary([mkResult("b.com", ["pass"])], decide([mkResult("b.com", ["pass"])], "advisory")).includes("No issues found"));
  check("footer credits Amino", md.includes("hireamino.com"));
}

console.log("== error-domain handling in summary ==");
{
  const errResult = { domain: "broken.invalid", primary_mx: null, error: "no such host", summary: { critical: 0, high: 0, medium: 0, low: 0, pass: 0 }, findings: [] };
  const decision = decide([errResult], "high");
  const md = renderSummary([errResult], decision);
  check("error domain doesn't fail the build by itself", decision.passed === true);
  check("error domain shown in summary", md.includes("Audit failed: no such host"));
}

console.log("== summaryOutput JSON ==");
{
  const out = JSON.parse(summaryOutput([mkResult("a.com", ["high", "pass"])]));
  check("summaryOutput is valid JSON array", Array.isArray(out) && out.length === 1);
  check("summaryOutput carries domain + counts", out[0].domain === "a.com" && out[0].high === 1);
}

// ── Live smoke test (DoH works in this env) ───────────────────────────────────
console.log("== live smoke: auditDomain('hireamino.com') ==");
try {
  const r = await auditDomain("hireamino.com");
  check("returns a findings array", Array.isArray(r.findings) && r.findings.length > 0);
  check("returns a summary object", r.summary && typeof r.summary.pass === "number");
  check("findings carry severity + area", r.findings.every((f) => f.severity && f.area));
  check("non-pass findings carry an action", r.findings.filter((f) => f.severity !== "pass").every((f) => typeof f.action === "string" && f.action.length > 0));
  // end-to-end render shouldn't throw
  const dec = decide([r], "advisory");
  const md = renderSummary([r], dec);
  check("renders a non-empty summary for the live result", md.length > 200);
} catch (e) {
  check(`live smoke test threw: ${e.message}`, false);
}

console.log("");
console.log(`Results: ${pass} passed, ${fail} failed.`);
process.exit(fail ? 1 : 0);
