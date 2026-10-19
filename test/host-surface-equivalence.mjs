import { readFileSync } from "node:fs";

const baselineIndexPath = process.env.BASELINE_INDEX;
const baselineActionPath = process.env.BASELINE_ACTION;
if (!baselineIndexPath || !baselineActionPath) {
  console.error("BASELINE_INDEX and BASELINE_ACTION are required");
  process.exit(2);
}

const baselineIndex = readFileSync(baselineIndexPath, "utf8");
const baselineAction = readFileSync(baselineActionPath, "utf8");
const currentIndex = readFileSync("src/index.mjs", "utf8");
const currentAction = readFileSync("action.yml", "utf8");

let expectedIndex = baselineIndex
  .replace(
    'import { auditDomain } from "./engine.mjs";',
    'import { createAuditEngine, createDefaultAdapters } from "../vendor/amino-audit-engine/engine.mjs";',
  )
  .replace(
    "// Loose syntactic gate (the engine re-validates strictly via its own DOMAIN_RE).",
    "// Loose syntactic gate for Action input hygiene; the canonical engine expects a\n// validated domain and does not independently apply this DOMAIN_RE.",
  )
  .replace(
    "      const r = await auditDomain(domain);",
    "      // The default adapters cache DNS for their lifetime with no TTL. Constructing\n" +
      "      // both inside the audit call prevents stale state crossing domains or runs.\n" +
      "      const r = await createAuditEngine(createDefaultAdapters()).auditDomain(domain);",
  );

const legacyDisplayBlock = "    lines.push(`### \\`${code(r.domain)}\\` — ${verdict}`);\n    if (r.error) {\n      lines.push(\"\");\n      lines.push(`> Audit failed: ${mdCell(r.error)}`);\n      lines.push(\"\");\n      continue;\n    }\n    lines.push(\"\");\n    lines.push(`**${counts}**${r.primary_mx ? ` · primary MX: \\`${code(r.primary_mx)}\\`` : \"\"}`);\n    lines.push(\"\");\n    const gaps = (r.findings || []).filter((f) => f.severity !== \"pass\");\n    if (!gaps.length) {\n      lines.push(\"_No issues found._\");\n      lines.push(\"\");\n      continue;\n    }\n    lines.push(\"| Severity | Area | Issue | Fix |\");\n    lines.push(\"| --- | --- | --- | --- |\");\n    for (const f of gaps) {\n      const sev = `${SEV_EMOJI[f.severity] || \"\"} ${mdCell(f.severity)}`.trim();\n      lines.push(`| ${sev} | ${mdCell(f.area)} | ${mdCell(f.title)} | ${mdCell(f.action || f.fix || \"\")} |`);\n    }\n    lines.push(\"\");\n    // The table cell carries f.action, which is a short verb-led LABEL — deliberately so,\n    // since it also renders as a 2x2 tile on the web tool. Until now that label was the\n    // only remediation text this action emitted anywhere: f.fix and f.detail were built\n    // and then dropped, and the `summary` output carries severity counts, not findings.\n    // So the conditions attached to a fix (for DMARC: the RFC 9989 section 7.4 caveats on\n    // p=reject) never reached anyone running this in CI. Render fix behind a disclosure.\n    const fixes = gaps.filter((f) => f.fix);\n    if (fixes.length) {\n      lines.push(\"<details><summary>What to do about each of these</summary>\");\n      lines.push(\"\");\n      for (const f of fixes) lines.push(`- **${mdCell(f.title)}** — ${mdCell(f.fix)}`);\n      lines.push(\"\");\n      lines.push(\"</details>\");\n      lines.push(\"\");\n    }\n  }\n";
const reviewedDisplayBlock = "    lines.push(`### \\`${code(r.domain)}\\` — ${verdict}`);\n    if (r.inconclusive && r.inconclusive_reason) {\n      lines.push(\"\");\n      lines.push(`> We couldn't finish checking this domain. A DNS lookup failed (\\`${code(r.inconclusive_reason)}\\`), so anything reported below as missing may be wrong, especially findings marked Not confirmed. Re-run before acting on it.`);\n    }\n    if (r.error) {\n      lines.push(\"\");\n      lines.push(`> Audit failed: ${mdCell(r.error)}`);\n      lines.push(\"\");\n      continue;\n    }\n    lines.push(\"\");\n    lines.push(`**${counts}**${r.primary_mx ? ` · primary MX: \\`${code(r.primary_mx)}\\`` : \"\"}`);\n    lines.push(\"\");\n    const gaps = (r.findings || []).filter((f) => f.severity !== \"pass\");\n    if (!gaps.length) {\n      lines.push(\"_No issues found._\");\n      lines.push(\"\");\n      continue;\n    }\n    lines.push(\"| Severity | Area | Issue | Fix |\");\n    lines.push(\"| --- | --- | --- | --- |\");\n    for (const f of gaps) {\n      const sev = `${SEV_EMOJI[f.severity] || \"\"} ${mdCell(f.severity)}`.trim();\n      const issue = f.unconfirmed ? `${f.title} (Not confirmed: ${f.unconfirmed})` : f.title;\n      lines.push(`| ${sev} | ${mdCell(f.area)} | ${mdCell(issue)} | ${mdCell(f.action || f.fix || \"\")} |`);\n    }\n    lines.push(\"\");\n    // The table cell carries f.action, which is a short verb-led LABEL — deliberately so,\n    // since it also renders as a 2x2 tile on the web tool. Until now that label was the\n    // only remediation text this action emitted anywhere: f.fix and f.detail were built\n    // and then dropped, and the `summary` output carries severity counts, not findings.\n    // So the conditions attached to a fix (for DMARC: the RFC 9989 section 7.4 caveats on\n    // p=reject) never reached anyone running this in CI. Render fix behind a disclosure.\n    const fixes = gaps.filter((f) => f.fix);\n    if (fixes.length) {\n      lines.push(\"<details><summary>What to do about each of these</summary>\");\n      lines.push(\"\");\n      for (const f of fixes) {\n        const fix = f.unconfirmed ? `Re-run the check first. If it's still reported: ${f.fix}` : f.fix;\n        lines.push(`- **${mdCell(f.title)}** — ${mdCell(fix)}`);\n      }\n      lines.push(\"\");\n      lines.push(\"</details>\");\n      lines.push(\"\");\n    }\n  }\n";
if (expectedIndex.split(legacyDisplayBlock).length - 1 !== 1) {
  throw new Error("immutable Action baseline must contain the legacy summary display block exactly once");
}
expectedIndex = expectedIndex.replace(legacyDisplayBlock, reviewedDisplayBlock);

if (expectedIndex === baselineIndex) {
  throw new Error("host-surface equivalence transformations did not match the immutable baseline");
}
if (!currentIndex.includes(reviewedDisplayBlock)) {
  throw new Error("reviewed Not confirmed display block is missing or changed");
}
if (currentIndex !== expectedIndex) {
  throw new Error("src/index.mjs changed outside the reviewed import, N3 comment, per-audit wiring, and Not confirmed display substitutions");
}

const baselineRuntime = '  using: "node20"';
const reviewedRuntime = '  using: "node24"';
if (baselineAction.split(baselineRuntime).length - 1 !== 1) {
  throw new Error("immutable action.yml baseline must contain the Node 20 runtime exactly once");
}
const expectedAction = baselineAction.replace(baselineRuntime, reviewedRuntime);
if (currentAction === baselineAction) {
  throw new Error("action.yml still declares node20; expected the reviewed node24 runtime substitution");
}
if (!currentAction.includes(reviewedRuntime)) {
  throw new Error("action.yml runtime must be node24");
}
if (currentAction !== expectedAction) {
  throw new Error("action.yml changed outside the reviewed node20 to node24 runtime substitution");
}

console.log("Action host-surface equivalence PASS: action.yml differs from ae04a36 only by the reviewed node20 to node24 runtime substitution.");
console.log("Action host-surface equivalence PASS: index output, fail-on, finalize and exit logic are byte-identical outside the three migration substitutions and reviewed Not confirmed display block.");
