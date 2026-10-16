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

const expectedIndex = baselineIndex
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

if (expectedIndex === baselineIndex) {
  throw new Error("host-surface equivalence transformations did not match the immutable baseline");
}
if (currentIndex !== expectedIndex) {
  throw new Error("src/index.mjs changed outside the reviewed import, N3 comment, and per-audit wiring substitutions");
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
console.log("Action host-surface equivalence PASS: index output, fail-on, finalize, rendering and exit logic are byte-identical outside the three migration substitutions.");
