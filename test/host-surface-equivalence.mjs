import { readFileSync } from "node:fs";

const baselineIndexPath = process.env.BASELINE_INDEX;
const baselineActionPath = process.env.BASELINE_ACTION;
if (!baselineIndexPath || !baselineActionPath) {
  console.error("BASELINE_INDEX and BASELINE_ACTION are required");
  process.exit(2);
}

const baselineIndex = readFileSync(baselineIndexPath, "utf8");
const baselineAction = readFileSync(baselineActionPath);
const currentIndex = readFileSync("src/index.mjs", "utf8");
const currentAction = readFileSync("action.yml");

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
if (!currentAction.equals(baselineAction)) {
  throw new Error("action.yml changed: Action inputs, outputs or runtime interface are not byte-identical to ae04a36");
}

console.log("Action host-surface equivalence PASS: action.yml is byte-identical to ae04a36.");
console.log("Action host-surface equivalence PASS: index output, fail-on, finalize, rendering and exit logic are byte-identical outside the three migration substitutions.");
