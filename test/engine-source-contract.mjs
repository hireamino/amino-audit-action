import { readFileSync } from "node:fs";

const enginePath = process.env.ENGINE_FILE || new URL("../vendor/amino-audit-engine/engine.mjs", import.meta.url);
const indexPath = process.env.INDEX_FILE || new URL("../src/index.mjs", import.meta.url);

const bytes = readFileSync(enginePath);
const source = bytes.toString("utf8");
const indexSource = readFileSync(indexPath, "utf8");

let passed = 0;
let failed = 0;
function assert(name, condition) {
  console.log(`${condition ? "PASS" : "FAIL"} ${name}`);
  if (condition) passed += 1;
  else failed += 1;
}

// Relocated from test/conformance.mjs. These inspect the shipped canonical
// artifact, while behavioral Action output/fail-on/finalize checks stay in their
// original harnesses.
// The first eight claim checks guarded the old file's Pages result renderer and
// FAQ, neither of which belongs in the Action runtime. Their relocated contract
// is now deletion: none of that host-only content may re-enter the shipped engine.
assert("Pages empty-quadrant renderer is not shipped", !/DKIM &amp; DMARC enforced<\/li>/.test(source));
assert("Pages all-clear renderer is not shipped", !/const clean = gaps\.length === 0/.test(source));
assert("Pages np= FAQ is not shipped", !/cousin-domain spoofing|NON-EXISTENT subdomains of your domain/.test(source));
assert("Pages IR 8547 FAQ is not shipped", !/IR 8547/.test(source));
assert("Pages PQC FAQ is not shipped", !/standardized post-quantum path/.test(source));
assert("Pages read-only FAQ is not shipped", !/fetches your published MTA-STS policy over HTTPS/.test(source));
assert("Pages bulk-sender FAQ is not shipped", !/Google explicitly allows that policy to be p=none/.test(source));
assert("Pages unsubscribe FAQ is not shipped", !/marketing and subscribed messages specifically/.test(source));
assert("pct= not recommended for staging", !/optionally with pct= staging/.test(source));
assert("the pct removal is stated", /RFC 9989 removed pct/.test(source));
assert("MTA-STS rollout staged via testing", /start at mode: testing/.test(source));
assert("MTA-STS cites BSI, not NIS2", !/growing compliance ask under NIS2/.test(source));
assert("§7.4 reject is not framed as the destination", !/ramp to p=quarantine/.test(source));
assert("§7.4 no unevidenced provider trust-signal claim", !/increasingly treat enforced policies as a trust signal/.test(source));
assert("§7.4 no claim that p=reject is 'the goal'", !/which is the goal and what large mailbox providers/.test(source));
assert("§7.4 p=none is not called the most common deliverability mistake", !/most common deliverability mistake/.test(source));
assert("§7.4 mailing-list caution is stated and scoped", /users may post to mailing lists not to publish p=reject/.test(source));
assert("§7.4 staging advice is scoped, not universal", /for those that still do, it recommends at least a month/.test(source));
assert("§7.4 DKIM-not-SPF-alone prerequisite is stated", /DMARC-aligned DKIM rather than relying only on SPF/.test(source));
assert("t=y is offered in place of the removed pct", /use t=y to test an enforcement policy/.test(source));
assert("Pages dated Google allowance is not shipped", !/As of August 2026, Google's bulk-sender guidance permits p=none/.test(source));

assert("Action imports only the pinned shipped engine", /from "\.\.\/vendor\/amino-audit-engine\/engine\.mjs"/.test(indexSource));
assert("Action creates default adapters inside each audit call", /createAuditEngine\(createDefaultAdapters\(\)\)\.auditDomain\(domain\)/.test(indexSource));
assert("Action does not pass a resolver through the legacy q parameter", !/auditDomain\(domain\s*,/.test(indexSource));
assert("deleted Pages engine is not imported", !/from "\.\/engine\.mjs"/.test(indexSource));
assert("DOMAIN_RE comment does not claim canonical re-validation", !/engine re-validates strictly via its own DOMAIN_RE/.test(indexSource));

console.log(`Shipped canonical artifact loaded for Action-only source checks: ${bytes.length} bytes.`);
console.log(`Engine source/wiring contract: ${passed} passed, ${failed} failed.`);
if (failed) process.exit(1);
