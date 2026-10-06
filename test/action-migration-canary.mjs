import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const dir = mkdtempSync(join(tmpdir(), "amino-action-migration-canary-"));
const engine = readFileSync("vendor/amino-audit-engine/engine.mjs");
const provenance = JSON.parse(readFileSync("vendor/amino-audit-engine/provenance.json", "utf8"));
const index = readFileSync("src/index.mjs", "utf8");
const base = "996b7525234755de9ea6dc51fe5ad3b29a65f073";

function runContract(env = {}) {
  return spawnSync(process.execPath, ["test/engine-source-contract.mjs"], {
    cwd: root,
    env: { ...process.env, ...env },
    encoding: "utf8",
  });
}

function outputOf(result) {
  return `${result.stdout || ""}\n${result.stderr || ""}`;
}

function expectContractRed(name, env, diagnostic) {
  const result = runContract(env);
  const output = outputOf(result);
  if (result.status === 0 || !output.includes(diagnostic)) {
    throw new Error(`${name} did not make the gate red with ${JSON.stringify(diagnostic)}\n${output}`);
  }
  console.log(`PASS ${name}: ${diagnostic}`);
}

function expectCommandRed(name, command, args, options, diagnostic) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  const output = outputOf(result);
  if (result.status === 0 || !output.includes(diagnostic)) {
    throw new Error(`${name} did not make the gate red with ${JSON.stringify(diagnostic)}\n${output}`);
  }
  console.log(`PASS ${name}: ${diagnostic}`);
}

try {
  // Healthy control first: a broken detector must not get credit for rejecting mutations.
  const healthy = runContract();
  if (healthy.status !== 0) throw new Error(`healthy engine identity contract is red\n${outputOf(healthy)}`);
  console.log("PASS C5 healthy engine identity contract is green");

  const oldArtifactResult = spawnSync(
    "git",
    ["show", `${base}:vendor/amino-audit-engine/engine.mjs`],
    { cwd: root, encoding: "buffer" },
  );
  if (oldArtifactResult.status !== 0) throw new Error("could not read the immutable 1.4.0 artifact");
  const oldArtifact = join(dir, "engine-1.4.0.mjs");
  writeFileSync(oldArtifact, oldArtifactResult.stdout);
  expectContractRed(
    "C5.1 engine pin bumped but artifact left at 1.4.0",
    { ENGINE_FILE: oldArtifact },
    "FAIL shipped engine byte count is pinned",
  );

  const oldEnginePin = join(dir, "engine-1.4.0.pin");
  writeFileSync(oldEnginePin, "15775c593d6eddf215c4172ab72dbd43670e3f35\n");
  expectContractRed(
    "C5.2 artifact replaced but engine pin left at 1.4.0",
    { ENGINE_PIN_FILE: oldEnginePin },
    "FAIL engine pin is the reviewed 1.5.0 merge SHA",
  );

  const staleShaProvenance = join(dir, "provenance-stale-sha.json");
  writeFileSync(staleShaProvenance, `${JSON.stringify({
    ...provenance,
    sha256: "978cd28742f3e5ab57293d76d8681fcb5ec3fa75d235929a05c19ac8db9e460e",
  }, null, 2)}\n`);
  expectContractRed(
    "C5.3 provenance SHA-256 left at 1.4.0",
    { PROVENANCE_FILE: staleShaProvenance },
    "FAIL shipped engine SHA-256 is pinned",
  );

  const staleVersionProvenance = join(dir, "provenance-stale-version.json");
  writeFileSync(staleVersionProvenance, `${JSON.stringify({
    ...provenance,
    contractVersion: "1.4.0",
  }, null, 2)}\n`);
  expectContractRed(
    "C5.4 provenance contractVersion left at 1.4.0",
    { PROVENANCE_FILE: staleVersionProvenance },
    "FAIL contract version is pinned",
  );

  const oldSkillsPin = join(dir, "skills-1.4.0.pin");
  writeFileSync(oldSkillsPin, "2558a593ec8aacb816bf3cd91821c32433a3b341\n");
  expectContractRed(
    "C5.5 skills pin left at the 1.4.0 contract revision",
    { SKILLS_PIN_FILE: oldSkillsPin },
    "FAIL skills pin is the engine's reviewed 1.5.0 contract pin",
  );

  const oneByteAltered = join(dir, "engine-one-byte-altered.mjs");
  const altered = Buffer.from(engine);
  altered[10] ^= 1;
  writeFileSync(oneByteAltered, altered);
  expectContractRed(
    "C5.6 one byte altered inside the vendored artifact",
    { ENGINE_FILE: oneByteAltered },
    "FAIL shipped engine SHA-256 is pinned",
  );
  console.log("WHI-220 identity mutation canaries PASS: 6/6");

  // Keep the pre-existing host-wiring guards load-bearing.
  const sharedIndex = join(dir, "index.mjs");
  const wiringAnchor = "createAuditEngine(createDefaultAdapters()).auditDomain(domain)";
  if (index.split(wiringAnchor).length - 1 !== 1) {
    throw new Error("request-scoped wiring canary anchor must occur exactly once");
  }
  writeFileSync(sharedIndex, index.replace(wiringAnchor, "sharedEngine.auditDomain(domain)"));
  expectContractRed(
    "request-scoped adapter wiring canary",
    { INDEX_FILE: sharedIndex },
    "FAIL Action creates default adapters inside each audit call",
  );

  const mismatchedSkillsPin = join(dir, "mismatched-skills.pin");
  writeFileSync(mismatchedSkillsPin, `${"0".repeat(40)}\n`);
  expectCommandRed(
    "consumer and engine skills pins must match",
    "bash",
    ["scripts/verify-pinned-engine.sh", join(dir, "current-engine")],
    { cwd: root, env: { ...process.env, SKILLS_PIN_FILE: mismatchedSkillsPin } },
    "::error::consumer skills pin 0000000000000000000000000000000000000000 does not equal pinned engine skills pin",
  );

  const driftClone = join(dir, "index-drift-clone");
  const clone = spawnSync("git", ["clone", "--quiet", "--no-hardlinks", root, driftClone], { encoding: "utf8" });
  if (clone.status !== 0) throw new Error(`could not clone the committed head for the host-surface canary\n${clone.stderr}`);
  appendFileSync(join(driftClone, "src/index.mjs"), " ");
  const baselineIndex = join(dir, "baseline-index.mjs");
  const baselineAction = join(dir, "baseline-action.yml");
  for (const [spec, destination] of [
    ["ae04a363f76da800ac6d98a3647cf5bf5ab7e44a:src/index.mjs", baselineIndex],
    ["ae04a363f76da800ac6d98a3647cf5bf5ab7e44a:action.yml", baselineAction],
  ]) {
    const shown = spawnSync("git", ["show", spec], { cwd: root, encoding: "buffer" });
    if (shown.status !== 0) throw new Error(`could not read immutable baseline ${spec}`);
    writeFileSync(destination, shown.stdout);
  }
  expectCommandRed(
    "one-byte Action entrypoint drift",
    process.execPath,
    ["test/host-surface-equivalence.mjs"],
    {
      cwd: driftClone,
      env: { ...process.env, BASELINE_INDEX: baselineIndex, BASELINE_ACTION: baselineAction },
    },
    "src/index.mjs changed outside the reviewed import, N3 comment, and per-audit wiring substitutions",
  );
} finally {
  rmSync(dir, { recursive: true, force: true });
}
