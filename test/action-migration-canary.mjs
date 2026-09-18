import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const dir = mkdtempSync(join(tmpdir(), "amino-action-migration-canary-"));
const engine = readFileSync("vendor/amino-audit-engine/engine.mjs");
const index = readFileSync("src/index.mjs", "utf8");

function expectRed(name, env, diagnostic) {
  const result = spawnSync(process.execPath, ["test/engine-source-contract.mjs"], {
    cwd: root,
    env: { ...process.env, ...env },
    encoding: "utf8",
  });
  const output = `${result.stdout || ""}\n${result.stderr || ""}`;
  if (result.status === 0 || !output.includes(diagnostic)) {
    throw new Error(`${name} did not make the gate red with ${JSON.stringify(diagnostic)}\n${output}`);
  }
  console.log(`PASS ${name}: ${diagnostic}`);
}

function expectCommandRed(name, command, args, options, diagnostic) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  const output = `${result.stdout || ""}\n${result.stderr || ""}`;
  if (result.status === 0 || !output.includes(diagnostic)) {
    throw new Error(`${name} did not make the gate red with ${JSON.stringify(diagnostic)}\n${output}`);
  }
  console.log(`PASS ${name}: ${diagnostic}`);
}

try {
  const driftedEngine = join(dir, "engine.mjs");
  writeFileSync(driftedEngine, Buffer.concat([engine, Buffer.from("\n")]));
  expectRed("artifact byte-drift canary", { ENGINE_FILE: driftedEngine }, "FAIL shipped engine byte count is pinned");

  const sharedIndex = join(dir, "index.mjs");
  const wiringAnchor = "createAuditEngine(createDefaultAdapters()).auditDomain(domain)";
  if (index.split(wiringAnchor).length - 1 !== 1) {
    throw new Error("request-scoped wiring canary anchor must occur exactly once");
  }
  writeFileSync(sharedIndex, index.replace(
    wiringAnchor,
    "sharedEngine.auditDomain(domain)",
  ));
  expectRed("request-scoped adapter wiring canary", { INDEX_FILE: sharedIndex }, "FAIL Action creates default adapters inside each audit call");

  const oldEnginePin = join(dir, "old-engine.pin");
  writeFileSync(oldEnginePin, "33daa64671479c04c238d53ebda41e227867f3ed\n");
  expectCommandRed(
    "1.3.0 engine pin with 1.4.0 shipped bytes",
    "bash",
    ["scripts/verify-pinned-engine.sh", join(dir, "old-engine")],
    { cwd: root, env: { ...process.env, PIN_FILE: oldEnginePin } },
    "::error::committed engine copy differs byte-for-byte from the pinned canonical artifact",
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
