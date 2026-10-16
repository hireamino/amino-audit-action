import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const dir = mkdtempSync(join(tmpdir(), "amino-action-migration-canary-"));
const index = readFileSync("src/index.mjs", "utf8");

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
  // Healthy control first: a broken Action-specific detector must not get
  // credit for rejecting its wiring mutations. Engine identity mutations are
  // owned once by the pinned engine's shared consumer-copy verifier suite.
  const healthy = runContract();
  if (healthy.status !== 0) throw new Error(`healthy Action source/wiring contract is red\n${outputOf(healthy)}`);
  console.log("PASS healthy Action source/wiring contract is green");

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
