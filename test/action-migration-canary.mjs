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

function engineCopyWithMutation(name, anchor, replacement) {
  const source = readFileSync("vendor/amino-audit-engine/engine.mjs", "utf8");
  if (source.split(anchor).length - 1 !== 1) {
    throw new Error(`${name} engine canary anchor must occur exactly once`);
  }
  const destination = join(dir, `${name}.mjs`);
  writeFileSync(destination, source.replace(anchor, () => replacement));
  return destination;
}

function expectSeamRed(name, engineFile, diagnostic) {
  expectCommandRed(
    name,
    process.execPath,
    ["test/engine-adapter-seam.mjs"],
    { cwd: root, env: { ...process.env, ENGINE_FILE: engineFile } },
    diagnostic,
  );
}

function cloneCommittedHead(name) {
  const destination = join(dir, name);
  const clone = spawnSync("git", ["clone", "--quiet", "--no-hardlinks", root, destination], { encoding: "utf8" });
  if (clone.status !== 0) throw new Error(`could not clone the committed head for ${name}\n${clone.stderr}`);
  return destination;
}

function replaceActionRuntime(cloneDir, replacement) {
  const actionPath = join(cloneDir, "action.yml");
  const action = readFileSync(actionPath, "utf8");
  const anchor = '  using: "node24"';
  if (action.split(anchor).length - 1 !== 1) {
    throw new Error("Node 24 Action runtime canary anchor must occur exactly once");
  }
  writeFileSync(actionPath, action.replace(anchor, replacement));
}

function replaceIndexOnce(cloneDir, name, anchor, replacement) {
  const indexPath = join(cloneDir, "src/index.mjs");
  const source = readFileSync(indexPath, "utf8");
  if (source.split(anchor).length - 1 !== 1) {
    throw new Error(`${name} canary anchor must occur exactly once`);
  }
  writeFileSync(indexPath, source.replace(anchor, () => replacement));
}

function displayBlock(source) {
  const startAnchor = "    lines.push(`###";
  const endAnchor = '\n  }\n\n  lines.push("---");';
  const start = source.indexOf(startAnchor);
  const end = source.indexOf(endAnchor, start);
  if (start < 0 || end < 0 || source.indexOf(startAnchor, start + 1) !== -1) {
    throw new Error("summary display block anchors must identify exactly one block");
  }
  return source.slice(start, end + 5);
}

try {
  // Healthy control first: a broken Action-specific detector must not get
  // credit for rejecting its wiring mutations. Engine identity mutations are
  // owned once by the pinned engine's shared consumer-copy verifier suite.
  const healthy = runContract();
  if (healthy.status !== 0) throw new Error(`healthy Action source/wiring contract is red\n${outputOf(healthy)}`);
  console.log("PASS healthy Action source/wiring contract is green");

  const healthySeam = spawnSync(process.execPath, ["test/engine-adapter-seam.mjs"], {
    cwd: root,
    encoding: "utf8",
  });
  if (healthySeam.status !== 0) throw new Error(`healthy Action adapter seam is red\n${outputOf(healthySeam)}`);
  console.log("PASS healthy Action adapter seam is green");

  const metaAnchor = `  if (typeof dns.meta === "function") {
    query.meta = (name, rrtype) => dns.meta(name, rrtype);
  }
`;
  expectSeamRed(
    "dns.meta adapter seam removed",
    engineCopyWithMutation("missing-meta-seam", metaAnchor, ""),
    "ENGINE ADAPTER SEAM dns.meta reached the shipped engine",
  );

  const probeAnchor = `  if (typeof dns.dnssecProbe === "function") {
    query.dnssecProbe = (name) => dns.dnssecProbe(name);
  }
`;
  expectSeamRed(
    "dns.dnssecProbe adapter seam removed",
    engineCopyWithMutation("missing-dnssec-probe-seam", probeAnchor, ""),
    "ENGINE ADAPTER SEAM dns.dnssecProbe reached the shipped engine",
  );

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

  const driftClone = cloneCommittedHead("index-drift-clone");
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
    "src/index.mjs changed outside the reviewed import, N3 comment, per-audit wiring, and Not confirmed display substitutions",
  );

  const missingDisplayClone = cloneCommittedHead("missing-display-clone");
  const currentDisplay = displayBlock(readFileSync(join(missingDisplayClone, "src/index.mjs"), "utf8"));
  const legacyDisplay = displayBlock(readFileSync(baselineIndex, "utf8"));
  replaceIndexOnce(missingDisplayClone, "display block removed", currentDisplay, legacyDisplay);
  expectCommandRed(
    "reviewed Not confirmed display block removed",
    process.execPath,
    ["test/host-surface-equivalence.mjs"],
    {
      cwd: missingDisplayClone,
      env: { ...process.env, BASELINE_INDEX: baselineIndex, BASELINE_ACTION: baselineAction },
    },
    "reviewed Not confirmed display block is missing or changed",
  );

  const resultReasonClone = cloneCommittedHead("result-reason-clone");
  replaceIndexOnce(
    resultReasonClone,
    "result-level reason substitution",
    "const issue = f.unconfirmed ? `${f.title} (Not confirmed: ${f.unconfirmed})` : f.title;",
    "const issue = f.unconfirmed ? `${f.title} (Not confirmed: ${r.inconclusive_reason})` : f.title;",
  );
  expectCommandRed(
    "display reason re-derived from result-level inconclusive_reason",
    process.execPath,
    ["test/host-surface-equivalence.mjs"],
    {
      cwd: resultReasonClone,
      env: { ...process.env, BASELINE_INDEX: baselineIndex, BASELINE_ACTION: baselineAction },
    },
    "reviewed Not confirmed display block is missing or changed",
  );

  const actionDriftClone = cloneCommittedHead("action-drift-clone");
  appendFileSync(join(actionDriftClone, "action.yml"), " ");
  expectCommandRed(
    "any other action.yml byte changed",
    process.execPath,
    ["test/host-surface-equivalence.mjs"],
    {
      cwd: actionDriftClone,
      env: { ...process.env, BASELINE_INDEX: baselineIndex, BASELINE_ACTION: baselineAction },
    },
    "action.yml changed outside the reviewed node20 to node24 runtime substitution",
  );

  const node20Clone = cloneCommittedHead("action-node20-clone");
  replaceActionRuntime(node20Clone, '  using: "node20"');
  expectCommandRed(
    "action.yml left at node20",
    process.execPath,
    ["test/host-surface-equivalence.mjs"],
    {
      cwd: node20Clone,
      env: { ...process.env, BASELINE_INDEX: baselineIndex, BASELINE_ACTION: baselineAction },
    },
    "action.yml still declares node20; expected the reviewed node24 runtime substitution",
  );

  const node22Clone = cloneCommittedHead("action-node22-clone");
  replaceActionRuntime(node22Clone, '  using: "node22"');
  expectCommandRed(
    "action.yml changed to a different runtime",
    process.execPath,
    ["test/host-surface-equivalence.mjs"],
    {
      cwd: node22Clone,
      env: { ...process.env, BASELINE_INDEX: baselineIndex, BASELINE_ACTION: baselineAction },
    },
    "action.yml runtime must be node24",
  );
} finally {
  rmSync(dir, { recursive: true, force: true });
}
