import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
} finally {
  rmSync(dir, { recursive: true, force: true });
}
