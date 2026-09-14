import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const enginePath = process.env.ENGINE || "vendor/amino-audit-engine/engine.mjs";
const source = readFileSync(enginePath, "utf8");
const dir = mkdtempSync(join(tmpdir(), "amino-engine-boundary-canary-"));

function count(sourceText, anchor) {
  let found = 0;
  let offset = 0;
  while ((offset = sourceText.indexOf(anchor, offset)) !== -1) {
    found++;
    offset += anchor.length;
  }
  return found;
}

function proveMutation({ label, anchor, replacement, diagnostic }) {
  const occurrences = count(source, anchor);
  if (occurrences !== 1) throw new Error(`${label}: mutation anchor must occur exactly once, got ${occurrences}`);
  const mutated = join(dir, `${label}.mjs`);
  writeFileSync(mutated, source.replace(anchor, replacement));
  const result = spawnSync(process.execPath, ["test/engine-equivalence.mjs"], {
    cwd: process.cwd(),
    env: { ...process.env, ENGINE: mutated },
    encoding: "utf8",
  });
  const combined = `${result.stdout || ""}\n${result.stderr || ""}`;
  if (result.status === 0 || !combined.includes(diagnostic)) {
    throw new Error(`${label}: mutation did not fail for the named boundary case\n${combined}`);
  }
  console.log(`${label} PASS: ${diagnostic}`);
}

try {
  proveMutation({
    label: "expiry-30-to-31",
    anchor: "left >= 0 && left < 30",
    replacement: "left >= 0 && left < 31",
    diagnostic: "boundary-expiry-30: baseline and injected outputs differ",
  });
  for (const [cap, diagnostic] of [
    [8000, "cap-8192-valid: baseline and injected outputs differ"],
    [8191, "cap-8192-valid: baseline and injected outputs differ"],
    [8193, "cap-8193-cut: baseline and injected outputs differ"],
    [9000, "cap-8193-cut: baseline and injected outputs differ"],
  ]) {
    proveMutation({
      label: `cap-8192-to-${cap}`,
      anchor: ".slice(0, 8192)",
      replacement: `.slice(0, ${cap})`,
      diagnostic,
    });
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
