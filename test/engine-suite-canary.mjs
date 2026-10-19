import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

const checkout = process.env.ENGINE_CHECKOUT;
if (!checkout) {
  console.error("ENGINE_CHECKOUT is required");
  process.exit(2);
}

const sourcePath = join(checkout, "src/engine.mjs");
const source = readFileSync(sourcePath, "utf8");
const anchor = '      if (affected.has([finding.area, finding.title].join("\\0"))) finding.unconfirmed = reason;';
const occurrences = source.split(anchor).length - 1;
if (occurrences !== 1) throw new Error(`per-finding reason mutation anchor must occur exactly once, got ${occurrences}`);

const dir = mkdtempSync(join(tmpdir(), "amino-action-engine-suite-canary-"));
const copy = join(dir, "engine");
try {
  cpSync(checkout, copy, {
    recursive: true,
    filter: (path) => !path.endsWith("/.git") && !path.includes("/.git/") && !path.endsWith("/.cache") && !path.includes("/.cache/"),
  });
  const mutatedSource = source.replace(
    anchor,
    () => '      if (affected.has([finding.area, finding.title].join("\\0"))) finding.unconfirmed = inconclusiveReason;',
  );
  writeFileSync(join(copy, "src/engine.mjs"), mutatedSource);
  const provenancePath = join(copy, "engine.provenance.json");
  const provenance = JSON.parse(readFileSync(provenancePath, "utf8"));
  provenance.artifact.sha256 = createHash("sha256").update(mutatedSource).digest("hex");
  writeFileSync(provenancePath, `${JSON.stringify(provenance, null, 2)}\n`);

  const result = spawnSync("bash", ["scripts/verify.sh"], {
    cwd: copy,
    env: {
      ...process.env,
      SKILLS_DIR: join(checkout, ".cache/amino-skills"),
      BASELINE_DIR: join(checkout, ".cache/amino-audit-action"),
    },
    encoding: "utf8",
  });
  const output = `${result.stdout || ""}\n${result.stderr || ""}`;
  const diagnostic = 'inconclusive-apex-txt-before-mx.findings[MTA-STS|No MTA-STS policy].unconfirmed: expected "MX ex.com: SERVFAIL/REFUSED", got "TXT ex.com: SERVFAIL/REFUSED"';
  if (result.status === 0 || !output.includes(diagnostic)) {
    throw new Error(`mutated pinned engine suite did not fail through the named per-finding reason assertion\n${output}`);
  }
  console.log(`Pinned engine suite canary PASS: ${diagnostic}`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
