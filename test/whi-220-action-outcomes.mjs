import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { finalize, summaryOutput } from "../src/index.mjs";

const BASE = "996b7525234755de9ea6dc51fe5ad3b29a65f073";
const CHANGED_FIXTURES = new Set([
  "inconclusive-apex-txt-notimp",
  "inconclusive-dmarc-txt-formerr",
  "inconclusive-apex-mx-notimp",
]);
const LEVELS = ["advisory", "low", "medium", "high", "critical"];
const CONTRACT_MODES = new Set(["dns-engine", "http-observation"]);
const skillsDir = resolve(process.env.SKILLS_DIR || ".cache/amino-skills");
const reportPath = resolve("evidence/whi-220-action-1.5.0-outcomes.md");
const temporary = mkdtempSync(join(tmpdir(), "amino-whi-220-action-outcomes-"));

function mockQ(dns, http = {}, nowMs = 1767225600000) {
  const norm = (name) => name.replace(/\.+$/, "").toLowerCase();
  const map = {};
  for (const [name, records] of Object.entries(dns || {})) map[norm(name)] = records;
  const q = async (name, type) => {
    name = norm(name);
    if (map[name] && map[name][type]) return map[name][type];
    for (const key of Object.keys(map)) {
      if (key.startsWith("*._domainkey.") && name.endsWith(key.slice(1)) && map[key][type]) {
        return map[key][type];
      }
    }
    return [];
  };
  q.meta = async (name, rrtype) => {
    const entry = map[norm(name)] || {};
    const configured = entry.status !== undefined ? entry.status : 0;
    const status = configured && typeof configured === "object" && !Array.isArray(configured)
      ? (configured[String(rrtype || "").toUpperCase()] ?? 0)
      : configured;
    return { status, ad: !!entry.ad, error: false };
  };
  const response = (name) => http[name] === "unavailable" || http[name] === undefined
    ? null : structuredClone(http[name]);
  q.http = {
    mtaSts: async () => response("mta_sts_policy"),
    robots: async () => response("robots"),
    // Both compared engines are 1.4.0+, whose reviewed RDAP port is {status,data}.
    rdap: async () => {
      const value = response("rdap");
      return value === null ? null : { status: value.status, data: value.data };
    },
  };
  q.clock = { nowMs: () => nowMs };
  return q;
}

function view(result, level) {
  const decision = finalize([result], level, true);
  return {
    passed: decision.passed,
    auditComplete: decision.auditComplete,
    failBuild: decision.failBuild,
    worstSeverity: decision.worst,
    findingSummary: summaryOutput([result]),
  };
}

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function cell(value) {
  if (typeof value === "boolean") return value ? "true" : "false";
  return value === null ? "none" : String(value).replaceAll("|", "\\|");
}

function markdown(rows, oldVersion, newVersion) {
  const lines = [
    "# WHI-220 Part B — Action outcome measurement",
    "",
    `Old engine: **${oldVersion}** at consumer base \`${BASE}\`.`,
    `New engine: **${newVersion}** at \`41abd12470ccaa43564f8d8c9c1e350fed9d922c\`.`,
    "",
    "Every executable pinned-corpus fixture is evaluated at all five `fail-on` levels",
    "through the Action's unchanged `finalize()` and `summaryOutput()` functions.",
    "The RDAP port uses the reviewed `{status,data}` shape required by both 1.4.0 and 1.5.0.",
    "",
    "| Fixture | fail-on | Old passed | New passed | Old complete | New complete | Old failBuild | New failBuild | Worst old→new | Summary changed |",
    "|---|---|---:|---:|---:|---:|---:|---:|---|---:|",
  ];
  for (const row of rows) {
    lines.push(
      `| ${row.fixture} | ${row.level} | ${cell(row.old.passed)} | ${cell(row.new.passed)} | ` +
      `${cell(row.old.auditComplete)} | ${cell(row.new.auditComplete)} | ` +
      `${cell(row.old.failBuild)} | ${cell(row.new.failBuild)} | ` +
      `${cell(row.old.worstSeverity)}→${cell(row.new.worstSeverity)} | ` +
      `${row.old.findingSummary === row.new.findingSummary ? "no" : "yes"} |`,
    );
  }
  return `${lines.join("\n")}\n`;
}

try {
  const oldEnginePath = join(temporary, "engine-1.4.0.mjs");
  const shown = spawnSync("git", ["show", `${BASE}:vendor/amino-audit-engine/engine.mjs`], {
    encoding: "buffer",
  });
  if (shown.status !== 0) throw new Error(`cannot read the immutable old engine: ${shown.stderr}`);
  writeFileSync(oldEnginePath, shown.stdout);

  const oldEngine = await import(pathToFileURL(oldEnginePath).href);
  const newEngine = await import(pathToFileURL(resolve("vendor/amino-audit-engine/engine.mjs")).href);
  console.log(
    `SHAPE old engine contractVersion=${oldEngine.contractVersion} -> rdap port {status,data} (1.4.0+); ` +
    `new engine=${newEngine.contractVersion}`,
  );
  if (oldEngine.contractVersion !== "1.4.0" || newEngine.contractVersion !== "1.5.0") {
    throw new Error(`unexpected engine versions ${oldEngine.contractVersion} -> ${newEngine.contractVersion}`);
  }

  const document = JSON.parse(readFileSync(join(skillsDir, "conformance/fixtures.json"), "utf8"));
  const fixtures = document.fixtures.filter((fixture) => CONTRACT_MODES.has(fixture.mode));
  if (fixtures.length !== 53) throw new Error(`expected 53 executable fixtures, got ${fixtures.length}`);

  const rows = [];
  for (const fixture of fixtures) {
    const { domain, dns = {}, http = {}, nowMs } = fixture.input;
    const oldResult = await oldEngine.auditDomain(domain, mockQ(dns, http, nowMs));
    const newResult = await newEngine.auditDomain(domain, mockQ(dns, http, nowMs));
    for (const level of LEVELS) {
      rows.push({
        fixture: fixture.id,
        level,
        old: view(oldResult, level),
        new: view(newResult, level),
      });
    }
  }

  const changed = rows.filter((row) => !same(row.old, row.new));
  const newlyFailing = rows.filter((row) => !row.old.failBuild && row.new.failBuild);
  const newlyPassing = rows.filter((row) => row.old.failBuild && !row.new.failBuild);
  const summaryChanges = rows.filter((row) => row.old.findingSummary !== row.new.findingSummary);
  const changedFixtureSet = new Set(changed.map((row) => row.fixture));
  const advisoryPassedChanges = changed.filter(
    (row) => row.level === "advisory" && row.old.passed && !row.new.passed,
  );
  const completeChanges = changed.filter(
    (row) => row.old.auditComplete && !row.new.auditComplete,
  );

  const expectedFixtures = [...CHANGED_FIXTURES].sort();
  const actualFixtures = [...changedFixtureSet].sort();
  const assertions = [
    [rows.length === 265, `265 result pairs, got ${rows.length}`],
    [changed.length === 15, `15 changed pairs, got ${changed.length}`],
    [same(actualFixtures, expectedFixtures), `changed fixtures ${JSON.stringify(actualFixtures)}`],
    [newlyFailing.length === 0, `0 newly failing builds, got ${newlyFailing.length}`],
    [newlyPassing.length === 0, `0 newly passing builds, got ${newlyPassing.length}`],
    [summaryChanges.length === 0, `0 finding-summary changes, got ${summaryChanges.length}`],
    [advisoryPassedChanges.length === 3, `3 advisory passed true→false changes, got ${advisoryPassedChanges.length}`],
    [completeChanges.length === 15, `15 audit-complete true→false changes, got ${completeChanges.length}`],
    [changed.every((row) => row.old.failBuild === row.new.failBuild), "failBuild unchanged on all changed pairs"],
  ];
  for (const [condition, label] of assertions) {
    console.log(`${condition ? "PASS" : "FAIL"} ${label}`);
    if (!condition) process.exitCode = 1;
  }

  const generated = markdown(rows, oldEngine.contractVersion, newEngine.contractVersion);
  if (process.argv.includes("--write")) {
    writeFileSync(reportPath, generated);
    console.log(`WROTE ${reportPath}`);
  } else {
    const committed = readFileSync(reportPath, "utf8");
    if (committed !== generated) {
      console.error("FAIL committed 265-pair table differs from the measured result");
      process.exitCode = 1;
    } else {
      console.log("PASS committed 265-pair table is byte-identical to the measured result");
    }
  }
  console.log(
    `MODE=auto fixtures=${fixtures.length} pairs=${rows.length} changed=${changed.length} ` +
    `newlyFail=${newlyFailing.length} newlyPass=${newlyPassing.length} summaryChanges=${summaryChanges.length}`,
  );
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
