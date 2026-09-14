import { readFileSync } from "node:fs";

const file = process.env.ENGINE || "vendor/amino-audit-engine/engine.mjs";
const source = readFileSync(file, "utf8");
const start = source.indexOf("export function createDefaultAdapters() {");
const end = source.indexOf("\n// ─────────────────────────────────────────────────────────────────────────────\n// DNS helpers", start);
if (start < 0 || end < 0) throw new Error("default real-adapter factory boundary not found");

const patterns = [/\bfetch\s*\(/g, /\bDate\.now\s*\(/g, /\bnew Date\s*\(/g, /\bglobalThis\b/g];
let failed = false;
for (const pattern of patterns) {
  for (const match of source.matchAll(pattern)) {
    const line = source.slice(0, match.index).split("\n").length;
    const text = source.split("\n")[line - 1].trim();
    console.log(`${file}:${line}: ${text}`);
    if (match.index < start || match.index >= end) failed = true;
  }
}

for (const banned of ["onRequestGet", "rateLimited", "htmlResponse", "renderResult", "process.exit", "_metrics.mjs"]) {
  if (source.includes(banned)) {
    console.error(`FAIL forbidden host concern in engine: ${banned}`);
    failed = true;
  }
}
if (failed) process.exit(1);
console.log("Purity PASS: ambient network/time access is confined to createDefaultAdapters().");
