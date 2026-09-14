import { readFileSync } from "node:fs";

const files = [".github/workflows/security-gate.yml", ".github/workflows/dogfood.yml"];
let count = 0;
for (const file of files) {
  const source = readFileSync(file, "utf8");
  for (const match of source.matchAll(/^\s*uses:\s*([^\s#]+)/gm)) {
    const target = match[1];
    count += 1;
    if (target.startsWith("./")) continue;
    if (!/@[0-9a-f]{40}$/.test(target)) {
      throw new Error(`${file}: workflow action is not pinned by a full lowercase SHA: ${target}`);
    }
    console.log(`PASS ${file}: ${target}`);
  }
}
if (count === 0) throw new Error("no workflow action references were checked");
console.log(`Workflow action pins PASS: ${count} references checked; the local ./ action is the only non-remote reference.`);
