import { pathToFileURL } from "node:url";

const runner = process.env.RUNNER;
const expected = Number(process.env.EXPECT_FETCH_CALLS || "0");
if (!runner || !process.env.ENGINE || !process.env.SURFACE) {
  console.error("RUNNER, ENGINE and SURFACE are required");
  process.exit(2);
}

const realFetch = globalThis.fetch;
const realNow = Date.now;
const realExit = process.exit;
const urls = [];
const sentinel = Symbol("runner-exit");
let runnerStatus = null;

globalThis.fetch = async (url) => {
  urls.push(String(url));
  throw new Error("network denied by WHI-7 purity gate");
};
Date.now = () => 1789257600000;
process.exit = (code = 0) => {
  runnerStatus = code;
  throw sentinel;
};

try {
  await import(pathToFileURL(runner).href + "?network-observe=1");
} catch (error) {
  if (error !== sentinel) throw error;
} finally {
  globalThis.fetch = realFetch;
  Date.now = realNow;
  process.exit = realExit;
}

const distinct = [...new Set(urls)];
console.log(`Network observation: ${urls.length} fetch attempts, ${distinct.length} distinct URLs.`);
for (const url of distinct) console.log(`  ${url}`);
if (runnerStatus !== 0 || urls.length !== expected) {
  console.error(`FAIL network observation: runner=${runnerStatus}, expected ${expected} fetch calls, got ${urls.length}`);
  process.exit(1);
}
