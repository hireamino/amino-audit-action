import { createAuditEngine } from "../vendor/amino-audit-engine/engine.mjs";

const domain = "private-target.test";
const records = {
  [domain]: { A: ["127.0.0.1"] },
  [`_mta-sts.${domain}`]: { TXT: ["v=STSv1; id=1"] },
  [`mta-sts.${domain}`]: { A: ["169.254.169.254"] },
};
const dns = {
  async query(name, rrtype) { return records[name]?.[rrtype] || []; },
  async meta() { return { status: 0, ad: false, error: false }; },
};
const calls = { mtaSts: 0, robots: 0, rdap: 0 };
const engine = createAuditEngine({
  dns,
  http: {
    async mtaSts() { calls.mtaSts++; throw new Error("SSRF guard failed"); },
    async robots() { calls.robots++; throw new Error("SSRF guard failed"); },
    async rdap() { calls.rdap++; return null; },
  },
  clock: { nowMs: () => 1789257600000 },
});
await engine.auditDomain(domain);
if (calls.mtaSts !== 0 || calls.robots !== 0 || calls.rdap !== 1) {
  throw new Error(`SSRF call order failed: ${JSON.stringify(calls)}`);
}
console.log(`SSRF guard PASS: domain-controlled HTTP ports were not called ${JSON.stringify(calls)}`);
