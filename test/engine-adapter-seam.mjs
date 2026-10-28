import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const engineFile = resolve(process.env.ENGINE_FILE || "vendor/amino-audit-engine/engine.mjs");
const { createAuditEngine } = await import(`${pathToFileURL(engineFile).href}?seam=${Date.now()}`);

let metadataCalls = 0;
let probeCalls = 0;
const domain = "adapter-seam.invalid";
const adapters = {
  dns: {
    query: async () => [],
    meta: async (name, rrtype) => {
      metadataCalls += 1;
      return {
        status: name === domain && rrtype === "DNSKEY" ? 2 : 0,
        ad: false,
        error: false,
      };
    },
    dnssecProbe: async () => {
      probeCalls += 1;
      return {};
    },
  },
  http: {
    mtaSts: async () => null,
    robots: async () => null,
    rdap: async () => null,
  },
  clock: { nowMs: () => 1767225600000 },
};

const result = await createAuditEngine(adapters).auditDomain(domain);
const keys = Object.keys(result.rule_evaluation || {});

if (metadataCalls === 0) {
  throw new Error("ENGINE ADAPTER SEAM dns.meta reached the shipped engine: expected calls, got 0");
}
if (probeCalls !== 1) {
  throw new Error(`ENGINE ADAPTER SEAM dns.dnssecProbe reached the shipped engine: expected 1 call, got ${probeCalls}`);
}
if (keys.length !== 56) {
  throw new Error(`ENGINE ADAPTER SEAM rule_evaluation closed world: expected 56 rows, got ${keys.length}`);
}
if (result.rule_evaluation["dnssec.validation_failing"] !== `DNSKEY ${domain}: SERVFAIL`) {
  throw new Error(`ENGINE ADAPTER SEAM source-exact DNSKEY failure: got ${result.rule_evaluation["dnssec.validation_failing"]}`);
}

console.log(`ENGINE ADAPTER SEAM PASS: meta=${metadataCalls}, dnssecProbe=${probeCalls}, rules=${keys.length}`);
