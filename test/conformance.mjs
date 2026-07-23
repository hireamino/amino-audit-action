// Conformance check for THIS surface (see the conformance spec in hireamino/amino-skills).
// Runs auditDomain() against canned DNS (mock resolver, no network) and asserts the
// v1.2 batch-1 false-pass fixtures now produce the correct verdict. Exits non-zero on
// any violation so it runs as a CI gate.
import { auditDomain } from "../src/engine.mjs";

function makeQ(dns, dkimRec) {
  return async (name, type) => {
    name = name.replace(/\.+$/, "").toLowerCase();
    if (dkimRec && name.endsWith("._domainkey.ex.com") && type === "TXT") return [dkimRec];
    const rec = dns[name];
    return rec ? (rec[type] || []) : [];
  };
}
const titles = (F) => F.map((f) => f.area + ": " + f.title);
let ok = true;
const assert = (name, cond) => { ok = cond && ok; console.log((cond ? "PASS" : "FAIL"), name); };

{ // I1 — revoked DKIM (empty p=) must not read as present
  const F = (await auditDomain("ex.com", makeQ({ "ex.com": {} }, "v=DKIM1; k=rsa; p="))).findings;
  const t = titles(F);
  assert("I1 revoked DKIM flagged", t.some((x) => x.includes("DKIM key is revoked or malformed")));
  assert("I1 not reported as present", !t.some((x) => x.includes("DKIM present")));
}
{ // I6/I9 — DMARC p=banana is invalid, not enforced
  const F = (await auditDomain("ex.com", makeQ({ "_dmarc.ex.com": { TXT: ["v=DMARC1; p=banana; rua=mailto:d@ex.com"] } }))).findings;
  const t = titles(F);
  assert("I6 banana flagged invalid", t.some((x) => x.includes("DMARC policy value is invalid")));
  assert("I9 banana not enforced", !t.some((x) => x.includes("DMARC enforced")));
}
{ // I7 — uppercase tags: P=Reject enforced
  const F = (await auditDomain("ex.com", makeQ({ "_dmarc.ex.com": { TXT: ["v=DMARC1; P=Reject; RUA=mailto:d@ex.com"] } }))).findings;
  const t = titles(F);
  assert("I7 P=Reject enforced", t.some((x) => x.includes("DMARC enforced")));
  assert("I7 P=Reject not invalid", !t.some((x) => x.includes("policy value is invalid")));
}
{ // I11 — SPF -ALL behaves like -all
  const F = (await auditDomain("ex.com", makeQ({ "ex.com": { TXT: ["v=spf1 -ALL"] } }))).findings;
  const t = titles(F);
  assert("I11 -ALL: no 'no all mechanism'", !t.some((x) => x.includes("no `all` mechanism")));
  assert("I11 -ALL: SPF present", t.some((x) => x.includes("SPF present")));
}
console.log(ok ? "\nALL PASS" : "\nSOME FAILED");
process.exit(ok ? 0 : 1);
