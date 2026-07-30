// Conformance check for THIS surface (see the conformance spec in hireamino/amino-skills).
// Runs auditDomain() against canned DNS (mock resolver, no network) and asserts the
// v1.2 batch-1 false-pass fixtures now produce the correct verdict. Exits non-zero on
// any violation so it runs as a CI gate.
import { auditDomain, mtaStsPolicyProblems } from "../src/engine.mjs";

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
{ // I10 — subdomain inherits org policy via RFC 9989 tree walk (no false "No DMARC")
  const dns = { "_dmarc.example.co.uk": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.co.uk"] } };
  const F = (await auditDomain("send.example.co.uk", makeQ(dns))).findings;
  const t = titles(F);
  assert("I10 subdomain inherits enforced policy", t.some((x) => x.includes("DMARC enforced (inherited")));
  assert("I10 no false 'No DMARC record'", !t.some((x) => x.includes("No DMARC record")));
}
{ // I15 — MTA-STS strict field validation (RFC 8461)
  assert("I15 valid enforce → no problems", mtaStsPolicyProblems("version: STSv1\nmode: enforce\nmax_age: 604800\nmx: mx.ex.com\n").problems.length === 0);
  assert("I15 enforce missing fields → problems", mtaStsPolicyProblems("mode: enforce\n").problems.length > 0);
  assert("I15 max_age out of range → problem", mtaStsPolicyProblems("version: STSv1\nmode: enforce\nmax_age: 99999999\nmx: a.ex.com").problems.some((p) => p.includes("max_age")));
  assert("I15 mode none needs no mx", mtaStsPolicyProblems("version: STSv1\nmode: none\nmax_age: 100").problems.length === 0);
}
{ // I16 — TXT advertises a policy but it isn't fetchable (200 + text/plain) → not enforced
  const F = (await auditDomain("ex.com", makeQ({ "_mta-sts.ex.com": { TXT: ["v=STSv1; id=1"] } }))).findings;
  const t = titles(F);
  assert("I16 unfetchable policy → flagged", t.some((x) => x.includes("policy file not retrievable")));
  assert("I16 not reported present/enforced", !t.some((x) => x.includes("MTA-STS present")));
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2026-07-30 — claim assertions. This engine is PUBLIC (GitHub Marketplace), and five
// false claims sat here identically to the web tool and the public skill. The inventory
// parity gate compares which CHECKS exist, not what they SAY, so wording was wrong in
// lockstep and nothing caught it. These assert the text of this copy specifically.
// ═══════════════════════════════════════════════════════════════════════════════
{
  const { readFileSync } = await import("node:fs");
  const SRC = readFileSync(new URL("../src/engine.mjs", import.meta.url), "utf8");
  assert("no empty-quadrant global all-clear", !/DKIM &amp; DMARC enforced<\/li>/.test(SRC));
  assert("all-clear gated on zero gaps", /const clean = gaps\.length === 0/.test(SRC));
  assert("np= not claimed to stop cousin-domain spoofing", !/np=reject to shut down cousin-domain spoofing/.test(SRC));
  assert("np= scope stated correctly", /NON-EXISTENT subdomains of your domain/.test(SRC));
  assert("IR 8547 draft status stated", /still an initial public draft/.test(SRC) && !/IR 8547\) sets today's classical crypto/.test(SRC));
  assert("no PQC migration path claimed for DKIM", /NO standardized post-quantum path/.test(SRC));
  assert("read-only answer names the HTTPS fetches", /fetches your published MTA-STS policy over HTTPS/.test(SRC));
  assert("Gmail p=none allowance stated", /Google explicitly allows that policy to be p=none/.test(SRC));
  assert("one-click unsubscribe scope stated", /marketing and subscribed messages specifically/.test(SRC));
  assert("pct= not recommended for staging", !/optionally with pct= staging/.test(SRC));
  assert("MTA-STS rollout staged via testing", /start at mode: testing/.test(SRC));
  assert("MTA-STS cites BSI, not NIS2", !/growing compliance ask under NIS2/.test(SRC));
  assert("inbound controls gated on receiving mail", /noInboundMail/.test(SRC));
}

// Summary LAST — it previously sat mid-file with a hard process.exit(), so anything
// appended below never ran and could not fail CI. Verified with a canary.
console.log(ok ? "\nALL PASS" : "\nSOME FAILED");
process.exit(ok ? 0 : 1);
