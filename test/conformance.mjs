// Conformance check for THIS surface (see the conformance spec in hireamino/amino-skills).
// Runs auditDomain() against canned DNS (mock resolver, no network) and asserts the
// v1.2 batch-1 false-pass fixtures now produce the correct verdict. Exits non-zero on
// any violation so it runs as a CI gate.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { auditDomain, buckets, mtaStsPolicyProblems } from "../vendor/amino-audit-engine/engine.mjs";
import { mdCell, renderSummary } from "../src/index.mjs";

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

function fixtureQ(dns, http = {}, nowMs = 1767225600000, dnssecProbe = {}) {
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
  const dnssecProbeMap = {};
  for (const [name, evidence] of Object.entries(dnssecProbe || {})) {
    dnssecProbeMap[norm(name)] = evidence;
  }
  q.dnssecProbe = async (name) => structuredClone(dnssecProbeMap[norm(name)] || {});
  const response = (name) => http[name] === "unavailable" || http[name] === undefined
    ? null : structuredClone(http[name]);
  q.http = {
    mtaSts: async () => response("mta_sts_policy"),
    robots: async () => response("robots"),
    rdap: async () => {
      const value = response("rdap");
      return value === null ? null : { status: value.status, data: value.data };
    },
  };
  q.clock = { nowMs: () => nowMs };
  return q;
}

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
{ // WHI-50 — only a true null MX exempts inbound-only controls
  const nullMxDns = {
    "nomail.invalid": { TXT: ["v=spf1 -all"], MX: ["0 ."] },
    "_dmarc.nomail.invalid": { TXT: ["v=DMARC1; p=reject"] },
  };
  const nullFindings = (await auditDomain("nomail.invalid", makeQ(nullMxDns))).findings;
  const nullScore = await buckets("nomail.invalid", makeQ(nullMxDns));
  assert("WHI-50 null MX → MTA-STS not applicable", nullFindings.some((f) => f.title === "MTA-STS not applicable — domain receives no mail"));
  assert("WHI-50 null MX → no TLS-RPT or DANE gap", !nullFindings.some((f) => ["TLS-RPT"].includes(f.area) || /DANE/.test(f.title)));
  assert("WHI-50 null MX → inbound score buckets are N/A and gap is 2", nullScore.MTA_STS === null && nullScore.TLS_RPT === null && nullScore.DANE === null && nullScore.gap === 2);

  const noMxDns = {
    "nomx.invalid": { TXT: ["v=spf1 -all"] },
    "_dmarc.nomx.invalid": { TXT: ["v=DMARC1; p=reject"] },
  };
  const noMxFindings = (await auditDomain("nomx.invalid", makeQ(noMxDns))).findings;
  const noMxScore = await buckets("nomx.invalid", makeQ(noMxDns));
  assert("WHI-50 no MX → inbound controls still apply", noMxFindings.some((f) => f.title === "No MTA-STS policy") && noMxFindings.some((f) => f.title === "No TLS-RPT") && noMxScore.MTA_STS === false && noMxScore.gap === 5);

  const ambiguousDns = {
    "ambiguous.invalid": { TXT: ["v=spf1 -all"], MX: ["0 .", "10 mx.ambiguous.invalid."] },
    "_dmarc.ambiguous.invalid": { TXT: ["v=DMARC1; p=reject"] },
  };
  const ambiguousFindings = (await auditDomain("ambiguous.invalid", makeQ(ambiguousDns))).findings;
  const ambiguousScore = await buckets("ambiguous.invalid", makeQ(ambiguousDns));
  assert("WHI-50 ambiguous MX → fails toward reporting", ambiguousFindings.some((f) => f.title === "No MTA-STS policy") && ambiguousFindings.some((f) => f.title === "No DANE/TLSA") && ambiguousScore.MTA_STS === false && ambiguousScore.gap === 5);
}

// Summary LAST — it previously sat mid-file with a hard process.exit(), so anything
// appended below never ran and could not fail CI. Verified with a canary.
{ // DMARC enforcement advice — RFC 9989 §7.4
  // The short action label is the ONLY remediation text the GitHub Action renders
  // (index.mjs builds its table from f.action || f.fix), so it is asserted here
  // BEHAVIOURALLY off a real audit, not by grepping the source.
  const F = (await auditDomain("ex.com", makeQ({ "ex.com": {}, "_dmarc.ex.com": { TXT: ["v=DMARC1; p=none; rua=mailto:d@ex.com"] } }))).findings;
  const pnone = F.find((f) => f.title.includes("p=none (monitor"));
  assert("§7.4 the p=none finding is raised at all (positive control)", !!pnone);
  assert("§7.4 label is the staged one", pnone?.action === "Review DMARC reports, then stage quarantine");
  assert("§7.4 the short label does not name reject", !/reject/i.test(pnone?.action || ""));

  // §7.4 scopes BOTH its "SHOULD NOT publish p=reject" and its month-then-month
  // staging advice to domains hosting users who might post to mailing lists.
  // Neither may be restated here as universal advice.
}

{ // WHI-280 — Action rendering consumes, but never derives, engine-owned markers.
  const skillsDir = process.env.SKILLS_DIR;
  assert("WHI-280 pinned skills checkout is provided to the display contract", !!skillsDir);
  if (skillsDir) {
    const fixturePath = resolve(skillsDir, "conformance/fixtures.json");
    const { fixtures } = JSON.parse(readFileSync(fixturePath, "utf8"));
    const cases = fixtures.filter((fixture) => fixture.id.startsWith("inconclusive-") && fixture.expect?.inconclusive === true);
    assert("WHI-280 display contract selects exactly 8 inconclusive fixtures", cases.length === 8);
    for (const fixture of cases) {
      const q = fixtureQ(
        fixture.input.dns,
        fixture.input.http,
        fixture.input.nowMs,
        fixture.input.dnssecProbe,
      );
      const result = await auditDomain(fixture.input.domain, q);
      const summary = renderSummary([result], {
        passed: false,
        failBuild: false,
        auditComplete: false,
        level: "advisory",
        reason: "fixture display contract",
      });
      const caution = `> We couldn't finish checking this domain. A DNS lookup failed (\`${fixture.expect.inconclusive_reason}\`), so anything reported below as missing may be wrong, especially findings marked Not confirmed. Re-run before acting on it.`;
      assert(`${fixture.id} renders one exact inconclusive caution line`, summary.split(caution).length - 1 === 1);

      const expected = fixture.expect.findings.filter((finding) => {
        const surfaces = finding.surfaces || ["skill", "web", "action"];
        return surfaces.includes("action") && finding.severity !== "pass";
      });
      for (const wanted of expected) {
        const actual = result.findings.find((finding) => finding.area === wanted.area && finding.title === wanted.title);
        assert(`${fixture.id} ${wanted.area}|${wanted.title} exists for Action display`, !!actual);
        if (!actual) continue;
        if (wanted.unconfirmed) {
          const issue = `${actual.title} (Not confirmed: ${wanted.unconfirmed})`;
          assert(
            `${fixture.id} ${wanted.area}|${wanted.title} row uses finding.unconfirmed`,
            summary.includes(`| ${mdCell(actual.area)} | ${mdCell(issue)} |`),
          );
          assert(
            `${fixture.id} ${wanted.area}|${wanted.title} fix starts with the re-run lead-in`,
            !actual.fix || summary.includes(`- **${mdCell(actual.title)}** — ${mdCell(`Re-run the check first. If it's still reported: ${actual.fix}`)}`),
          );
        } else {
          assert(
            `${fixture.id} ${wanted.area}|${wanted.title} unmarked row stays unmarked`,
            summary.includes(`| ${mdCell(actual.area)} | ${mdCell(actual.title)} |`)
              && !summary.includes(`${mdCell(actual.title)} \\(Not confirmed:`),
          );
        }
      }
    }
  }
}

console.log(ok ? "\nALL PASS" : "\nSOME FAILED");
process.exit(ok ? 0 : 1);
