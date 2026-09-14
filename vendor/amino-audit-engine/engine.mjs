const MAX_DKIM_CONCURRENCY = 12;

const DKIM_SELECTORS = [
  "selector1", "selector2", "google", "default", "default2", "k1", "k2", "k3",
  "mandrill", "dkim", "dkim1", "dkim2", "mail", "smtp", "s1", "s2", "s1024", "s2048",
  "sig1", "cf2024-1", "mxvault", "zoho", "zmail", "pm", "pm-bounces", "scph0", "scph1",
  "sendgrid", "sg", "fd", "fm1", "fm2", "fm3", "mte1", "mte2", "m1", "marketo",
  "amazonses", "ses", "sparkpost", "mailjet", "klaviyo", "hs1", "hs2", "hubspot",
  "protonmail", "protonmail2", "protonmail3", "cm", "mailerlite", "ml",
  "everlytickey1", "key1", "1", "2", "mailo", "turbo-smtp",
];

const PROVIDER_SELECTORS = {
  google: ["google"],
  outlook: ["selector1", "selector2"],
  pphosted: ["selector1", "selector2"],
  mimecast: ["mimecast", "selector1"],
  mandrill: ["mandrill", "k1", "k2", "k3"],
  sendgrid: ["s1", "s2", "smtp"],
  mailgun: ["mx", "smtp", "k1", "mailo"],
  amazonses: ["amazonses", "ses"],
  zoho: ["zoho", "zmail"],
  mailchimp: ["k1", "k2", "k3"],
  sparkpost: ["scph0", "scph1", "sparkpost"],
  protonmail: ["protonmail", "protonmail2", "protonmail3"],
  messagingengine: ["fm1", "fm2", "fm3"],
  hubspot: ["hs1", "hs2", "hubspot"],
  klaviyo: ["klaviyo"],
  mktomail: ["m1", "mte1", "mte2"],
  sparkpostmail: ["scph0", "scph1"],
  cloudflare: ["cf2024-1", "cf2025-1"],
  mailerlite: ["ml", "mailerlite"],
  campaignmonitor: ["cm"],
};

const RR = { A: 1, NS: 2, PTR: 12, SOA: 6, MX: 15, TXT: 16, AAAA: 28, DNSKEY: 48, TLSA: 52, CAA: 257 };

// AI answer-engine crawlers (UA tokens, lowercased for robots.txt matching).
const AI_BOTS = [
  "GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot", "Claude-Web",
  "PerplexityBot", "Google-Extended", "CCBot", "Applebot-Extended",
];

// ─────────────────────────────────────────────────────────────────────────────
// Small utilities
// ─────────────────────────────────────────────────────────────────────────────

async function mapPool(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  async function worker() {
    while (i < items.length) { const idx = i++; out[idx] = await fn(items[idx], idx); }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) || 0 }, worker));
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// DoH resolver  —  query(name, rrtype) -> string[]   (resolver.py contract)
// Per-request cache (stores in-flight promises so concurrent checks dedupe).
// ─────────────────────────────────────────────────────────────────────────────

export const contractVersion = "1.1.0";

const UNAVAILABLE_HTTP = Object.freeze({
  mtaSts: async () => null,
  robots: async () => null,
  rdap: async () => null,
});

const UNUSED_CLOCK = Object.freeze({ nowMs: () => 0 });

function queryFromDns(dns) {
  if (!dns || typeof dns.query !== "function") throw new TypeError("dns.query must be a function");
  const query = (name, rrtype) => dns.query(name, rrtype);
  if (typeof dns.meta === "function") {
    query.meta = (name, rrtype) => dns.meta(name, rrtype);
  }
  return query;
}

function dnsFromLegacyQuery(query) {
  return {
    query: (name, rrtype) => query(name, rrtype),
    meta: typeof query.meta === "function" ? (name, rrtype) => query.meta(name, rrtype) : undefined,
  };
}

// The only ambient-I/O boundary in this module. Production in-process consumers
// may pass these adapters explicitly to createAuditEngine(); compatibility calls
// without a resolver use the same factory so there is one real implementation.
export function createDefaultAdapters() {
  const cache = new Map();
  const metaCache = new Map(); // "type name" -> { status, ad, error }
  async function raw(name, rrtype) {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${rrtype}`;
    let json;
    try {
      const res = await fetch(url, {
        headers: { accept: "application/dns-json" },
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) { metaCache.set(rrtype + " " + name, { status: null, ad: false, error: true }); return []; }
      json = await res.json();
    } catch (e) {
      metaCache.set(rrtype + " " + name, { status: null, ad: false, error: true });
      return [];
    }
    // Surface DoH Status (RCODE: 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN, 5 REFUSED) and the AD
    // (Authenticated Data = DNSSEC-validated) bit for the DNSSEC/DANE/reliability checks.
    metaCache.set(rrtype + " " + name, { status: json.Status ?? null, ad: !!json.AD, error: false });
    const want = RR[rrtype];
    const rows = (json.Answer || []).filter((a) => a.type === want).map((a) => a.data);
    if (rrtype === "TXT") {
      // De-chunk 255-byte segments + unquote, exactly like resolver.py.
      return rows.map((r) => {
        const parts = [...String(r).matchAll(/"([^"]*)"/g)].map((m) => m[1]);
        return parts.length ? parts.join("") : String(r).trim();
      });
    }
    return rows.map((r) => String(r).trim());
  }
  const dns = {
    query(name, rrtype) {
      const k = rrtype + " " + name;
      if (!cache.has(k)) cache.set(k, raw(name, rrtype));
      return cache.get(k);
    },
    async meta(name, rrtype) {
      await dns.query(name, rrtype);
      return metaCache.get(rrtype + " " + name) || { status: null, ad: false, error: true };
    },
  };
  const http = {
    async mtaSts(domain) {
      try {
        const res = await fetch("https://mta-sts." + domain + "/.well-known/mta-sts.txt", {
          signal: AbortSignal.timeout(3000), redirect: "manual",
        });
        const contentType = res.headers.get("content-type") || "";
        const body = res.status === 200 && contentType.toLowerCase().includes("text/plain")
          ? await res.text() : "";
        return { status: res.status, contentType, body };
      } catch (e) { return null; }
    },
    async robots(domain) {
      try {
        const res = await fetch("https://" + domain + "/robots.txt", {
          signal: AbortSignal.timeout(3000), redirect: "manual",
        });
        return { status: res.status, body: res.ok ? await res.text() : "" };
      } catch (e) { return null; }
    },
    async rdap(domain) {
      try {
        const res = await fetch("https://rdap.org/domain/" + encodeURIComponent(domain), {
          signal: AbortSignal.timeout(3000), headers: { accept: "application/rdap+json" },
        });
        return res.ok ? await res.json() : null;
      } catch (e) { return null; }
    },
  };
  const clock = { nowMs: () => Date.now() };
  return { dns, http, clock };
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS helpers (ports of audit.py)
// ─────────────────────────────────────────────────────────────────────────────

async function firstTxt(name, prefix, q) {
  const p = prefix.toLowerCase();
  for (const rec of await q(name, "TXT")) if (rec.toLowerCase().startsWith(p)) return rec;
  return null;
}

// A pragmatic subset of the Public Suffix List: registry suffixes where the
// registrable domain is the last THREE labels, not two. Not exhaustive (the full PSL
// is a ~200 KB data dependency); it fixes the cases that matter for same-org checks —
// e.g. good.co.uk and evil.co.uk must read as DIFFERENT orgs, not both "co.uk".
const PUBLIC_SUFFIX_2 = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk", "sch.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ad.jp",
  "co.za", "org.za", "gov.za", "ac.za",
  "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
  "com.br", "net.br", "org.br", "gov.br",
  "com.cn", "net.cn", "org.cn", "gov.cn", "ac.cn",
  "co.kr", "or.kr", "com.mx", "com.sg", "com.hk", "com.tw",
  "co.il", "com.tr", "co.id", "com.my", "co.th", "or.th",
]);

function orgBase(host) {
  const labels = host.replace(/\.+$/, "").toLowerCase().split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  return (PUBLIC_SUFFIX_2.has(lastTwo) ? labels.slice(-3) : labels.slice(-2)).join(".");
}

async function isVoid(name, q) {
  if ((await q(name, "TXT")).length) return false;
  return !(await q(name, "A")).length;
}

// ── SSRF guard: reject hostnames that resolve to private/internal/metadata IPs ──
// Post-resolution check — DOMAIN_RE only validates syntax, so a public-looking
// hostname can still point at 169.254.169.254 / 127.0.0.1 / 10.x etc.

function isPublicIp(ip) {
  ip = String(ip || "").trim().toLowerCase();
  if (!ip) return false;
  if (ip.includes(":")) {
    // IPv6
    if (ip === "::1" || ip === "::") return false;            // loopback / unspecified
    // ::ffff:0:0/96 IPv4-mapped — unwrap and re-check as v4
    const m = ip.match(/^::ffff:(?:0:)?([0-9a-f.:]+)$/);
    if (m) {
      const inner = m[1];
      if (inner.includes(".")) return isPublicIp(inner);
      // hex form ::ffff:7f00:1 → two 16-bit groups → dotted quad from the 32 bits
      const grps = inner.split(":").filter(Boolean);
      if (grps.length && grps.length <= 2 && grps.every((g) => /^[0-9a-f]{1,4}$/.test(g))) {
        let n = 0;
        for (const g of grps) n = (n << 16) | parseInt(g, 16);
        n = n >>> 0;
        return isPublicIp([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join("."));
      }
    }
    const head = parseInt(ip.split(":")[0] || "0", 16);
    if ((head & 0xfe00) === 0xfc00) return false;              // fc00::/7 ULA
    if ((head & 0xffc0) === 0xfe80) return false;              // fe80::/10 link-local
    return true;
  }
  // IPv4
  const o = ip.split(".");
  if (o.length !== 4) return false;
  const b = o.map((x) => parseInt(x, 10));
  if (b.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return false;
  if (b[0] === 0) return false;                                // 0.0.0.0/8
  if (b[0] === 127) return false;                              // loopback 127/8
  if (b[0] === 10) return false;                               // private 10/8
  if (b[0] === 172 && b[1] >= 16 && b[1] <= 31) return false;  // private 172.16/12
  if (b[0] === 192 && b[1] === 168) return false;              // private 192.168/16
  if (b[0] === 169 && b[1] === 254) return false;              // link-local 169.254/16
  if (b[0] === 100 && b[1] >= 64 && b[1] <= 127) return false; // CGNAT 100.64/10
  return true;
}

// True only if the host resolves AND every resolved A/AAAA address is public.
// Fail-closed: no addresses, or any private/internal address → false.
async function resolvesPublic(domain, env, q) {
  q = q || makeResolver();
  const [a, aaaa] = await Promise.all([q(domain, "A"), q(domain, "AAAA")]);
  const ips = [...a, ...aaaa].map((x) => String(x).trim()).filter(Boolean);
  if (!ips.length) return false;
  return ips.every(isPublicIp);
}

function mxHosts(mxRows) {
  const out = [];
  for (const r of mxRows) {
    const parts = r.split(/\s+/);
    if (parts.length >= 2 && /^\d+$/.test(parts[0])) {
      const host = parts[parts.length - 1].replace(/\.+$/, "").toLowerCase();
      if (host) out.push(host);
    }
  }
  return out;
}

function isNullMxRow(row) {
  // WHI-50 changes only mixed-answer ambiguity. Preserve the earlier root-exchange
  // spellings, including a non-zero preference, rather than redesign detection here.
  const parts = row.trim().split(/\s+/);
  return parts.length > 0
    && (parts[parts.length - 1].replace(/\.+$/, "") === "" || ["0 .", "0."].includes(row.trim()));
}

function isNullMx(mxRows) {
  return mxRows.length > 0 && mxRows.every(isNullMxRow);
}

function realMxRows(mxRows) {
  return mxRows.filter((row) => !isNullMxRow(row));
}

function mxPatternMatches(pattern, host) {
  pattern = pattern.trim().replace(/\.+$/, "").toLowerCase();
  host = host.replace(/\.+$/, "").toLowerCase();
  if (pattern.startsWith("*.")) {
    // RFC 8461 §4.1: a wildcard matches exactly ONE leftmost label — *.example.com
    // matches mx.example.com but NOT a.b.example.com or example.com itself.
    const suffix = pattern.slice(1); // ".example.com"
    if (!host.endsWith(suffix)) return false;
    const left = host.slice(0, host.length - suffix.length);
    return left.length > 0 && !left.includes(".");
  }
  return pattern === host;
}

async function mxProviders(domain, q) {
  const out = [];
  for (const r of await q(domain, "MX")) {
    const parts = r.split(/\s+/);
    if (parts.length >= 2 && /^\d+$/.test(parts[0])) {
      const host = parts[parts.length - 1].replace(/\.+$/, "").toLowerCase();
      if (!host) continue;
      const labels = host.split(".");
      const provider = labels.length >= 2 ? labels.slice(-2).join(".") : host;
      out.push([parseInt(parts[0], 10), host, provider]);
    }
  }
  return out;
}

// ── SPF ──────────────────────────────────────────────────────────────────────

function spfQualifier(spf) {
  const m = spf.match(/([-~?+]?)all\b/i); // qualifiers are case-insensitive: -ALL == -all
  return !m ? null : (m[1] || "+");
}

async function effectiveTerminator(domain, q, seen, depth) {
  seen = seen || new Set(); depth = depth || 0;
  if (depth > 10 || seen.has(domain)) return null;
  seen.add(domain);
  const spf = await firstTxt(domain, "v=spf1", q);
  if (!spf) return null;
  const qual = spfQualifier(spf);
  if (qual !== null) return qual;
  const m = spf.match(/redirect=(\S+)/);
  if (m) return effectiveTerminator(m[1].replace(/;+$/, ""), q, seen, depth + 1);
  return null;
}

async function countSpfLookups(domain, q, seen, depth) {
  seen = seen || new Set(); depth = depth || 0;
  if (depth > 12 || seen.has(domain)) return [0, 0];
  seen.add(domain);
  const spf = await firstTxt(domain, "v=spf1", q);
  if (!spf) return [0, 0];
  let n = 0, voids = 0;
  for (const tok of spf.split(/\s+/)) {
    const t = tok.toLowerCase();
    if (t === "a" || t === "mx") { n += 1; continue; }
    if (/^(include:|a:|mx:|ptr|exists:|redirect=)/.test(t)) {
      n += 1;
      let sub = null;
      if (t.startsWith("include:")) sub = tok.split(":")[1];
      else if (t.startsWith("redirect=")) sub = tok.split("=").slice(1).join("=").replace(/;+$/, "");
      if (sub) {
        if (await isVoid(sub, q)) voids += 1;
        const [sn, sv] = await countSpfLookups(sub, q, seen, depth + 1);
        n += sn; voids += sv;
      }
    }
  }
  return [n, voids];
}

async function checkSpf(domain, F, q) {
  const spfRecords = (await q(domain, "TXT")).filter((r) => r.toLowerCase().startsWith("v=spf1"));
  if (spfRecords.length > 1) {
    F.push({ area: "SPF", severity: "high", title: "Multiple SPF records (invalid)",
      detail: spfRecords.length + " v=spf1 records are published at the apex. RFC 7208 allows only one — receivers treat multiple as a PermError, so SPF fails entirely.",
      fix: "Merge them into a single v=spf1 record." });
  }
  const spf = await firstTxt(domain, "v=spf1", q);
  if (!spf) {
    F.push({ area: "SPF", severity: "high", title: "No SPF record",
      detail: "No v=spf1 TXT record at the apex. Receivers can't verify which hosts may send for this domain; alignment-based DMARC pass via SPF is impossible.",
      fix: 'Add a TXT record at the apex: "v=spf1 include:<your-ESP> -all" (replace include with your sending providers; end with -all once confident).' });
    return;
  }
  const qual = await effectiveTerminator(domain, q);
  if (qual === null) {
    F.push({ area: "SPF", severity: "medium", title: "SPF has no `all` mechanism",
      detail: "Without a terminating all qualifier, SPF gives receivers no default disposition.",
      fix: "End the SPF record with -all (hard fail) or at least ~all (soft fail)." });
  } else if (qual === "+" || qual === "?") {
    F.push({ area: "SPF", severity: "high", title: "SPF terminates in `" + qual + "all` (permissive)",
      detail: "`" + qual + "all` makes no fail assertion — anything not listed is treated as pass/neutral, so SPF gives effectively no protection against spoofing (`+all` literally authorizes any host).",
      fix: "Change the terminating qualifier to -all (or ~all while testing)." });
  }
  const [n, voids] = await countSpfLookups(domain, q);
  if (n > 10) {
    F.push({ area: "SPF", severity: "high", title: "SPF exceeds 10 DNS lookups (" + n + ")",
      detail: "Over 10 DNS-querying mechanisms triggers a PermError and SPF silently fails at many receivers — a classic invisible deliverability drain.",
      fix: "Flatten or consolidate includes; remove unused senders. Target <=8 to leave headroom." });
  }
  if (voids > 2) {
    F.push({ area: "SPF", severity: "high", title: "SPF exceeds the void-lookup limit (" + voids + ")",
      detail: "More than 2 SPF mechanisms point at names that resolve to nothing (RFC 7208 caps 'void' lookups at 2). This trips a PermError and SPF silently fails — usually a dead/retired include nobody removed.",
      fix: "Find and remove the dead include/redirect/a/mx targets (the ones that no longer resolve)." });
  }
  if (/(?:^|\s)[-~?+]?ptr\b/.test(spf.toLowerCase())) {
    F.push({ area: "SPF", severity: "low", title: "SPF uses the deprecated `ptr` mechanism",
      detail: "The ptr mechanism is slow, unreliable, and explicitly discouraged by RFC 7208 §5.5; some receivers ignore it entirely.",
      fix: "Remove ptr and authorize senders via include:/a/mx/ip4/ip6 instead." });
  }
  const incs = [...spf.toLowerCase().matchAll(/include:(\S+)/g)].map((m) => m[1]);
  const dupes = [...new Set(incs.filter((i) => incs.filter((x) => x === i).length > 1))].sort();
  if (dupes.length) {
    F.push({ area: "SPF", severity: "low", title: "SPF has duplicate include(s)",
      detail: "The record repeats include(s): " + dupes.join(", ") + ". Each duplicate still burns one of the 10 DNS lookups for no benefit.",
      fix: "Remove the repeated include entries." });
  }
  F.push({ area: "SPF", severity: "pass", title: "SPF present",
    detail: "Record found; effective terminator: " + qual + "all; ~" + n + " DNS lookups, " + voids + " void.",
    fix: null, record: spf });
}

// ── DKIM ─────────────────────────────────────────────────────────────────────

function b64ByteLen(s) {
  try { return atob(s.replace(/\s+/g, "")).length; } catch { return -1; }
}

// Real RSA modulus bit-length from a DKIM p= (base64 SubjectPublicKeyInfo DER), or null
// if it can't be parsed — more accurate than estimating from the base64 length. Pure
// atob + manual DER walk so it works on Node AND the Cloudflare Workers runtime.
function rsaModulusBits(b64) {
  let bytes;
  try { bytes = Uint8Array.from(atob(b64.replace(/\s+/g, "")), (c) => c.charCodeAt(0)); }
  catch { return null; }
  let i = 0;
  const readLen = () => {
    let n = bytes[i++];
    if (n & 0x80) { let k = n & 0x7f; n = 0; while (k-- > 0) n = (n << 8) | bytes[i++]; }
    return n;
  };
  const expect = (tag) => { if (bytes[i++] !== tag) throw new Error("der"); return readLen(); };
  try {
    expect(0x30);                              // SubjectPublicKeyInfo SEQUENCE
    const algLen = expect(0x30); i += algLen;  // skip AlgorithmIdentifier
    expect(0x03); i += 1;                       // BIT STRING, skip the unused-bits byte
    expect(0x30);                              // RSAPublicKey SEQUENCE
    let len = expect(0x02);                     // modulus INTEGER
    if (bytes[i] === 0x00) len -= 1;            // strip a leading sign byte
    return len > 0 ? len * 8 : null;
  } catch { return null; }
}

function parseDkim(rec) {
  const kv = {};
  for (const m of rec.matchAll(/(\w+)=([^;]+)/g)) kv[m[1].toLowerCase()] = m[2];
  const ktype = (kv.k || "rsa").trim().toLowerCase();
  const pub = (kv.p || "").trim();
  const flags = (kv.t || "").trim().toLowerCase();
  const testing = flags ? flags.split(":").map((x) => x.trim()).includes("y") : false;
  // An empty p= is a REVOKED selector (RFC 6376 §3.6.1) — never a healthy key.
  if (pub === "") return { ktype, pub, bits: null, testing, valid: false, reason: "revoked" };
  let bits = null, valid = true, reason = null;
  if (ktype === "rsa") {
    bits = rsaModulusBits(pub); // real modulus …
    if (bits === null) { const approx = Math.floor((pub.length * 3) / 4); bits = approx < 200 ? 1024 : approx < 400 ? 2048 : 4096; } // … or estimate if unparseable
  } else if (ktype === "ed25519") {
    // Ed25519 public keys are exactly 32 bytes; anything else is malformed.
    if (b64ByteLen(pub) !== 32) { valid = false; reason = "malformed-ed25519"; }
  }
  return { ktype, pub, bits, testing, valid, reason };
}

async function dkimCandidates(domain, q) {
  const blob = ((await q(domain, "MX")).join(" ") + " " + ((await firstTxt(domain, "v=spf1", q)) || "")).toLowerCase();
  let sels = [];
  for (const [fp, slist] of Object.entries(PROVIDER_SELECTORS)) if (blob.includes(fp)) sels = sels.concat(slist);
  sels = sels.concat(DKIM_SELECTORS);
  const seen = new Set(), out = [];
  for (const s of sels) if (!seen.has(s)) { seen.add(s); out.push(s); }
  return out;
}

async function dkimProbe(domain, sel, q) {
  const name = sel + "._domainkey." + domain;
  let rec = await firstTxt(name, "v=dkim1", q);
  if (!rec) rec = (await q(name, "TXT")).find((r) => r.includes("p=")) || null;
  return rec;
}

async function dkimLookup(domain, q) {
  const cands = await dkimCandidates(domain, q);
  const recs = await mapPool(cands, MAX_DKIM_CONCURRENCY, (s) => dkimProbe(domain, s, q));
  let weak = null, weakTesting = false, invalid = null;
  for (let i = 0; i < cands.length; i++) {
    const rec = recs[i];
    if (!rec) continue;
    const { ktype, bits, testing, valid, reason } = parseDkim(rec);
    if (valid === false) {
      // Revoked/malformed key here. A healthy sibling selector still wins, so record
      // it and keep scanning; surface it only if nothing better turns up.
      invalid = invalid || (reason === "revoked"
        ? "DKIM " + cands[i] + " revoked (empty p=)"
        : "DKIM " + cands[i] + " malformed (" + reason + ")");
      continue;
    }
    if (ktype === "rsa" && bits && bits < 2048) { weak = weak || ("DKIM " + cands[i] + "=RSA-" + bits); weakTesting = weakTesting || testing; continue; }
    const label = ktype.toUpperCase() + (bits ? "-" + bits : "");
    return ["good", "DKIM " + cands[i] + " (" + label + ")", testing];
  }
  if (weak) return ["weak", weak, weakTesting];
  if (invalid) return ["invalid", invalid, false];
  return ["unknown", "no DKIM key at common/provider selectors", false];
}

async function checkDkim(domain, F, q) {
  const [state, note, testing] = await dkimLookup(domain, q);
  if (state === "good") {
    F.push({ area: "DKIM", severity: "pass", title: "DKIM present (" + note + ")",
      detail: "A modern DKIM key was found at a probed selector.", fix: null });
  } else if (state === "weak") {
    F.push({ area: "DKIM", severity: "high", title: "DKIM key is RSA-1024 (legacy)",
      detail: "RSA-1024 is below current strength guidance and is being phased out; some receivers discount it, and it's the first thing a PQC/crypto-hygiene review flags.",
      fix: "Rotate the selector to RSA-2048 (or Ed25519): publish the new key, let it propagate, then switch signing over.", record: note });
  } else if (state === "invalid") {
    F.push({ area: "DKIM", severity: "high", title: "DKIM key is revoked or malformed",
      detail: "A DKIM record is published but the key is unusable (" + note + "). A revoked (empty p=) or malformed key can't verify signatures — receivers treat the mail as unsigned, so DKIM gives no protection.",
      fix: "Publish a valid key at this selector (RSA >=2048 or Ed25519), or remove the dead record and sign from a live selector.", record: note });
  } else {
    F.push({ area: "DKIM", severity: "low", title: "DKIM not found at common/provider selectors",
      detail: "No DKIM key at the selectors probed. DKIM has no discovery mechanism, so this is a blind spot — the domain may well sign with a custom selector. Verify against actual message headers before concluding DKIM is absent; don't treat this as a confirmed gap.",
      fix: "Confirm the selector with the sending provider; if genuinely unsigned, enable DKIM at the ESP." });
  }
  if (testing) {
    F.push({ area: "DKIM", severity: "low", title: "DKIM key is in testing mode (t=y)",
      detail: "The surfaced DKIM key carries the t=y testing flag, which tells receivers to treat the signature as experimental and NOT act on failures — so DKIM gives no real protection while it's set. Usually left over from initial setup.",
      fix: "Remove the t=y flag from the DKIM TXT record once you've confirmed signing works." });
  }
}

// ── DMARC ────────────────────────────────────────────────────────────────────

// RFC 9989 (DMARCbis) tree walk: the applicable DMARC record is the domain's own
// _dmarc if present, otherwise the nearest ancestor's, walking up to the organizational
// domain (bounded to 5 lookups). A subdomain with no record of its own inherits the
// ancestor's sp (subdomain policy) if set, else its p.
async function discoverDmarc(domain, q) {
  domain = domain.replace(/\.+$/, "").toLowerCase();
  const own = await firstTxt("_dmarc." + domain, "v=dmarc1", q);
  if (own) return { rec: own, source: domain, inherited: false };
  const base = orgBase(domain);
  const labels = domain.split(".");
  for (let i = 1; i <= labels.length - 2 && i <= 5; i++) {
    const parent = labels.slice(i).join(".");
    const rec = await firstTxt("_dmarc." + parent, "v=dmarc1", q);
    if (rec) return { rec, source: parent, inherited: true };
    if (parent === base) break; // don't walk above the organizational domain
  }
  return { rec: null, source: null, inherited: false };
}

async function checkDmarc(domain, F, q) {
  const disc = await discoverDmarc(domain, q);
  const rec = disc.rec;
  if (!rec) {
    F.push({ area: "DMARC", severity: "critical", title: "No DMARC record",
      detail: "No policy at _dmarc. Receivers have no instruction on how to handle unauthenticated mail in your name — and as of 2024-25, Gmail/Yahoo/Microsoft require DMARC for bulk senders. This is both a spoofing exposure and a hard deliverability blocker.",
      fix: 'Publish TXT at _dmarc: start with "v=DMARC1; p=none; rua=mailto:dmarc@<domain>" to collect reports. Review those reports before any enforcement, then stage p=quarantine; whether p=reject is appropriate depends on your mail flows (RFC 9989 §7.4).' });
    return;
  }
  const kv = {};
  for (const m of rec.matchAll(/(\w+)=\s*([^;]+)/g)) kv[m[1].toLowerCase()] = m[2];
  const p = (kv.p || "").trim().toLowerCase();
  const sp = (kv.sp || "").trim().toLowerCase();
  const VALID_POLICY = new Set(["none", "quarantine", "reject"]);

  if (disc.inherited) {
    // No _dmarc at this subdomain: it inherits the org domain's policy — the sp
    // (subdomain policy) tag if set, otherwise p (RFC 9989 tree walk).
    const eff = sp || p;
    const src = disc.source;
    if (!VALID_POLICY.has(eff) || eff === "none") {
      F.push({ area: "DMARC", severity: "high", title: "DMARC subdomain not enforced (inherited " + (sp ? "sp" : "p") + "=" + (eff || "<missing>") + " from " + src + ")",
        detail: "This subdomain has no _dmarc record; it inherits " + src + "'s policy, which resolves to " + (eff || "<missing>") + " — spoofed mail from this subdomain isn't stopped.",
        fix: "Publish _dmarc." + domain + " with p=reject, or set sp=reject on " + src + "." });
    } else {
      F.push({ area: "DMARC", severity: "pass", title: "DMARC enforced (inherited " + (sp ? "sp" : "p") + "=" + eff + " from " + src + ")",
        detail: "This subdomain has no record of its own and is covered by " + src + "'s enforced policy.", fix: null, record: rec });
    }
    return;
  }

  const dmarcRecords = (await q("_dmarc." + disc.source, "TXT")).filter((r) => r.toLowerCase().startsWith("v=dmarc1"));
  if (dmarcRecords.length > 1) {
    F.push({ area: "DMARC", severity: "high", title: "Multiple DMARC records (invalid)",
      detail: dmarcRecords.length + " DMARC records exist at _dmarc. Exactly one is allowed — receivers ignore the policy entirely when there are several, so you effectively have no DMARC.",
      fix: "Keep one DMARC record and remove the rest." });
  }
  const rua = "rua" in kv;
  if (!VALID_POLICY.has(p)) {
    F.push({ area: "DMARC", severity: "high", title: "DMARC policy value is invalid (p=" + (p || "<missing>") + ")",
      detail: "The p= tag must be exactly none, quarantine, or reject (RFC 9989). An unrecognized or missing value means receivers apply no enforcement — you have a DMARC record but no effective policy.",
      fix: "Set p= to none (monitor), quarantine, or reject." });
  } else if (p === "none") {
    F.push({ area: "DMARC", severity: "high", title: "DMARC policy is p=none (monitor only)",
      detail: "p=none offers, in the words of RFC 9989, no expression of preference — a receiver applying DMARC has nothing to act on, though its own filtering still applies. An enforcement policy requests quarantine or rejection of failures, but it can affect legitimate mail when an authorized sender is unauthenticated or misaligned, which is why aggregate reports come first. This is primarily an anti-spoofing gap, not a deliverability failure.",
      fix: "Collect and review DMARC aggregate reports before enforcement, and remediate every legitimate unauthenticated or misaligned stream. Move to p=quarantine once authorized sources are passing. Before considering p=reject, ensure every legitimate stream has valid, DMARC-aligned DKIM rather than relying only on SPF. RFC 9989 §7.4 advises domains whose users may post to mailing lists not to publish p=reject; for those that still do, it recommends at least a month at p=none followed by an equally long period at p=quarantine. Treat reject as conditional on your mail flows, not as the default destination. RFC 9989 removed pct; use t=y to test an enforcement policy instead." });
  } else {
    F.push({ area: "DMARC", severity: "pass", title: "DMARC enforced (p=" + p + ")",
      detail: "Enforcement policy in place.", fix: null, record: rec });
    if (sp === "none") {
      F.push({ area: "DMARC", severity: "medium", title: "DMARC subdomain policy not enforced (sp=none)",
        detail: "The org domain is enforced but sp=none leaves every subdomain unprotected — attackers spoof random.<domain> and DMARC won't stop it. A common gap on domains with one strong apex policy.",
        fix: "Set sp=reject (or sp=quarantine) so the enforcement also covers subdomains." });
    }
  }
  const pct = (kv.pct || "").trim();
  if (pct && /^\d+$/.test(pct) && parseInt(pct, 10) < 100) {
    F.push({ area: "DMARC", severity: "medium", title: "DMARC only partially enforced (pct=" + pct + ")",
      detail: "pct=" + pct + " applies the policy to only " + pct + "% of failing mail — the rest is let through, so enforcement is probabilistic. (Note: pct is also removed in DMARCbis / RFC 9989.)",
      fix: "Once confident, remove pct (or set pct=100) so the policy applies to all failing mail." });
  }
  const removed = ["rf", "ri", "pct"].filter((t) => t in kv);
  if (removed.length) {
    F.push({ area: "DMARC", severity: "low", title: "DMARC uses tags removed in RFC 9989 (DMARCbis)",
      detail: "The record uses " + removed.join(", ") + ", which DMARCbis (RFC 9989, published May 2026, obsoletes RFC 7489) removes. They're still tolerated today but are no longer part of the spec; np= is the new tag for non-existent subdomains.",
      fix: "Drop rf/ri/pct on your next edit; add np=reject to cover non-existent subdomains per RFC 9989." });
  }
  if (!rua) {
    F.push({ area: "DMARC", severity: "medium", title: "DMARC has no rua (no aggregate reporting)",
      detail: "Without rua you're blind to who's sending as you and to auth failures — you lose the early-warning signal a deliverability owner relies on.",
      fix: "Add rua=mailto:dmarc@<domain> to receive daily aggregate XML reports." });
  } else {
    const dests = [...rec.matchAll(/mailto:[^@\s;,]+@([^\s;,!]+)/gi)].map((m) => m[1]);
    const unauth = [];
    for (const dest of new Set(dests.map((d) => d.replace(/\.+$/, "").toLowerCase()))) {
      if (orgBase(dest) !== orgBase(domain)) {
        const auth = await firstTxt(domain + "._report._dmarc." + dest, "v=dmarc1", q);
        if (!auth) unauth.push(dest);
      }
    }
    if (unauth.length) {
      F.push({ area: "DMARC", severity: "medium", title: "DMARC report destination not authorized",
        detail: "Aggregate/forensic reports are sent to an external domain (" + unauth.sort().join(", ") + ") that hasn't published the required authorization record, so most receivers will silently DROP your reports — you think you have reporting, but you don't.",
        fix: "Have the destination publish a TXT record at '" + domain + "._report._dmarc.<destination>' containing 'v=DMARC1;' (your DMARC vendor usually does this automatically)." });
    }
  }
}

// ── MTA-STS (DNS TXT + HTTPS policy fetch) ───────────────────────────────────

async function fetchMtaStsPolicy(domain, q, http, dns) {
  // SSRF: host adapters validate domain syntax, but a valid-looking hostname can still
  // resolve internally. Reject unless mta-sts.<domain> resolves to public IP(s) only.
  // Short timeout + size cap. redirect:"manual" — don't chase a redirect off-host.
  try {
    if (!(await resolvesPublic("mta-sts." + domain, null, q))) return null; // fail-closed
    const res = await http.mtaSts(domain, dns);
    if (!res) return null;
    // RFC 8461 §3.3: the policy MUST be served as HTTP 200 with Content-Type text/plain.
    if (res.status !== 200) return null;
    if (!(res.contentType || "").toLowerCase().includes("text/plain")) return null;
    return String(res.body || "").slice(0, 8192);
  } catch (e) {
    return null;
  }
}

// RFC 8461 §3.2 policy validation. Returns { problems[], mode, maxAge, polMx }.
// A well-formed policy has version: STSv1, a valid mode, an integer max_age in range,
// and (unless mode: none) at least one mx:. Exported for conformance tests.
export function mtaStsPolicyProblems(policy) {
  const version = (policy.match(/^[ \t]*version:[ \t]*(\S+)/im) || [])[1];
  const mode = ((policy.match(/^[ \t]*mode:[ \t]*(\w+)/im) || [])[1] || "").toLowerCase();
  const maxAgeRaw = (policy.match(/^[ \t]*max_age:[ \t]*(\d+)/im) || [])[1];
  const maxAge = maxAgeRaw === undefined ? null : parseInt(maxAgeRaw, 10);
  const polMx = [...policy.matchAll(/^[ \t]*mx:[ \t]*(\S+)/gim)].map((m) => m[1]);
  const problems = [];
  if (!version || version.toLowerCase() !== "stsv1") problems.push("missing/invalid version (must be STSv1)");
  if (!["enforce", "testing", "none"].includes(mode)) problems.push("missing/invalid mode");
  if (maxAge === null || maxAge <= 0 || maxAge > 31557600) problems.push("missing/invalid max_age");
  if (mode !== "none" && polMx.length === 0) problems.push("no mx entries");
  return { problems, mode, maxAge, polMx };
}

async function checkMtaSts(domain, F, q, http, dns) {
  const txt = await firstTxt("_mta-sts." + domain, "v=stsv1", q);
  if (!txt) {
    F.push({ area: "MTA-STS", severity: "medium", title: "No MTA-STS policy",
      detail: "MTA-STS lets you require TLS for inbound SMTP and is part of a modern transport posture (and increasingly asked for in EU procurement, and specified in BSI's guidance for secure email transport (TR-03108)). Absent it, downgrade attacks on mail-in-transit are possible.",
      fix: "Publish _mta-sts TXT (v=STSv1; id=...) and host https://mta-sts.<domain>/.well-known/mta-sts.txt. Stage it: publish TLS-RPT first so you get failure reports, start at mode: testing, confirm every production AND backup MX passes TLS, then switch to mode: enforce (RFC 8461 provides testing mode for exactly this)." });
    return;
  }
  const policy = await fetchMtaStsPolicy(domain, q, http, dns);
  if (!policy) {
    F.push({ area: "MTA-STS", severity: "medium", title: "MTA-STS TXT present but policy file not retrievable",
      detail: "The _mta-sts TXT record advertises a policy, but https://mta-sts." + domain + "/.well-known/mta-sts.txt did not return a valid policy (RFC 8461 requires HTTP 200 with Content-Type text/plain). Senders can't fetch it, so MTA-STS isn't actually enforced.",
      fix: "Serve the policy at that URL over HTTPS with status 200 and Content-Type: text/plain." });
    return;
  }
  const { problems, mode, polMx } = mtaStsPolicyProblems(policy);
  if (problems.length) {
    F.push({ area: "MTA-STS", severity: mode === "enforce" ? "high" : "medium", title: "MTA-STS policy is malformed",
      detail: "The hosted policy is invalid (" + problems.join("; ") + "). RFC 8461 requires version: STSv1, a valid mode, an integer max_age, and at least one mx: (unless mode: none)." +
        (mode === "enforce" ? " Under mode: enforce a malformed policy can break inbound mail delivery." : ""),
      fix: "Fix the hosted mta-sts.txt to include version: STSv1, mode:, max_age:, and mx: lines per RFC 8461." });
    return;
  }
  F.push({ area: "MTA-STS", severity: mode === "enforce" ? "pass" : "medium", title: "MTA-STS present (mode: " + mode + ")",
    detail: "Policy published." + (mode === "enforce" ? "" : " mode is not 'enforce' — testing/none gives no real protection."),
    fix: mode === "enforce" ? null : "Move policy to mode: enforce once tested." });
  const realMx = mxHosts(await q(domain, "MX"));
  if (polMx.length && realMx.length) {
    const unmatched = realMx.filter((h) => !polMx.some((p) => mxPatternMatches(p, h)));
    if (unmatched.length) {
      F.push({ area: "MTA-STS", severity: mode === "enforce" ? "high" : "medium", title: "MTA-STS policy does not cover all MX hosts",
        detail: "These live MX hosts match no mx: line in the policy: " + unmatched.join(", ") + "." +
          (mode === "enforce" ? " Under mode: enforce, senders will REFUSE to deliver to them — active mail loss." : " Once you move to enforce, mail to them will fail."),
        fix: "Add the missing MX hostnames (or a *.<domain> wildcard) to the mx: lines in the hosted policy." });
    }
  }
}

// ── TLS-RPT + BIMI ───────────────────────────────────────────────────────────

async function checkSimple(domain, F, q) {
  const tlsrpt = await firstTxt("_smtp._tls." + domain, "v=tlsrptv1", q);
  if (tlsrpt) {
    if (!tlsrpt.toLowerCase().includes("rua=")) {
      F.push({ area: "TLS-RPT", severity: "low", title: "TLS-RPT present but has no rua endpoint",
        detail: "A TLS-RPT record exists but defines no rua= destination, so no TLS failure reports are actually delivered anywhere.",
        fix: 'Add a destination: "v=TLSRPTv1; rua=mailto:tlsrpt@<domain>".' });
    } else {
      F.push({ area: "TLS-RPT", severity: "pass", title: "TLS-RPT present", detail: "Receiving TLS failure reports.", fix: null });
    }
  } else {
    F.push({ area: "TLS-RPT", severity: "low", title: "No TLS-RPT",
      detail: "No SMTP TLS reporting; you won't learn when senders fail to negotiate TLS to you.",
      fix: 'Add _smtp._tls TXT: "v=TLSRPTv1; rua=mailto:tlsrpt@<domain>".' });
  }
  const bimi = await firstTxt("default._bimi." + domain, "v=bimi1", q);
  if (bimi) {
    if (!/(?:^|;)\s*a=\s*https?:\/\//.test(bimi.toLowerCase())) {
      F.push({ area: "BIMI", severity: "low", title: "BIMI present without a VMC",
        detail: "A BIMI record is published but has no a= (Verified Mark Certificate) URL. Gmail and Apple Mail require a VMC to actually display the logo, so without it most inboxes won't render your mark.",
        fix: "Obtain a VMC (or a CMC) and add it as a=https://<domain>/path/vmc.pem to the BIMI record." });
    } else {
      F.push({ area: "BIMI", severity: "pass", title: "BIMI present (with VMC)", detail: "Brand indicator + VMC published.", fix: null });
    }
  } else {
    F.push({ area: "BIMI", severity: "low", title: "No BIMI",
      detail: "BIMI (logo in inbox) requires p=quarantine/reject DMARC first; it's a trust/brand signal, not a blocker.",
      fix: "Once DMARC is enforced, publish default._bimi with an SVG logo (+ VMC for Gmail/Apple)." });
  }
}

// ── Transport: MX / null-MX / DANE  (STARTTLS:25 probe DROPPED at the edge) ──

function badTlsa(rows) {
  for (const r of rows) {
    const parts = r.split(/\s+/);
    if (parts.length >= 3 && parts.slice(0, 3).every((p) => /^\d+$/.test(p))) {
      const usage = +parts[0], mtype = +parts[2];
      if (usage === 0 || usage === 1) return "one uses usage " + usage + " (PKIX mode), which is inappropriate for SMTP DANE.";
      if (mtype === 0) return "one uses matching-type 0 (full cert), which is brittle across cert rotation.";
    }
  }
  return "";
}

async function checkTransport(domain, F, q) {
  const mx = await q(domain, "MX");
  if (!mx.length) {
    F.push({ area: "Transport", severity: "low", title: "No MX records",
      detail: "No MX record is published. SMTP then treats the domain as if it had an implicit MX pointing to itself and resolves that host's address records, so this does not show that the domain receives no mail — a null MX (0 .) is what says that explicitly. This may be intentional for a send-only or parked domain.",
      fix: "If it should receive mail, publish MX records. If it should not, publish a null MX (0 .) so receivers know." });
    return null;
  }
  if (isNullMx(mx)) {
    F.push({ area: "Transport", severity: "pass", title: "Null MX (RFC 7505) — domain declares no mail",
      detail: "A null MX (0 .) declares under RFC 7505 that this domain accepts no inbound mail. That is good hygiene for a domain not meant to receive mail. It says nothing about whether the domain sends — outbound authentication is assessed separately.", fix: null });
    return null;
  }
  const host = realMxRows(mx).sort((a, b) => {
    const pa = a.split(/\s+/)[0], pb = b.split(/\s+/)[0];
    return (/^\d+$/.test(pa) ? +pa : 99) - (/^\d+$/.test(pb) ? +pb : 99);
  })[0].split(/\s+/).pop().replace(/\.+$/, "");
  const daneName = "_25._tcp." + host;
  const dane = await q(daneName, "TLSA");
  const daneMeta = q.meta ? await q.meta(daneName, "TLSA") : null;
  if (dane.length) {
    const bad = badTlsa(dane);
    if (bad) {
      F.push({ area: "Transport", severity: "medium", title: "DANE/TLSA present but misconfigured",
        detail: "TLSA records exist but " + bad + " For SMTP DANE only usage 3 (DANE-EE) or 2 (DANE-TA) are valid, and matching-type 1 (SHA-256) is recommended; an invalid record can break DANE-enforcing senders.",
        fix: "Correct the TLSA usage/selector/matching-type (typically '3 1 1' for the MX cert) and re-publish." });
    } else if (daneMeta && daneMeta.ad === false) {
      // TLSA present but the answer isn't DNSSEC-authenticated — DANE REQUIRES a validated
      // chain (RFC 7672), so an unsigned TLSA is not active protection.
      F.push({ area: "Transport", severity: "medium", title: "DANE/TLSA present but not DNSSEC-validated",
        detail: "TLSA records exist but the response isn't DNSSEC-authenticated (AD bit not set). DANE requires a validated DNSSEC chain — without it senders can't trust the TLSA, so DANE gives no protection and can't be enforced.",
        fix: "Enable DNSSEC on the zone so the TLSA records are cryptographically validated." });
    } else {
      F.push({ area: "Transport", severity: "pass", title: "DANE/TLSA present", detail: "TLSA records bind the MX cert" + (daneMeta && daneMeta.ad ? " (DNSSEC-validated)." : "."), fix: null });
    }
  } else {
    F.push({ area: "Transport", severity: "low", title: "No DANE/TLSA",
      detail: "No TLSA records on the MX. DANE is recommended in BSI guidance for secure email transport (TR-03108) and depends on DNSSEC.",
      fix: "If DNSSEC is enabled, publish TLSA records for the MX; otherwise enable DNSSEC first." });
  }
  return host;
}

// ── MX hygiene ───────────────────────────────────────────────────────────────

async function checkMxHygiene(domain, F, q) {
  const mxs = await mxProviders(domain, q);
  const providers = {};
  for (const [prio, , prov] of mxs) (providers[prov] = providers[prov] || []).push(prio);
  const names = Object.keys(providers);
  if (names.length <= 1) return;
  const primary = names.reduce((a, b) => (Math.min(...providers[a]) <= Math.min(...providers[b]) ? a : b));
  const primHi = Math.max(...providers[primary]);
  const risky = names.filter((p) => p !== primary && Math.min(...providers[p]) <= primHi);
  const listing = names.map((p) => p + " (prio " + [...providers[p]].sort((a, b) => a - b).join(",") + ")").join("; ");
  F.push({ area: "MX", severity: risky.length ? "medium" : "low", title: "Mixed MX providers (" + names.length + ")",
    detail: "Inbound MX spans multiple providers: " + listing + ". Senders deliver to whichever MX is reachable at the lowest priority, so a stale/duplicate backup provider can silently receive (or drop) mail and is a relay/interception surface." +
      (risky.length ? " '" + risky[0] + "' sits at a priority that can actively receive mail today." : ""),
    fix: "Confirm every MX provider is intentional and enforces TLS; remove stale/registrar-default backup MX so all inbound flows to your primary provider." });
}

// ── DNSSEC (DNS, runs in the parallel batch) ─────────────────────────────────

async function checkDnssec(domain, F, q) {
  const keys = await q(domain, "DNSKEY");
  const meta = q.meta ? await q.meta(domain, "DNSKEY") : null;
  // The AD (Authenticated Data) bit from a validating resolver is authoritative and
  // respects the zone cut — a validated NODATA inside a signed parent still sets AD, so
  // a subdomain isn't mis-reported as unsigned. Fall back to DNSKEY presence only when
  // meta isn't available (non-DoH resolver / mock).
  const signed = meta ? meta.ad : keys.length > 0;
  if (signed) {
    F.push({ area: "DNSSEC", severity: "pass", title: "DNSSEC enabled",
      detail: "The zone is DNSSEC-signed and answers validate.", fix: null });
  } else {
    F.push({ area: "DNSSEC", severity: "low", title: "DNSSEC not enabled",
      detail: "DNS answers for this domain aren't cryptographically signed/validated — and DANE can't be used without it. A trust/security gap more than a deliverability one.",
      fix: "Enable DNSSEC at your DNS provider (it's also the prerequisite for DANE)." });
  }
}

// ── Domain age / expiry via RDAP (one HTTPS call, 3s cap, fail-open) ─────────
// RDAP is the modern WHOIS (HTTPS/JSON); legacy WHOIS:43 isn't reachable at the edge.

async function checkDomainAge(domain, F, http, clock) {
  let data;
  try {
    data = await http.rdap(domain);
    if (!data) return;              // no RDAP for this TLD / not found → say nothing
  } catch (e) { return; }           // fail-open: never extend the latency budget
  const events = Array.isArray(data && data.events) ? data.events : [];
  const now = clock.nowMs();
  const reg = events.find((e) => e.eventAction === "registration");
  if (reg && reg.eventDate) {
    const age = Math.floor((now - Date.parse(reg.eventDate)) / 86400000);
    if (age >= 0 && age < 90) {
      F.push({ area: "Reputation", severity: "medium", title: "Domain is newly registered (" + age + " days)",
        detail: "Brand-new domains have no sending reputation, so mailbox providers throttle them. Sending cold or at volume now risks the spam folder.",
        fix: "Warm up gradually — start low-volume to engaged recipients and ramp over weeks before scaling." });
    }
  }
  const exp = events.find((e) => e.eventAction === "expiration");
  if (exp && exp.eventDate) {
    const left = Math.floor((Date.parse(exp.eventDate) - now) / 86400000);
    if (left >= 0 && left < 30) {
      F.push({ area: "Reputation", severity: "high", title: "Domain expires in " + left + " days",
        detail: "If the registration lapses, mail and the website stop entirely — a full outage, and a reputation reset once recovered.",
        fix: "Renew the domain now and turn on auto-renew." });
    }
  }
}

// ── AI-bot readiness — light (one robots.txt fetch, 3s cap, fail-open) ────────

function robotsBlocksAiBots(txt) {
  const lines = txt.split(/\r?\n/).map((l) => l.replace(/#.*/, "").trim()).filter(Boolean);
  const groups = [];
  let cur = null, expectAgent = false;
  for (const ln of lines) {
    const ua = ln.match(/^user-agent:\s*(.+)$/i);
    if (ua) {
      if (!expectAgent) { cur = { agents: [], rules: [] }; groups.push(cur); }
      cur.agents.push(ua[1].trim().toLowerCase());
      expectAgent = true;
      continue;
    }
    const rule = ln.match(/^(dis)?allow:\s*(.*)$/i);
    if (rule && cur) { cur.rules.push({ allow: !rule[1], path: rule[2].trim() }); expectAgent = false; }
  }
  const rootBlocked = (gs) => {
    let dis = false, allowRoot = false;
    for (const g of gs) for (const r of g.rules) {
      if (r.path === "/") { if (r.allow) allowRoot = true; else dis = true; }
    }
    return dis && !allowRoot;
  };
  return AI_BOTS.filter((bot) => {
    const ua = bot.toLowerCase();
    const exact = groups.filter((g) => g.agents.includes(ua));     // specific UA wins…
    return rootBlocked(exact.length ? exact : groups.filter((g) => g.agents.includes("*"))); // …else "*"
  });
}

async function checkAiBots(domain, F, q, http, dns) {
  let txt;
  try {
    // SSRF: syntax validation alone cannot stop a host resolving to a private/metadata
    // address. Fail-closed (skip the check) if the post-resolution IP is not public.
    if (!(await resolvesPublic(domain, null, q))) return;
    // redirect:"manual" — the host is attacker-controllable, so don't chase a redirect
    // to an internal/metadata URL (defense-in-depth + parity with the skill's no-follow).
    const res = await http.robots(domain, dns);
    if (!res || res.status < 200 || res.status >= 300) return; // no robots.txt / redirect → no finding
    txt = String(res.body || "").slice(0, 20000);
  } catch (e) { return; }
  const blocked = robotsBlocksAiBots(txt);
  if (blocked.length) {
    F.push({ area: "AI visibility", severity: "low", title: "robots.txt blocks AI crawlers",
      detail: "robots.txt disallows " + blocked.slice(0, 4).join(", ") + (blocked.length > 4 ? ", and others" : "") +
        ". As people increasingly ask AI engines (ChatGPT, Perplexity, Google AI) about vendors, blocking these crawlers makes your site invisible to those answers.",
      fix: "Allow the AI crawlers you want in robots.txt (or drop the blanket Disallow)." });
  }
}

// ── Reverse DNS / FCrDNS on the primary MX (DNS, parallel) ───────────────────

function reverseName(ip) { return ip.split(".").reverse().join(".") + ".in-addr.arpa"; }

async function checkReverseDns(domain, F, q) {
  const mx = await q(domain, "MX");
  if (!mx.length) return;
  if (isNullMx(mx)) return;
  const realMx = realMxRows(mx);
  if (!realMx.length) return;
  const host = realMx.sort((a, b) => {
    const pa = a.split(/\s+/)[0], pb = b.split(/\s+/)[0];
    return (/^\d+$/.test(pa) ? +pa : 99) - (/^\d+$/.test(pb) ? +pb : 99);
  })[0].split(/\s+/).pop().replace(/\.+$/, "");
  const ips = (await q(host, "A")).filter((ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip));
  if (!ips.length) return;
  const ip = ips[0];
  const ptr = await q(reverseName(ip), "PTR");
  if (!ptr.length) {
    F.push({ area: "Transport", severity: "low", title: "Mail server has no reverse DNS (PTR)",
      detail: "The primary MX (" + host + ", " + ip + ") has no PTR record. Receivers check reverse DNS on connecting mail servers, so a missing PTR hurts deliverability for self-hosted / own-IP senders (managed providers like Google and Microsoft set this for you).",
      fix: "Have your host set a PTR (reverse DNS) record for the mail server's IP that matches its hostname." });
    return;
  }
  const ptrName = ptr[0].replace(/\.+$/, "");
  const fwd = await q(ptrName, "A");
  if (!fwd.includes(ip)) {
    F.push({ area: "Transport", severity: "low", title: "Mail server reverse DNS isn't forward-confirmed",
      detail: "The MX IP " + ip + " has a PTR (" + ptrName + ") but that name doesn't resolve back to the same IP — no forward-confirmed reverse DNS (FCrDNS). Some receivers read this as a spam signal.",
      fix: "Align the PTR hostname and its A record so reverse and forward DNS agree." });
  }
}

// ── CAA — which CAs may issue TLS certs (protects the certs MTA-STS/DANE lean on) ──

async function checkCaa(domain, F, q) {
  const caa = await q(domain, "CAA");
  if (!caa.length) {
    F.push({ area: "CAA", severity: "low", title: "No CAA records",
      detail: "No CAA record restricts which certificate authorities can issue TLS certificates for your domain. CAA narrows cert mis-issuance — and the certs your MTA-STS and DANE rely on are part of your email trust chain.",
      fix: 'Publish a CAA record naming your CA(s), e.g. 0 issue "letsencrypt.org".' });
  }
}

// ── Effort×value classification (verbatim from audit.py) ──────────────────────

function priority(f) {
  if (f.severity === "pass") return [null, null];
  const a = f.area, t = f.title.toLowerCase();
  if (a === "SPF") {
    if (t.includes("exceeds 10") || t.includes("void-lookup")) return t.includes("exceeds 10") ? ["high", "high"] : ["low", "high"];
    if (t.includes("ptr") || t.includes("duplicate")) return ["low", "low"];
    return ["low", "high"];
  }
  if (a === "DKIM") return ["low", "low"];
  if (a === "DMARC") {
    if (t.includes("p=none (monitor")) return ["high", "high"];
    if (t.includes("removed in rfc 9989")) return ["low", "low"];
    return ["low", "high"];
  }
  if (a === "MTA-STS") {
    if (t.includes("does not cover all mx")) return ["low", "high"];
    if (t.includes("max_age")) return ["low", "low"];
    return ["high", "low"];
  }
  if (a === "TLS-RPT") return ["low", "low"];
  if (a === "BIMI") return ["high", "low"];
  if (a === "MX") return ["low", "high"];
  if (a === "Transport") return t.includes("dane") ? ["high", "low"] : ["low", "low"];
  if (a === "DNSSEC") return ["high", "low"];          // security/trust, not a deliverability lever → Hardening
  if (a === "Reputation") return ["low", "high"];      // warm-up / renew → Quick win
  if (a === "AI visibility") return ["low", "high"];   // unblock AI crawlers → Quick win
  if (a === "CAA") return ["low", "low"];              // cert-issuance hygiene → Fill-in
  return ["low", "low"];
}

const QUADRANT = {
  "low,high": "Quick wins — low effort, high value (do first)",
  "high,high": "Major projects — high effort, high value (plan & resource)",
  "low,low": "Fill-ins — low effort, low value (spare time)",
  "high,low": "Hardening — high effort, security/compliance value (when required, e.g. NIS2 / security reviews); not a deliverability or engagement lever",
};

function action(f) {
  if (f.severity === "pass") return null;
  const a = f.area, t = f.title.toLowerCase();
  if (a === "SPF") {
    if (t.includes("multiple spf")) return "Merge to a single SPF record";
    if (t.includes("no spf")) return "Publish an SPF record";
    if (t.includes("exceeds 10")) return "Flatten SPF to under 10 lookups";
    if (t.includes("void-lookup")) return "Remove dead SPF includes";
    if (t.includes("no `all`") || t.includes("no 'all'")) return "Add a terminating -all to SPF";
    if (t.includes("ptr")) return "Remove the SPF ptr mechanism";
    if (t.includes("duplicate")) return "Remove duplicate SPF includes";
    return "Tighten SPF to a hard -all policy";
  }
  if (a === "DKIM") {
    if (t.includes("rsa-1024")) return "Rotate DKIM to a 2048-bit key";
    if (t.includes("testing mode")) return "Take the DKIM key out of testing (t=y)";
    return "Confirm or enable DKIM signing";
  }
  if (a === "DMARC") {
    if (t.includes("no dmarc")) return "Publish a DMARC policy";
    if (t.includes("multiple dmarc")) return "Merge to a single DMARC record";
    if (t.includes("p=none (monitor")) return "Review DMARC reports, then stage quarantine";
    if (t.includes("subdomain policy")) return "Set DMARC sp=reject for subdomains";
    if (t.includes("partially enforced")) return "Raise DMARC pct to 100";
    if (t.includes("removed in rfc 9989")) return "Modernize DMARC tags for RFC 9989";
    if (t.includes("report destination")) return "Authorize the external DMARC report destination";
    if (t.includes("rua")) return "Turn on DMARC reporting (rua) — needed before you enforce";
    return "Strengthen the DMARC policy";
  }
  if (a === "MTA-STS") {
    if (t.includes("does not cover all mx")) return "Fix MTA-STS mx: entries to match your MX";
    if (t.includes("max_age")) return "Set a valid MTA-STS max_age";
    return "Publish an MTA-STS policy";
  }
  if (a === "TLS-RPT") return t.includes("no rua") ? "Add a rua endpoint to TLS-RPT" : "Add a TLS-RPT record";
  if (a === "BIMI") return t.includes("without a vmc") ? "Add a VMC to your BIMI record" : "Get a VMC, then publish BIMI";
  if (a === "MX") return "Consolidate to one MX provider";
  if (a === "Transport") {
    if (t === "no mx records") return "Confirm whether this domain should receive mail";
    if (t.includes("misconfigured")) return "Correct the DANE/TLSA record";
    if (t.includes("no reverse dns") || t.includes("has no reverse")) return "Set reverse DNS (PTR) for your mail server";
    if (t.includes("forward-confirmed")) return "Fix forward-confirmed reverse DNS (FCrDNS)";
    return t.includes("dane") ? "Publish DANE/TLSA records" : "Confirm STARTTLS on the mail server";
  }
  if (a === "CAA") return "Add a CAA record";
  if (a === "DNSSEC") return "Enable DNSSEC";
  if (a === "Reputation") return t.includes("expires") ? "Renew the domain before it lapses" : "Warm up the domain before scaling sends";
  if (a === "AI visibility") return "Unblock AI crawlers in robots.txt";
  return f.title;
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestration
// ─────────────────────────────────────────────────────────────────────────────

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, pass: 4 };

async function auditDomainWithPorts(domain, q, http, clock, dns) {
  const spf = [], dkim = [], dmarc = [], mta = [], simple = [], transport = [], mxh = [],
    dnssec = [], rep = [], aibots = [], rdns = [], caa = [];
  let mxHost = null;
  await Promise.all([
    checkSpf(domain, spf, q),
    checkDkim(domain, dkim, q),
    checkDmarc(domain, dmarc, q),
    checkMtaSts(domain, mta, q, http, dns),
    checkSimple(domain, simple, q),
    checkTransport(domain, transport, q).then((h) => { mxHost = h; }),
    checkMxHygiene(domain, mxh, q),
    checkDnssec(domain, dnssec, q),
    checkDomainAge(domain, rep, http, clock),
    checkAiBots(domain, aibots, q, http, dns),
    checkReverseDns(domain, rdns, q),
    checkCaa(domain, caa, q),
  ]);
  // INBOUND-ONLY controls are not applicable to a domain that publishes a true null MX.
  // MTA-STS (RFC 8461) protects mail being delivered TO a domain. Recommending it for mail
  // that by definition never arrives is noise dressed as a finding — and it competed with
  // real sending problems in the priority ranking. These checks run in parallel, so the MX
  // verdict isn't known until they've all settled; filter here rather than serialise them.
  const nullMx = transport.some((f) => /^Null MX \(RFC 7505\)/.test(f.title || ""));
  // TLS-RPT reports on TLS negotiation for mail arriving AT this domain, so it is
  // inbound-only for the same reason MTA-STS is. (DANE needs no entry: checkTransport
  // returns early on a null MX, so it is never probed.)
  const inboundOnly = new Set(["MTA-STS", "TLS-RPT"]);
  const mtaApplicable = nullMx
    ? [{ area: "MTA-STS", severity: "pass", title: "MTA-STS not applicable — domain receives no mail",
        detail: "MTA-STS tells sending servers to require TLS when delivering TO this domain. This domain publishes a null MX, so there is no inbound delivery for a policy to protect. Not a gap.", fix: null }]
    : mta;
  const F = [...spf, ...dkim, ...dmarc, ...mtaApplicable, ...simple, ...transport, ...mxh, ...dnssec, ...rep, ...aibots, ...rdns, ...caa]
    .filter((f) => !(nullMx && inboundOnly.has(f.area) && f.severity !== "pass"));
  F.sort((x, y) => (SEV_ORDER[x.severity] ?? 5) - (SEV_ORDER[y.severity] ?? 5));
  for (const f of F) {
    const [effort, value] = priority(f);
    f.effort = effort; f.value = value;
    if (effort) { f.quadrant = QUADRANT[effort + "," + value]; f.action = action(f); }
  }
  const summary = {};
  for (const s of ["critical", "high", "medium", "low", "pass"]) summary[s] = F.filter((f) => f.severity === s).length;
  // I20: if a CRITICAL lookup (SPF/DMARC/MX) hit a transient failure (SERVFAIL/REFUSED or
  // a fetch error) the audit is inconclusive — those verdicts can't be trusted as "absent".
  // Distinct from NXDOMAIN(3)/NODATA(0), which are conclusive. The Action folds this into
  // audit-complete; other surfaces expose it for downstream consumers.
  let inconclusive = false, inconclusiveReason = null;
  if (typeof q === "function" && q.meta) {
    for (const [n, t] of [[domain, "TXT"], ["_dmarc." + domain, "TXT"], [domain, "MX"]]) {
      const m = await q.meta(n, t);
      if (m.error || m.status === 2 || m.status === 5) {
        inconclusive = true;
        inconclusiveReason = t + " " + n + ": " + (m.error ? "lookup error" : "SERVFAIL/REFUSED");
        break;
      }
    }
  }
  return { domain, primary_mx: mxHost, summary, findings: F, inconclusive, inconclusive_reason: inconclusiveReason };
}

// batch_score.py parity surface — the DNS-only, edge-safe Y/N/N/A buckets + gap.
// Exported for the golden-set parity harness (diff vs Python batch_score.py).
async function bucketsWithQuery(domain, q) {
  const r = { SPF: false, DMARC: false, DMARC_enforced: false, DMARC_rua: false, MTA_STS: false, TLS_RPT: false, DANE: false, BIMI: false };
  const note = [];

  const spf = await firstTxt(domain, "v=spf1", q);
  if (spf) {
    const qual = await effectiveTerminator(domain, q);
    const [lookups, voids] = await countSpfLookups(domain, q);
    r.SPF = (qual === "-" || qual === "~") && lookups <= 10 && voids <= 2;
    if (qual === "+" || qual === "?") note.push("SPF " + qual + "all (permissive)");
    else if (qual === null) note.push("SPF no 'all' mechanism");
    if (lookups > 10) note.push("SPF " + lookups + " lookups");
  } else note.push("no SPF");

  const [dkimState, dkimNote] = await dkimLookup(domain, q);
  r.DKIM = dkimState;
  if (dkimState !== "good") note.push(dkimNote);

  const dmarc = await firstTxt("_dmarc." + domain, "v=dmarc1", q);
  if (dmarc) {
    r.DMARC = true;
    const m = dmarc.match(/p=\s*(\w+)/);
    const p = m ? m[1].toLowerCase() : "";
    r.DMARC_enforced = p === "quarantine" || p === "reject";
    r.DMARC_rua = dmarc.replace(/ /g, "").includes("rua=");
    if (p === "none") note.push("DMARC p=none");
    if (!r.DMARC_rua) note.push("no rua");
  } else note.push("no DMARC");

  const mx = await q(domain, "MX");
  const nullMx = isNullMx(mx);
  if (nullMx) {
    r.MTA_STS = null;
    r.TLS_RPT = null;
    r.DANE = null;
  } else {
    r.MTA_STS = !!(await firstTxt("_mta-sts." + domain, "v=stsv1", q));
    r.TLS_RPT = !!(await firstTxt("_smtp._tls." + domain, "v=tlsrptv1", q));
  }
  const realMx = realMxRows(mx);
  if (realMx.length && !nullMx) {
    const host = realMx.sort((a, b) => {
      const pa = a.split(/\s+/)[0], pb = b.split(/\s+/)[0];
      return (/^\d+$/.test(pa) ? +pa : 99) - (/^\d+$/.test(pb) ? +pb : 99);
    })[0].split(/\s+/).pop().replace(/\.+$/, "");
    r.DANE = !!(await q("_25._tcp." + host, "TLSA")).length;
  }
  const provs = new Set((await mxProviders(domain, q)).map((x) => x[2]));
  if (provs.size > 1) note.push("mixed MX (" + provs.size + " providers)");
  r.BIMI = !!(await firstTxt("default._bimi." + domain, "v=bimi1", q));

  const bool = ["SPF", "DMARC", "DMARC_enforced", "DMARC_rua", "MTA_STS", "TLS_RPT", "DANE", "BIMI"];
  let gap = bool.filter((b) => r[b] === false).length;
  if (r.DKIM === "weak") gap += 1;
  return { ...r, gap, note: note.length ? note.join("; ") : "clean" };
}

export function createAuditEngine({ dns, http, clock }) {
  const q = queryFromDns(dns);
  for (const name of ["mtaSts", "robots", "rdap"]) {
    if (!http || typeof http[name] !== "function") throw new TypeError("http." + name + " must be a function");
  }
  if (!clock || typeof clock.nowMs !== "function") throw new TypeError("clock.nowMs must be a function");
  return Object.freeze({
    auditDomain: (domain) => auditDomainWithPorts(domain, q, http, clock, dns),
    buckets: (domain) => bucketsWithQuery(domain, q),
  });
}

function compatibilityAdapters(q) {
  if (!q) return createDefaultAdapters();
  return {
    dns: dnsFromLegacyQuery(q),
    // A supplied legacy resolver denotes a fixture/offline caller. Purpose-specific
    // ports may be attached for deterministic success-path tests; otherwise HTTP is
    // unavailable, matching the historical fail-soft result without ambient I/O.
    http: q.http || UNAVAILABLE_HTTP,
    clock: q.clock || UNUSED_CLOCK,
  };
}

export async function auditDomain(domain, q) {
  return createAuditEngine(compatibilityAdapters(q)).auditDomain(domain);
}

export async function buckets(domain, q) {
  return createAuditEngine(compatibilityAdapters(q)).buckets(domain);
}
