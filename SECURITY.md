# Security Policy

## Reporting a vulnerability

If you find a security issue in `amino-audit-action`, please email
**admin@whiteboard.vc** with the details. Do not open a public issue for security reports.

We aim to acknowledge within a few business days and to ship a fix promptly for confirmed
issues. Coordinated disclosure is appreciated.

## What this Action does (and doesn't)

`amino-audit-action` is **read-only**. It inspects a domain's public DNS over DoH
(`cloudflare-dns.com`) and makes a few outbound HTTPS requests to assess email posture — to
the MTA-STS policy host and to RDAP (domain age/expiry) — then writes a job summary, sets
outputs, and optionally posts a scorecard as a comment on your own pull request. It never:

- writes or modifies DNS,
- sends email,
- requires or stores credentials or API keys (the optional `github-token` is used only to
  post the PR comment and stays within your GitHub),
- writes to any file outside the runner's workspace.

## Hardening in place

- **PR-comment output is defanged** — DNS-derived values (primary MX, finding titles) are
  attacker-controllable by the audited domain's owner, and the PR comment is posted under a
  token. Every value rendered into the summary/comment is escaped at the rendering boundary
  (`mdCell` backslash-escapes all CommonMark-active punctuation and strips control/zero-width
  characters; code-span values strip backticks) so no DNS value can smuggle active markdown —
  image beacons, `@mentions`/`#refs`, link/emphasis breakout, or table-structure injection.
- **Least-privilege token** — the PR comment needs only `pull-requests: write`; the README
  documents the minimal permission block and the fork-PR token caveat. Comment failures fail
  soft and never break the build, and never log the token.
- **SSRF guard on outbound fetches** — the MTA-STS policy host must resolve to a public IP
  before it is fetched (fail-closed on private/loopback/link-local/reserved/metadata
  addresses); the fetch uses a short timeout, a response-size cap, and does not follow
  redirects off-host.
- **Untrusted content is data, not instructions** — DNS records and fetched policy files are
  treated as data; nothing they contain is executed or interpolated into a shell (the engine
  has no shell or subprocess — all DNS goes over `fetch`).
- **Zero runtime dependencies** — no third-party packages at runtime (nothing to compromise
  via the dependency chain). CI actions are pinned by commit SHA and the gitleaks binary is
  checksum-verified; every push and pull request runs secret scanning plus the local test and
  conformance harnesses (see `.github/workflows/security-gate.yml`).

## Scope

In scope: the Action's engine, entrypoint, `action.yml`, and workflows in this repository.
Out of scope: third-party services the Action queries (public DoH resolvers, RDAP, mailbox
providers), and issues requiring a compromised CI runner.
