# Amino Email Deliverability Audit — GitHub Action

**Fail your CI build if your sending domain's SPF / DMARC / DKIM (and more) regresses.**

[![Email deliverability audit](https://img.shields.io/badge/email%20deliverability-audited%20by%20Amino-orange)](https://hireamino.com/audit)

Audit any sending domain's email-authentication posture directly in CI — SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DANE, BIMI, DNSSEC, CAA, MX hygiene, reverse DNS and more — and (optionally) break the build when something regresses. **Read-only. Zero secrets. Runs on any runner OS.**

## What it does

On every push or pull request, this action runs the same audit engine that powers [hireamino.com/audit](https://hireamino.com/audit) against the domain(s) you list. It:

- Inspects **public DNS** (over DNS-over-HTTPS) for your email-auth records.
- Produces a **GitHub job summary** with a verdict, severity counts, and a table of findings + the exact fix for each.
- Sets **outputs** you can branch on.
- Optionally **comments the summary on the pull request**.
- **Fails the build** only if you ask it to (via `fail-on`) — the default is non-breaking.

## Why

Email deliverability silently rots. An SPF include that stops resolving, a DMARC record someone flipped back to `p=none`, a DKIM key downgraded to RSA-1024, an MTA-STS policy that no longer covers your MX — none of these throw an error, they just quietly tank your inbox placement weeks later. This action turns those regressions into a visible CI signal **before** they cost you deliverability.

## Quickstart

```yaml
name: Email deliverability audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/amino-audit-action@v1
        with:
          domains: example.com
          # Default is advisory (report-only). Flip to enforce once you trust it:
          # fail-on: high
```

Audit several domains and comment on PRs:

```yaml
jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # required ONLY for comment-on-pr
    steps:
      - uses: your-org/amino-audit-action@v1
        with:
          domains: |
            example.com
            mail.example.com
          fail-on: high
          comment-on-pr: true
          github-token: ${{ github.token }}
```

> **Note:** `comment-on-pr` needs `pull-requests: write` (shown above) — grant it only on the jobs that use the feature. Pull requests opened from **forks** receive a read-only token, so the comment is skipped there (the build still runs and the job summary is always written). The default token is otherwise read-only.

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `domains` | yes | — | One or more sending domains to audit. Comma-, space-, or newline-separated. Capped at 50. |
| `fail-on` | no | `advisory` | Severity threshold that fails the build: `advisory` \| `low` \| `medium` \| `high` \| `critical`. `advisory` never fails. |
| `comment-on-pr` | no | `false` | If `true` and the event is a `pull_request`, post the summary as a PR comment (needs `github-token`). Fails soft. |
| `github-token` | no | `${{ github.token }}` | Token used **only** to post the PR comment. |

## Outputs

| Output | Description |
| --- | --- |
| `passed` | `true` if the audit passed the `fail-on` threshold, else `false`. |
| `worst-severity` | Worst severity across all domains (`critical`/`high`/`medium`/`low`), or `none`. |
| `summary` | Compact JSON array of per-domain severity counts. |

## `fail-on` explained

Severity order, worst-first: **critical > high > medium > low**. The build fails if **any** finding is **at-or-worse-than** the threshold.

| `fail-on` | Build fails when… |
| --- | --- |
| `advisory` _(default)_ | **Never.** Report-only — your build is never broken. Safe for first-time adopters. |
| `low` | Any finding exists (low or worse). |
| `medium` | Any medium, high, or critical finding. |
| `high` | Any high or critical finding. |
| `critical` | Only on a critical finding. |

Start with `advisory` to see what the audit reports with zero risk, then ratchet up to `high` (a good default for enforcement) once you've cleaned house.

## Example job summary

The action writes a rich summary to the run's **Summary** tab:

> ## Amino Email Deliverability Audit
> ✅ **PASS** — `fail-on: advisory`. Advisory mode: never fails the build (worst seen: medium).
>
> ### `example.com` — ⚠️ minor gaps
> **critical 0 · high 0 · medium 1 · low 4 · pass 4** · primary MX: `mx.example.com`
>
> | Severity | Area | Issue | Fix |
> | --- | --- | --- | --- |
> | 🟨 medium | MTA-STS | No MTA-STS policy | Publish an MTA-STS policy |
> | ⬜ low | DKIM | DKIM not found at common/provider selectors | Confirm or enable DKIM signing |

_(screenshot placeholder — see the live render in your Actions → Summary tab)_

## Privacy

**Read-only. No secrets. Nothing leaves your runner except public DNS lookups** (DNS-over-HTTPS to `cloudflare-dns.com`) and a small number of public HTTPS fetches the engine makes for `mta-sts.txt` / `robots.txt` / RDAP — all of which are guarded against pointing at private/internal addresses. The action never touches your DNS, never sends mail, and needs no credentials. The only token it ever uses is the optional `github-token`, used solely to post the PR comment you asked for.

## License

Apache-2.0 — © 2026 WBVP Enterprises Inc.

---

**Powered by [Amino](https://hireamino.com/audit)** — run the full audit at [hireamino.com/audit](https://hireamino.com/audit), then let Amino watch your domain and warn you the moment it drifts: [hireamino.com/warmup](https://hireamino.com/warmup).
