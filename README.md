<div align="center">

# SECflow

**Zero-cost security scanning for AI-driven repositories.**

npm package: [`secflow`](https://www.npmjs.com/package/secflow) · single-file CLI · zero dependencies · Node 18+

*Secrets, vulnerable dependencies, and custom rules in one scan — with an AI-ready fix brief your coding agent can act on immediately.*

</div>

---

**Engines**

| Engine | What it scans | Required? |
|---|---|---|
| [gitleaks](https://github.com/gitleaks/gitleaks) | committed secrets (800+ rule types) | recommended |
| [trivy](https://github.com/aquasecurity/trivy) | dependency & container CVEs, extra secrets | optional |
| `npm audit` | npm dependency vulnerabilities | auto (skipped without `package.json`) |
| custom regex | Stripe, GitHub, OpenAI, AWS, Google, Slack, JWT, private keys, Supabase + your own rules | built in |

**Output:** unified `.secflow/report.md` + `.secflow/report.json` — severity-tagged, `file:line` locations, redacted matches, **AI-ready fix briefs** you paste straight into Claude Code, Codex, Cursor, or Hermes.

## Why


AI coding agents ship code fast — and they also miss leaked secrets, vulnerable dependencies, and auth bugs. Paid scanners (Rafter $39–199, Snyk, Semgrep) wrap these same free engines and charge you extra for the "AI fix" layer. SECflow gives you the engines for free and lets the agent you *already use* be the fix layer.

## How it works

```
secflow scan          →  .secflow/report.md  →  paste brief into your agent  →  fixes
     free engines           human + AI readable              no SaaS, no credits

# After fixing, verify nothing regressed:
secflow verify        →  re-runs scan, compares to previous, reports NEW regressions + fixed

# Accept known-good findings so future scans only flag NEW issues:
secflow baseline      →  snapshot current findings as accepted
secflow scan --baseline  →  subtract accepted findings from results
```

## Install

**npm** (global binary):

```bash
npm install -g secflow
```

**pnpm**:

```bash
pnpm add -g secflow
# if the secflow command isn't found afterwards:
pnpm setup && source ~/.zshrc   # adds PNPM_HOME to your shell (one-time)
```

**One-off, nothing installed**:

```bash
npx secflow@latest scan          # or: pnpm dlx secflow@latest scan
```

**From source**:

```bash
git clone https://github.com/imsankz/secflow && cd secflow
npm install -g .                 # or: pnpm add -g .
```

Then install the secret-scanning engine ([gitleaks](https://github.com/gitleaks/gitleaks#installation) — required for real coverage):

```bash
brew install gitleaks                          # macOS / Linux
# Windows: choco install gitleaks · scoop install gitleaks
# Linux: see gitleaks releases (single binary)

brew install aquasecurity/trivy/trivy         # optional: dep/container CVEs
```

> Without gitleaks, SECflow still runs `npm audit` + its regex engine and warns that gitleaks was skipped — so a plain `npx secflow scan` never hard-fails on a fresh machine.

Verify:

```bash
secflow --help      # usage + version
secflow scan        # first run writes .secflow/report.md
```

## Usage

```bash
secflow scan                  # scan current dir → .secflow/report.md + report.json
secflow scan --json           # machine-readable summary on stdout
secflow scan --skip trivy     # skip engines you don't have (gitleaks,trivy,npm,regex)
secflow scan --fail-on high   # override which severities exit non-zero
secflow scan --baseline       # subtract accepted findings (from `secflow baseline`)
secflow report                # print the AI-ready brief from the last scan
secflow verify                # re-attack: re-run scan, compare to previous, report regressions
secflow baseline              # snapshot current findings as accepted/known-good
secflow baseline --clear      # wipe baseline, start fresh
secflow init                  # write a secflow.yml config to the current repo
secflow install-hook          # pre-commit hook: gitleaks on staged files
secflow ci                    # CI mode — exits 1 when fail-on severities are present
```

Exit codes: `0` clean · `1` findings at/above threshold (`critical,high` by default) · `2` command/internal error (e.g. `secflow report` before any scan).

### Example report (`.secflow/report.md`)

```markdown
## Critical (1)
| # | Engine | Rule | File:Line | Match |
|---|--------|------|-----------|-------|
| 1 | regex | `stripe-live-secret` | `src/config.js:1` | `sk_live_…(redacted)` |

### AI-ready fixes
**stripe-live-secret** — src/config.js:1
- custom rule 'stripe-live-secret' matched
- Prompt for your agent: "Fix the SECflow finding 'stripe-live-secret' at src/config.js:1 — custom rule 'stripe-live-secret' matched. Redact and rotate the secret, then re-run secflow scan."
```

Paste that section into your coding agent with *"fix all of these"* — every entry carries engine, rule id, exact location, and severity.

## Use it as a GitHub Action

Add `.github/workflows/security.yml` to any repo:

```yaml
name: Security scan (SECflow)
on: [push, pull_request]
jobs:
  secflow:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      # Fast native gitleaks gate (zero config)
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      # Full SECflow report → uploads .secflow/ artifact, fails on critical/high
      - uses: imsankz/secflow@v0.4.1   # pin to the latest release tag; see Releases
        with:
          fail-on: critical,high   # or: skip: trivy · path: packages/api
```

A ready-to-copy version lives at [`examples/security.yml`](examples/security.yml). The composite action definition is [`action.yml`](action.yml).

## Configuration (`secflow.yml`)

Run `secflow init`, or drop this in your repo root:

```yaml
engines:
  gitleaks: true       # requires gitleaks binary; silently skipped if missing
  trivy: false         # enable once trivy is installed
  npmAudit: true       # skipped automatically when there's no package.json
  regex: true
failOn: critical, high            # severities that make CI exit 1
excludePaths: node_modules, .git, dist, build, .next, vendor, package-lock.json
customRegex:
  my-internal-token: { pattern: 'MYCOMPANY_[A-Za-z0-9]{32,}', severity: critical }
```

Notes:

- `excludePaths` entries are slash-tolerant (`tests/` matches dir `tests`) and always implicitly include `.git`, `node_modules`, `.secflow`.
- `--fail-on critical` on the CLI overrides `failOn:` from the file.
- Matches are always redacted: regex-engine matches show the first 8 characters; gitleaks matches are fully replaced with `REDACTED` by the engine itself before secflow ever sees them.

## For AI coding agents working in this repo

Read [`llms.txt`](llms.txt) (short) or [`llms-full.txt`](llms-full.txt) for the full brief. Ground rules:

- **Single-file CLI, zero npm deps** — everything lives in [`bin/secflow.js`](bin/secflow.js), Node 18+ stdlib only.
- **Test fixtures use deliberately-invalid `REPLACEME` tokens** so GitHub push protection passes. Never commit real-looking fake secrets.
- After changes: `npm test` must pass **25/25**, and self-scan must be clean: `node bin/secflow.js scan --skip trivy`.
- The report format is the contract for the AI fix layer — don't change fields without updating consumers.
- `secflow verify` re-runs the scan pipeline and compares against the previous report — use it to confirm fixes landed and catch regressions.
- `secflow baseline` snapshots accepted findings into `.secflow/baseline.json`; `secflow scan --baseline` subtracts them from results.

## Roadmap

- [ ] `secflow fix <file:line>` — hand the finding to your agent and apply the patch with review
- [ ] SARIF output for GitHub code-scanning integration
- [ ] `--baseline` — ignore previously accepted findings
- [x] Installable from npm/pnpm as `secflow`

## Related: the *flow* series

SECflow is part of a trio of zero-cost CLI tools — all MIT, all npm-published, all built on the same idea (free engines + your own AI agent as the smart layer):

| Tool | Job | Repo |
|---|---|---|
| **SECflow** | Security scanning for AI-driven repos | github.com/imsankz/SECflow |
| **[SeoFlow](https://github.com/imsankz/seoflow)** | AI-powered SEO pipeline (audit, internal links, content gen, GSC) | github.com/imsankz/seoflow |
| **[BacklinkFlow](https://github.com/imsankz/backlinkflow)** | Backlink & directory submission automation (1,123 directories, Playwright, $0) | github.com/imsankz/backlinkflow |

## License

[MIT](LICENSE) — free forever, no credits, no SaaS.

---

## ☕ Support

SECflow is free forever. If it caught a leaked secret or saved you a Snyk bill, [buy me a coffee](https://ko-fi.com/chasingwhereabouts).
