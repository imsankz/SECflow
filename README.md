# secflow

Zero-cost security scanning for AI-driven repositories.

**Engines:** [gitleaks](https://github.com/gitleaks/gitleaks) (secrets) · [trivy](https://github.com/aquasecurity/trivy) (dependencies/containers) · `npm audit` · custom regex rules (Stripe, GitHub, OpenAI, AWS, JWT, private keys, Supabase)

**Output:** unified `report.md` + `report.json` — severity-tagged, file:line locations, **AI-ready fix briefs** you paste straight into Hermes, Claude Code, or any coding agent.

## Why

AI coding agents ship code fast — and they also miss secrets, vulnerable dependencies, and auth bugs. Paid scanners (Rafter, Snyk, Semgrep) wrap the same free engines and charge you for the AI-fix layer. secflow gives you the engines for free and lets the agent you *already use* be the fix layer.

## Install

```bash
brew install gitleaks                                  # secrets (required)
brew install aquasecurity/trivy/trivy                  # optional: dep/container vulns
npm link                                               # or: npm i -g .
```

## Usage

```bash
secflow scan                  # scan current dir → .secflow/report.md + report.json
secflow scan --json           # machine-readable
secflow scan --skip trivy     # skip engines you don't have
secflow report                # print the AI-ready brief
secflow init                  # write secflow.yml config
secflow install-hook          # pre-commit gitleaks hook
secflow ci                    # CI mode (exit 1 if critical/high present)
```

### Example report

```markdown
## Critical (2)
| # | Engine | Rule | File:Line | Match |
|---|--------|------|-----------|-------|
| 1 | regex | `stripe-live-secret` | `src/config.js:1` | `sk_live_…(redacted)` |

### AI-ready fixes
**stripe-live-secret** — src/config.js:1
- custom rule 'stripe-live-secret' matched
- `secflow fix src/config.js:1`
```

## GitHub Action

Add `.github/workflows/security.yml` to any repo:

```yaml
name: Security scan (secflow)
on: [push, pull_request]
jobs:
  secflow:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      # Fast native gitleaks gate (zero config, blocks push)
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      # Full secflow report (gitleaks + npm audit + regex, AI-ready brief)
      - uses: imsankz/secflow@main
        with:
          fail-on: critical,high
```

## Config (`secflow.yml`)

```yaml
engines:
  gitleaks: true
  trivy: false        # enable when trivy installed
  npmAudit: true
  regex: true
failOn: critical, high
excludePaths: node_modules, .git, dist, build, .next, vendor
customRegex:
  stripe-live-secret: { pattern: 'sk_live_[A-Za-z0-9_]{24,}', severity: critical }
```

Run `secflow init` to generate this in any repo.

## For AI coding agents

Working in this repo (Claude Code, Codex, Hermes, Cursor — read `llms.txt` for the full brief):

- **Single-file CLI, zero npm deps** — `bin/secflow.js` only, Node 18+.
- **Test fixtures use `REPLACEME` tokens** (deliberately invalid) so GitHub push protection passes. Never add real-looking fake secrets — GitHub's scanner blocks the push.
- **`.gitleaks.toml` allowlist stays regex-based** — GitHub scans that file too.
- **`excludePaths` entries are slash-tolerant** (trailing `/` normalized at scan time).
- **After changes:** `node tests/run.js` (8/8) + `node bin/secflow.js scan --skip trivy` must report 0 findings.
- **Report format is the contract** for the AI fix layer — don't change fields without updating consumers.

## Roadmap

- [ ] `secflow fix` command (apply AI fixes with review)
- [ ] SARIF output for GitHub code scanning integration
- [ ] `--baseline` to ignore known findings
- [ ] Version tag `v0.1.0` for action pinning

## License

MIT — free forever, no credits, no SaaS.
