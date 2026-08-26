# secflow

Zero-cost security scanning for AI-driven repositories.

Engines: **gitleaks** (secrets) · **trivy** (dependencies/containers) · **npm audit** · **custom regex rules** (env keys, Stripe, GitHub, OpenAI, JWT, private keys…)

Output: unified `report.md` + `report.json` with severity tags, file:line locations, and **AI-ready fix briefs** — paste them into Hermes, Claude, or any coding agent.

## Why

AI coding agents ship code fast. They also miss secrets, vulnerable dependencies, and auth bugs. Paid scanners (Rafter, Snyk, Semgrep) wrap the same free engines and charge for the AI-fix layer. secflow gives you the engines for free and leaves the fix layer to whatever agent you already use.

## Install

```bash
brew install gitleaks        # secrets (required)
brew install aquasecurity/trivy/trivy   # optional: dependency/container vulns
npm link                      # or: npm i -g .
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

## GitHub Action

Drop this in `.github/workflows/security.yml`:

```yaml
name: secflow
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: gitleaks/gitleaks-action@v2   # native, fast, zero-config
      - uses: imsankz/secflow@v0.1.0        # optional: full report
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
  stripe-live-secret: { pattern: 'sk_live_[A-Za-z0-9]{24,}', severity: critical }
```

## License

MIT
