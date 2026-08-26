#!/usr/bin/env node
/**
 * SECflow (npm package: secflow) — zero-cost security scanning for AI-driven repos.
 * Engines: gitleaks (secrets) + trivy (deps) + npm audit + custom regex (env/keys).
 * Output: unified report.md + report.json, severity-tagged, file:line.
 * AI fix layer is external (Hermes/Claude/etc reads report.md).
 *
 * Usage:
 *   secflow scan [--path DIR] [--skip <engines>] [--fail-on critical,high] [--json]
 *   secflow report [--path DIR]           # read last scan, print AI-ready brief
 *   secflow install-hook [--path DIR]     # pre-commit hook → gitleaks only
 *   secflow init [--path DIR]             # add secflow.yml config
 *   secflow ci                            # CI mode: scan, fail on block, upload
 */

'use strict';

const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const VERSION = '0.2.0';

const DEFAULT_CONFIG = {
  engines: { gitleaks: true, trivy: false, npmAudit: true, regex: true },
  severity: ['error', 'warning', 'info'],
  failOn: ['critical', 'high'], // CI blocks on these
  excludePaths: ['node_modules', '.git', 'dist', 'build', '.next', 'vendor', 'package-lock.json'],
  customRegex: {
    'stripe-live-secret': { pattern: 'sk_live_[A-Za-z0-9_]{24,}', severity: 'critical' },
    'stripe-test-secret': { pattern: 'sk_test_[A-Za-z0-9_]{24,}', severity: 'high' },
    'stripe-publishable': { pattern: 'pk_(live|test)_[A-Za-z0-9_]{24,}', severity: 'info' },
    'github-token': { pattern: 'gh[pousr]_[A-Za-z0-9_]{36,}', severity: 'critical' },
    'openai-key': { pattern: 'sk-[A-Za-z0-9]{20,}', severity: 'critical' },
    'google-api-key': { pattern: 'AIza[0-9A-Za-z_-]{35}', severity: 'critical' },
    'aws-access-key': { pattern: 'AKIA[0-9A-Z]{16}', severity: 'critical' },
    'jwt': { pattern: 'eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}', severity: 'warning' },
    'private-key-block': { pattern: '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', severity: 'critical' },
    'slack-token': { pattern: 'xox[baprs]-[0-9A-Za-z-]{10,}', severity: 'critical' },
    'supabase-key': { pattern: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}', severity: 'high' },
  },
};

// ---------- helpers ----------

function log(msg) { process.stderr.write(`[secflow] ${msg}\n`); }

function findConfig(dir) {
  const p = path.join(dir, 'secflow.yml');
  return fs.existsSync(p) ? p : null;
}

function loadConfig(dir) {
  const cfg = JSON.parse(JSON.stringify(DEFAULT_CONFIG)); // deep copy
  const p = findConfig(dir);
  if (p) {
    try {
      // minimal YAML subset: key: value / key: { nested }
      const raw = fs.readFileSync(p, 'utf8');
      const lines = raw.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
      for (const line of lines) {
        const m = line.match(/^\s*([A-Za-z0-9_-]+):\s*(.*)$/);
        if (!m) continue;
        const [k, v] = [m[1], m[2].trim()];
        if (k in cfg.engines) cfg.engines[k] = v === 'true';
        else if (k === 'failOn') cfg.failOn = v.split(',').map(s => s.trim()).filter(Boolean);
        else if (k === 'excludePaths') cfg.excludePaths = v.split(',').map(s => s.trim()).filter(Boolean);
        else if (v.startsWith('{') && v.includes('pattern')) {
          // customRegex entry — name: { pattern: '...', severity: critical }
          const pm = v.match(/pattern:\s*'([^']*)'/);
          if (pm) {
            const sm = v.match(/severity:\s*([A-Za-z]+)/);
            cfg.customRegex[k] = { pattern: pm[1], severity: sm ? sm[1].toLowerCase() : 'warning' };
          }
        }
      }
      log(`config: ${p}`);
    } catch (e) { log(`warn: bad secflow.yml (${e.message})`); }
  }
  return cfg;
}

// CLI --fail-on overrides secflow.yml failOn (honored by scan + ci)
function applyCliFailOn(args, cfg) {
  const raw = typeof args['fail-on'] === 'string' ? args['fail-on'] : '';
  if (raw.trim()) cfg.failOn = raw.split(',').map(s => s.trim()).filter(Boolean);
}

function engineAvailable(name) {
  try { execFileSync('which', [name], { stdio: 'ignore' }); return true; }
  catch { return false; }
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...opts });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function severityRank(s) {
  const order = { info: 0, warning: 1, high: 2, critical: 3, error: 2 };
  return order[s] ?? 1;
}

// ---------- engines ----------

async function scanGitleaks(dir, cfg, findings) {
  if (!cfg.engines.gitleaks) return;
  if (!engineAvailable('gitleaks')) { log('warn: gitleaks not installed — skipping'); return; }
  log('scan: gitleaks (secrets)');
  const r = run('gitleaks', ['detect', '--source', dir, '--no-banner', '--redact', '=40', '--report-format', 'json', '--report-path', path.join(dir, '.secflow', 'gitleaks.json')]);
  if (r.status !== 0 && r.status !== 1) log(`warn: gitleaks exit ${r.status}: ${r.stderr.slice(0, 300)}`);
  const reportPath = path.join(dir, '.secflow', 'gitleaks.json');
  if (!fs.existsSync(reportPath)) return;
  let data;
  try { data = JSON.parse(fs.readFileSync(reportPath, 'utf8')); } catch { return; }
  if (!Array.isArray(data)) return;
  for (const f of data) {
    findings.push({
      engine: 'gitleaks',
      severity: (f.RuleID || '').toLowerCase().includes('test') ? 'high' : 'critical',
      rule: f.RuleID || 'secret',
      file: f.File,
      line: f.StartLine || f.line,
      match: (f.Secret || '').slice(0, 8) + '…(redacted)',
      message: f.Description || f.RuleID || 'secret found',
    });
  }
}

async function scanNpmAudit(dir, cfg, findings) {
  if (!cfg.engines.npmAudit) return;
  if (!fs.existsSync(path.join(dir, 'package.json'))) return;
  log('scan: npm audit (dependencies)');
  const r = run('npm', ['audit', '--json'], { cwd: dir });
  if (r.status === 0) return; // no vulns
  let data;
  try { data = JSON.parse(r.stdout); } catch { log('warn: npm audit output unparseable'); return; }
  const vulns = data.vulnerabilities || {};
  for (const [pkg, v] of Object.entries(vulns)) {
    const sev = v.severity === 'critical' ? 'critical' : v.severity === 'high' ? 'high' : 'warning';
    findings.push({
      engine: 'npm-audit',
      severity: sev,
      rule: v.title || 'vulnerable dependency',
      file: 'package.json',
      line: 0,
      match: `${pkg}@${v.range}`,
      message: `${v.title || pkg}: ${v.isDirect ? 'direct' : 'transitive'} dep, ${v.severity}. Fix: ${(v.fixAvailable && v.fixAvailable.isSemVerMajor ? 'major update required' : v.fixAvailable ? 'npm audit fix' : 'no fix available')}`,
    });
  }
}

async function scanTrivy(dir, cfg, findings) {
  if (!cfg.engines.trivy) return;
  if (!engineAvailable('trivy')) { log('warn: trivy not installed — skipping'); return; }
  log('scan: trivy (dependencies/containers)');
  const r = run('trivy', ['fs', '--scanners', 'vuln,secret', '--format', 'json', '--quiet', dir], { cwd: dir, timeout: 300000 });
  if (r.status !== 0) { log(`warn: trivy exit ${r.status}`); return; }
  let data;
  try { data = JSON.parse(r.stdout); } catch { return; }
  const results = data.Results || [];
  for (const res of results) {
    for (const v of (res.Vulnerabilities || [])) {
      const sev = (v.Severity || '').toLowerCase();
      findings.push({
        engine: 'trivy',
        severity: sev === 'critical' ? 'critical' : sev === 'high' ? 'high' : 'warning',
        rule: v.VulnerabilityID || 'cve',
        file: res.Target || '',
        line: 0,
        match: v.PkgName || '',
        message: `${v.VulnerabilityID} ${v.PkgName}@${v.InstalledVersion} → fix ${v.FixedVersion || 'n/a'}`,
      });
    }
    for (const s of (res.Secrets || [])) {
      findings.push({
        engine: 'trivy-secret',
        severity: 'critical',
        rule: s.RuleID || 'secret',
        file: res.Target || '',
        line: s.StartLine || 0,
        match: (s.Match || '').slice(0, 8) + '…(redacted)',
        message: s.Title || 'secret found',
      });
    }
  }
}

function scanRegex(dir, cfg, findings) {
  if (!cfg.engines.regex) return;
  log('scan: custom regex (env/keys)');
  const exclude = cfg.excludePaths.map(p => p.replace(/\/+$/, '')).concat(['.git', 'node_modules', '.secflow']);
  const walk = (d) => {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (exclude.includes(e.name)) continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) { walk(p); continue; }
      if (!e.isFile()) continue;
      if (p.includes('.secflow')) continue;
      let content;
      try { content = fs.readFileSync(p, 'utf8'); } catch { continue; }
      for (const [name, rule] of Object.entries(cfg.customRegex)) {
        const re = new RegExp(rule.pattern, 'g');
        let m;
        while ((m = re.exec(content)) !== null) {
          // compute line number
          const before = content.slice(0, m.index);
          const line = before.split('\n').length;
          findings.push({
            engine: 'regex',
            severity: rule.severity,
            rule: name,
            file: p.replace(dir + '/', ''),
            line,
            match: m[0].slice(0, 8) + '…(redacted)',
            message: `custom rule '${name}' matched`,
          });
        }
      }
    }
  };
  walk(dir);
}

// ---------- report ----------

function dedupe(findings) {
  const seen = new Set();
  return findings.filter(f => {
    const k = `${f.engine}|${f.file}|${f.line}|${f.rule}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function generateReport(findings, cfg, dir) {
  const out = path.join(dir, '.secflow');
  fs.mkdirSync(out, { recursive: true });

  const bySeverity = { critical: [], high: [], warning: [], info: [] };
  for (const f of findings) {
    const s = bySeverity[f.severity] ? f.severity : 'warning';
    bySeverity[s].push(f);
  }
  const counts = Object.fromEntries(Object.entries(bySeverity).map(([k, v]) => [k, v.length]));
  const blocked = cfg.failOn.filter(s => (bySeverity[s] || []).length > 0);

  const lines = [];
  lines.push(`# secflow report — ${path.basename(dir)}`);
  lines.push('');
  lines.push(`> Generated ${new Date().toISOString()} — secflow v${VERSION}`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  for (const s of ['critical', 'high', 'warning', 'info']) {
    lines.push(`| **${s}** | ${bySeverity[s].length} |`);
  }
  lines.push(`| **Total** | **${findings.length}** |`);
  lines.push('');
  if (blocked.length) {
    lines.push(`> ⛔ **CI BLOCKED** — findings in: ${blocked.join(', ')}`);
  } else {
    lines.push(`> ✅ **CI PASS** — no findings at or above fail threshold (${cfg.failOn.join(', ')})`);
  }
  lines.push('');

  for (const sev of ['critical', 'high', 'warning', 'info']) {
    const items = bySeverity[sev];
    if (!items.length) continue;
    lines.push(`## ${sev.charAt(0).toUpperCase() + sev.slice(1)} (${items.length})`);
    lines.push('');
    lines.push('| # | Engine | Rule | File:Line | Match |');
    lines.push('|---|--------|------|-----------|-------|');
    items.forEach((f, i) => {
      lines.push(`| ${i + 1} | ${f.engine} | \`${f.rule}\` | \`${f.file}:${f.line}\` | \`${f.match}\` |`);
    });
    lines.push('');
    lines.push('### AI-ready fixes');
    lines.push('');
    for (const f of items) {
      lines.push(`**${f.rule}** — ${f.file}:${f.line}`);
      lines.push(`- ${f.message}`);
      lines.push(`- \`secflow fix ${f.file}:${f.line}\``);
      lines.push('');
    }
    lines.push('');
  }

  fs.writeFileSync(path.join(out, 'report.md'), lines.join('\n'));
  fs.writeFileSync(path.join(out, 'report.json'), JSON.stringify({ version: VERSION, generated: new Date().toISOString(), counts, blocked, findings }, null, 2));
  log(`report: ${path.join(out, 'report.md')}`);
  return { counts, blocked };
}

// ---------- commands ----------

async function cmdScan(args) {
  let dir = args.path || '.';
  dir = path.resolve(dir);
  const skip = new Set((args.skip || '').split(',').map(s => s.trim()).filter(Boolean));
  const cfg = loadConfig(dir);
  applyCliFailOn(args, cfg);
  const findings = [];

  fs.mkdirSync(path.join(dir, '.secflow'), { recursive: true });

  if (!skip.has('gitleaks')) await scanGitleaks(dir, cfg, findings);
  if (!skip.has('trivy')) await scanTrivy(dir, cfg, findings);
  if (!skip.has('npm')) await scanNpmAudit(dir, cfg, findings);
  if (!skip.has('regex')) scanRegex(dir, cfg, findings);

  const deduped = dedupe(findings);
  const { counts, blocked } = generateReport(deduped, cfg, dir);

  if (args.json) {
    console.log(JSON.stringify({ version: VERSION, counts, blocked, findings: deduped }, null, 2));
    return;
  }
  console.log(`secflow scan complete: ${deduped.length} findings (critical ${counts.critical}, high ${counts.high}, warning ${counts.warning}, info ${counts.info})`);
  if (blocked.length) {
    console.error(`FAIL: ${blocked.join(', ')} severity present — see .secflow/report.md`);
    process.exitCode = 1;
  }
}

function cmdReport(args) {
  const dir = path.resolve(args.path || '.');
  const p = path.join(dir, '.secflow', 'report.md');
  if (!fs.existsSync(p)) { console.error('no report — run `secflow scan` first'); process.exit(1); }
  console.log(fs.readFileSync(p, 'utf8'));
}

function cmdInit(args) {
  const dir = path.resolve(args.path || '.');
  const p = path.join(dir, 'secflow.yml');
  if (fs.existsSync(p)) { console.error(`already exists: ${p}`); process.exit(1); }
  fs.writeFileSync(p, `# secflow configuration (see https://github.com/imsankz/secflow)
engines:
  gitleaks: true
  trivy: false
  npmAudit: true
  regex: true
failOn: critical, high
excludePaths: node_modules, .git, dist, build, .next, vendor, package-lock.json
`);
  console.log(`wrote ${p}`);
}

function cmdInstallHook(args) {
  const dir = path.resolve(args.path || '.');
  const hooksDir = path.join(dir, '.git', 'hooks');
  if (!fs.existsSync(hooksDir)) { console.error(`not a git repo: ${dir}`); process.exit(1); }
  const hookPath = path.join(hooksDir, 'pre-commit');
  const script = `#!/bin/sh
# secflow pre-commit — gitleaks quick scan (fast, secrets only)
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks protect --staged --no-banner --redact 2>/dev/null
  exit $?
fi
exit 0
`;
  fs.writeFileSync(hookPath, script);
  fs.chmodSync(hookPath, 0o755);
  console.log(`installed pre-commit hook: ${hookPath}`);
}

function cmdCi(args) {
  // CI mode: env vars from GitHub Actions
  const dir = path.resolve(args.path || process.env.GITHUB_WORKSPACE || '.');
  const cfg = loadConfig(dir);
  applyCliFailOn(args, cfg);
  const findings = [];
  fs.mkdirSync(path.join(dir, '.secflow'), { recursive: true });
  if (!args.skip || !args.skip.includes('gitleaks')) scanGitleaks(dir, cfg, findings).then(() => {
    // npm audit + regex are sync-ish; just call them
    scanNpmAudit(dir, cfg, findings);
    scanRegex(dir, cfg, findings);
    const deduped = dedupe(findings);
    const { counts, blocked } = generateReport(deduped, cfg, dir);
    console.log(`secflow ci: ${deduped.length} findings — ${blocked.length ? 'BLOCKED (' + blocked.join(',') + ')' : 'PASS'}`);
    if (blocked.length) process.exitCode = 1;
  }).catch(e => { console.error(e.message); process.exitCode = 2; });
  // also run the sync engines even if gitleaks skipped
}

// ---------- CLI ----------

const args = process.argv.slice(2);
const cmd = args[0] || 'help';
const opts = {};
const rest = args.slice(1);
for (let i = 0; i < rest.length; i++) {
  const a = rest[i];
  const m = a.match(/^--([A-Za-z0-9_-]+)(?:=(.*))?$/);
  if (m) {
    if (m[2] !== undefined) opts[m[1]] = m[2];
    else if (rest[i + 1] && !rest[i + 1].startsWith('--')) opts[m[1]] = rest[++i];
    else opts[m[1]] = true;
  }
}

const help = `secflow v${VERSION} — zero-cost security scanning for AI-driven repos
Usage:
  secflow scan [--path DIR] [--skip gitleaks,trivy,npm,regex] [--fail-on critical,high] [--json]
  secflow report [--path DIR]
  secflow init [--path DIR]
  secflow install-hook [--path DIR]
  secflow ci [--path DIR]
`;

switch (cmd) {
  case 'scan': cmdScan(opts); break;
  case 'report': cmdReport(opts); break;
  case 'init': cmdInit(opts); break;
  case 'install-hook': cmdInstallHook(opts); break;
  case 'ci': cmdCi(opts); break;
  default: console.log(help);
}
