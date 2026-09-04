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
 *   secflow verify [--path DIR] [--all]   # re-attack: confirm fixes landed
 *   secflow baseline [--path DIR] [--accept-all] [--clear]  # snapshot accepted findings
 *   secflow install-hook [--path DIR]     # pre-commit hook → gitleaks only
 *   secflow init [--path DIR]             # add secflow.yml config
 *   secflow ci                            # CI mode: scan, fail on block, upload
 *   secflow --version                     # print version
 */

'use strict';

const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const VERSION = (() => {
  try { return require('../package.json').version; } catch { return '0.0.0'; }
})();

const DEFAULT_CONFIG = {
  engines: { gitleaks: true, trivy: false, npmAudit: true, regex: true },
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
    'supabase-key': { pattern: '(?:eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9|eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9)\\.[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{10,}', severity: 'high' },
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
        const k = m[1];
        let v = m[2].trim();
        if (!v.startsWith('{')) {
          // strip trailing inline comments; unwrap surrounding quotes (a quoted scalar
          // may still carry a comment after the closing quote)
          const q = v.match(/^("([^"]*)"|'([^']*)')(?:\s+#.*)?$/);
          v = q ? (q[2] !== undefined ? q[2] : q[3]) : v.replace(/\s+#.*$/, '').trim();
        }
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

// CLI --skip parses to a Set; a bare --skip (no value) normalizes to "skip nothing"
function parseSkip(args) {
  const skipRaw = typeof args.skip === 'string' ? args.skip : '';
  return new Set(skipRaw.split(',').map(s => s.trim()).filter(Boolean));
}

function engineAvailable(name) {
  // probe the binary directly — `which` is absent on Windows shells
  try { execFileSync(name, ['--version'], { stdio: 'ignore', timeout: 60000 }); return true; }
  catch { return false; }
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 600000, ...opts });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

// ---------- engines ----------

async function scanGitleaks(dir, cfg, findings) {
  if (!cfg.engines.gitleaks) return;
  if (!engineAvailable('gitleaks')) { log('warn: gitleaks not installed — skipping'); return; }
  log('scan: gitleaks (secrets)');
  const relFile = (p) => (p && path.isAbsolute(p) ? path.relative(dir, p) : p || '');
  const reportPath = path.join(dir, '.secflow', 'gitleaks.json');
  const r = run('gitleaks', ['detect', '--source', dir, '--no-banner', '--redact=100', '--report-format', 'json', '--report-path', reportPath]);
  if (r.status !== 0 && r.status !== 1) log(`warn: gitleaks exit ${r.status}: ${r.stderr.slice(0, 300)}`);
  if (!fs.existsSync(reportPath)) return;
  let data;
  try { data = JSON.parse(fs.readFileSync(reportPath, 'utf8')); } catch { data = null; }
  fs.rmSync(reportPath, { force: true }); // never leave gitleaks' report on disk
  if (!Array.isArray(data)) return;
  for (const f of data) {
    findings.push({
      engine: 'gitleaks',
      severity: (f.RuleID || '').toLowerCase().includes('test') ? 'high' : 'critical',
      rule: f.RuleID || 'secret',
      file: relFile(f.File),
      line: f.StartLine || 0,
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
  const relFile = (p) => (p && path.isAbsolute(p) ? path.relative(dir, p) : p || '');
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
        file: relFile(res.Target),
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
        file: relFile(res.Target),
        line: s.StartLine || 0,
        match: (s.Match || '').slice(0, 8) + '…(redacted)',
        message: s.Title || 'secret found',
      });
    }
  }
}

const MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024;

function scanRegex(dir, cfg, findings) {
  if (!cfg.engines.regex) return;
  log('scan: custom regex (env/keys)');
  const exclude = cfg.excludePaths.map(p => p.replace(/\/+$/, '')).concat(['.git', 'node_modules', '.secflow']);
  const rel = (p) => path.relative(dir, p);
  const isExcluded = (p) => {
    const r = rel(p);
    // match full relative path OR any path segment (so `tests/` excludes dir `tests`, and
    // `skills/seo-google/references` excludes that whole subtree)
    const segs = r.split(path.sep);
    return exclude.includes(r) || segs.some(s => exclude.includes(s));
  };
  const compiled = [];
  for (const [name, rule] of Object.entries(cfg.customRegex)) {
    try { compiled.push({ name, severity: rule.severity, re: new RegExp(rule.pattern, 'g') }); }
    catch { log(`warn: rule '${name}' has invalid pattern — skipped`); }
  }
  const walk = (d) => {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (isExcluded(p)) continue;
      if (e.isDirectory()) { walk(p); continue; }
      if (!e.isFile()) continue;
      let size;
      try { size = fs.statSync(p).size; } catch { continue; }
      if (size > MAX_SCAN_FILE_BYTES) continue;
      let buf;
      try { buf = fs.readFileSync(p); } catch { continue; }
      if (buf.subarray(0, 8192).includes(0)) continue; // binary: NUL byte in first 8 KB
      const content = buf.toString('utf8');
      for (const { name, severity, re } of compiled) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(content)) !== null) {
          // compute line number
          const before = content.slice(0, m.index);
          const line = before.split('\n').length;
          findings.push({
            engine: 'regex',
            severity,
            rule: name,
            file: path.relative(dir, p),
            line,
            match: m[0].slice(0, 8) + '…(redacted)',
            message: `custom rule '${name}' matched`,
          });
          if (m[0].length === 0) re.lastIndex++; // zero-length match: advance or we loop forever
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

const cell = (s) => String(s).replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ');

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
      lines.push(`| ${i + 1} | ${cell(f.engine)} | \`${cell(f.rule)}\` | \`${cell(f.file)}:${f.line}\` | \`${cell(f.match)}\` |`);
    });
    lines.push('');
    lines.push('### AI-ready fixes');
    lines.push('');
    for (const f of items) {
      lines.push(`**${cell(f.rule)}** — ${cell(f.file)}:${f.line}`);
      lines.push(`- ${cell(f.message)}`);
      lines.push(`- Prompt for your agent: "Fix the SECflow finding '${cell(f.rule)}' at ${cell(f.file)}:${f.line} — ${cell(f.message)}. Redact and rotate the secret, then re-run secflow scan."`);
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

// shared engine pipeline used by both cmdScan and cmdCi; mkdirs .secflow first
async function runEngines(dir, cfg, skip, findings) {
  fs.mkdirSync(path.join(dir, '.secflow'), { recursive: true });
  if (!skip.has('gitleaks')) await scanGitleaks(dir, cfg, findings);
  if (!skip.has('trivy')) await scanTrivy(dir, cfg, findings);
  if (!skip.has('npm')) await scanNpmAudit(dir, cfg, findings);
  if (!skip.has('regex')) scanRegex(dir, cfg, findings);
}

async function cmdScan(args) {
  let dir = args.path || '.';
  dir = path.resolve(dir);
  const skip = parseSkip(args);
  const cfg = loadConfig(dir);
  applyCliFailOn(args, cfg);
  const findings = [];

  // Archive previous report before running new scan (so verify can compare)
  const reportDir = path.join(dir, '.secflow');
  const reportPath = path.join(reportDir, 'report.json');
  const prevPath = path.join(reportDir, 'report-prev.json');
  if (fs.existsSync(reportPath)) {
    try {
      fs.copyFileSync(reportPath, prevPath);
    } catch { /* ignore */ }
  }

  await runEngines(dir, cfg, skip, findings);

  const deduped = dedupe(findings);

  // If --baseline flag, subtract accepted findings from results
  let baseline = null;
  let newFindings = deduped;
  if (args.baseline) {
    const bl = loadBaseline(dir);
    baseline = bl.baseline;
    newFindings = deduped.filter(f => !bl.baselineKeys.has(`${f.engine}|${f.file}|${f.line}|${f.rule}`));
    if (baseline) {
      log(`baseline: subtracting ${baseline.total_accepted || 0} accepted findings`);
    }
  }

  const { counts, blocked } = generateReport(newFindings, cfg, dir);

  if (blocked.length) process.exitCode = 1;
  if (args.json) {
    console.log(JSON.stringify({ version: VERSION, counts, blocked, findings: newFindings }, null, 2));
    return;
  }
  if (baseline) {
    console.log(`secflow scan complete: ${newFindings.length} new findings (${deduped.length} total, ${deduped.length - newFindings.length} accepted via baseline)`);
  } else {
    console.log(`secflow scan complete: ${deduped.length} findings (critical ${counts.critical}, high ${counts.high}, warning ${counts.warning}, info ${counts.info})`);
  }
  if (blocked.length) console.error(`FAIL: ${blocked.join(', ')} severity present — see .secflow/report.md`);
}

// Load baseline findings (if any) to subtract from scan results.
// Returns { baseline: object|null, baselineKeys: Set }
function loadBaseline(dir) {
  const baselinePath = path.join(dir, '.secflow', 'baseline.json');
  if (!fs.existsSync(baselinePath)) return { baseline: null, baselineKeys: new Set() };
  try {
    const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
    const baselineKeys = new Set((baseline.accepted || []).map(f => `${f.engine}|${f.file}|${f.line}|${f.rule}`));
    return { baseline, baselineKeys };
  } catch {
    return { baseline: null, baselineKeys: new Set() };
  }
}

function cmdReport(args) {
  const dir = path.resolve(args.path || '.');
  const p = path.join(dir, '.secflow', 'report.md');
  if (!fs.existsSync(p)) { console.error('no report — run `secflow scan` first'); process.exit(2); }
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
  const marker = '# secflow pre-commit';
  if (fs.existsSync(hookPath) && !fs.readFileSync(hookPath, 'utf8').includes(marker)) {
    const bak = hookPath + '.secflow-bak';
    fs.copyFileSync(hookPath, bak);
    log(`existing non-secflow pre-commit hook backed up to ${bak}`);
  }
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

// CI mode: same engine pipeline as scan, single summary line on stdout, exit 1 on block
async function cmdCi(args) {
  const dir = path.resolve(args.path || process.env.GITHUB_WORKSPACE || '.');
  const skip = parseSkip(args);
  const cfg = loadConfig(dir);
  applyCliFailOn(args, cfg);
  const findings = [];
  await runEngines(dir, cfg, skip, findings);
  const deduped = dedupe(findings);
  const { blocked } = generateReport(deduped, cfg, dir);
  console.log(`secflow ci: ${deduped.length} findings — ${blocked.length ? 'BLOCKED (' + blocked.join(',') + ')' : 'PASS'}`);
  if (blocked.length) process.exitCode = 1;
}

// Baseline: snapshot current findings as accepted/known-good.
// Future scans with --baseline flag will subtract these from "new findings" alerts.
function cmdBaseline(args) {
  const dir = path.resolve(args.path || '.');
  const reportPath = path.join(dir, '.secflow', 'report.json');
  if (!fs.existsSync(reportPath)) { console.error('no report — run `secflow scan` first'); process.exit(2); }

  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  const findings = report.findings || [];
  const timestamp = new Date().toISOString();

  // Get git context for provenance
  let commit = 'unversioned';
  try {
    commit = execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim();
  } catch { /* ignore */ }

  const baselinePath = path.join(dir, '.secflow', 'baseline.json');

  // --clear: wipe baseline entirely
  if (args.clear) {
    if (fs.existsSync(baselinePath)) fs.rmSync(baselinePath);
    console.log('secflow baseline cleared');
    return;
  }

  // Build accepted findings list
  const accepted = findings.map(f => ({
    engine: f.engine,
    rule: f.rule,
    file: f.file,
    line: f.line,
    severity: f.severity,
  }));

  const baseline = {
    version: report.version,
    created: timestamp,
    commit,
    total_accepted: accepted.length,
    accepted,
  };

  fs.writeFileSync(baselinePath, JSON.stringify(baseline, null, 2));
  console.log(`secflow baseline saved: ${accepted.length} findings accepted at ${commit}`);
  console.log(`  future scans will subtract these from "new findings" alerts`);
}

// Re-attack verification: re-run scan, compare to previous report.
// Reports NEW regressions (findings that were absent before) separately.
// exit 0 = no new findings, exit 1 = new regressions found
async function cmdVerify(args) {
  const dir = path.resolve(args.path || '.');
  // Compare current scan against the PREVIOUS report (archived before this scan ran)
  const prevPath = path.join(dir, '.secflow', 'report-prev.json');
  if (!fs.existsSync(prevPath)) { console.error('no prior report — run `secflow scan` first'); process.exit(2); }

  const prevReport = JSON.parse(fs.readFileSync(prevPath, 'utf8'));
  const prevFindings = prevReport.findings || [];
  const prevKeys = new Set(prevFindings.map(f => `${f.engine}|${f.file}|${f.line}|${f.rule}`));

  // Re-run scan
  const cfg = loadConfig(dir);
  const skip = parseSkip(args);
  const findings = [];
  await runEngines(dir, cfg, skip, findings);
  const deduped = dedupe(findings);

  // Categorize: new regressions vs still-present vs fixed
  const newRegressions = deduped.filter(f => !prevKeys.has(`${f.engine}|${f.file}|${f.line}|${f.rule}`));
  const stillPresent = deduped.filter(f => prevKeys.has(`${f.engine}|${f.file}|${f.line}|${f.rule}`));
  const fixed = prevFindings.filter(f => !deduped.some(d => d.engine === f.engine && d.file === f.file && d.line === f.line && d.rule === f.rule));

  // Write verification report
  const out = path.join(dir, '.secflow');
  const verifyReport = {
    version: VERSION,
    generated: new Date().toISOString(),
    previous_scan: prevReport.generated || 'unknown',
    summary: {
      new_regressions: newRegressions.length,
      still_present: stillPresent.length,
      fixed: fixed.length,
      current_total: deduped.length,
      previous_total: prevFindings.length,
    },
    new_regressions: newRegressions,
    still_present: stillPresent,
    fixed,
  };

  fs.writeFileSync(path.join(out, 'verify.json'), JSON.stringify(verifyReport, null, 2));

  const lines = [];
  lines.push(`# secflow verify — ${path.basename(dir)}`);
  lines.push('');
  lines.push(`> Generated ${new Date().toISOString()} — secflow v${VERSION}`);
  lines.push('');
  lines.push('## Summary');
  lines.push('');
  lines.push(`| Metric | Count |`);
  lines.push(`|--------|-------|`);
  lines.push(`| **New regressions** | **${newRegressions.length}** |`);
  lines.push(`| Still present | ${stillPresent.length} |`);
  lines.push(`| Fixed since last scan | ${fixed.length} |`);
  lines.push(`| Current total | ${deduped.length} |`);
  lines.push(`| Previous total | ${prevFindings.length} |`);
  lines.push('');

  if (newRegressions.length > 0) {
    lines.push('## ⚠️ New Regressions');
    lines.push('');
    lines.push('| # | Engine | Rule | File:Line | Severity |');
    lines.push('|---|--------|------|-----------|----------|');
    newRegressions.forEach((f, i) => {
      lines.push(`| ${i + 1} | ${cell(f.engine)} | \`${cell(f.rule)}\` | \`${cell(f.file)}:${f.line}\` | **${f.severity}** |`);
    });
    lines.push('');
  }

  if (fixed.length > 0) {
    lines.push('## ✅ Fixed');
    lines.push('');
    lines.push('| # | Engine | Rule | File:Line | Severity |');
    lines.push('|---|--------|------|-----------|----------|');
    fixed.forEach((f, i) => {
      lines.push(`| ${i + 1} | ${cell(f.engine)} | \`${cell(f.rule)}\` | \`${cell(f.file)}:${f.line}\` | ${f.severity} |`);
    });
    lines.push('');
  }

  fs.writeFileSync(path.join(out, 'verify.md'), lines.join('\n'));

  if (newRegressions.length > 0) {
    console.error(`secflow verify: ${newRegressions.length} NEW regression(s) — see .secflow/verify.md`);
    process.exitCode = 1;
  } else if (fixed.length > 0) {
    console.log(`secflow verify: ✅ ${fixed.length} fixed, ${newRegressions.length} new — see .secflow/verify.md`);
  } else {
    console.log(`secflow verify: ✅ no regressions, ${stillPresent.length} still present — see .secflow/verify.md`);
  }
}

// ---------- CLI ----------

const argv = process.argv.slice(2);

const help = `secflow v${VERSION} — zero-cost security scanning for AI-driven repos
Usage:
  secflow scan [--path DIR] [--skip gitleaks,trivy,npm,regex] [--fail-on critical,high] [--json] [--baseline]
  secflow report [--path DIR]
  secflow verify [--path DIR] [--skip gitleaks,trivy,npm,regex]  # re-attack: confirm fixes landed
  secflow baseline [--path DIR] [--clear]                        # snapshot accepted findings
  secflow install-hook [--path DIR]
  secflow init [--path DIR]
  secflow ci [--path DIR]
  secflow --version
`;

if (argv[0] === '--version' || argv[0] === '-v') { console.log(`secflow v${VERSION}`); process.exit(0); }
if (argv[0] === '--help' || argv[0] === '-h') { console.log(help); process.exit(0); }

const cmd = argv[0] || 'help';
const opts = {};
const KNOWN_FLAGS = new Set(['path', 'skip', 'fail-on', 'json', 'baseline', 'clear']);
const rest = argv.slice(1);
for (let i = 0; i < rest.length; i++) {
  const a = rest[i];
  const m = a.match(/^--([A-Za-z0-9_-]+)(?:=(.*))?$/);
  if (m) {
    if (!KNOWN_FLAGS.has(m[1])) log(`warn: unrecognized flag --${m[1]} — ignored`);
    if (m[2] !== undefined) opts[m[1]] = m[2];
    else if (rest[i + 1] && !rest[i + 1].startsWith('--')) opts[m[1]] = rest[++i];
    else opts[m[1]] = true;
  }
}

function fail(e) { log(`error: ${(e && e.message) || e}`); process.exitCode = 2; }

try {
  switch (cmd) {
      case 'scan': cmdScan(opts).catch(fail); break;
      case 'report': cmdReport(opts); break;
      case 'verify': cmdVerify(opts).catch(fail); break;
      case 'baseline': cmdBaseline(opts); break;
      case 'init': cmdInit(opts); break;
      case 'install-hook': cmdInstallHook(opts); break;
      case 'ci': cmdCi(opts).catch(fail); break;
      case 'help': console.log(help); break;
      default: console.log(help); process.exitCode = 1;
  }
} catch (e) { fail(e); }
