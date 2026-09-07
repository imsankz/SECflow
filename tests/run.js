#!/usr/bin/env node
/**
 * secflow smoke tests — no framework, plain node asserts.
 * Run: node tests/run.js
 */
'use strict';

const assert = require('node:assert');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const BIN = path.join(__dirname, '..', 'bin', 'secflow.js');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secflow-test-'));

function run(args, opts = {}) {
  return spawnSync('node', [BIN, ...args], { encoding: 'utf8', ...opts });
}

// Shim an executable on PATH. Used to fake `npm audit` output deterministically
// (no network) and to assert the engine's npm-audit parsing/dedupe behavior.
function shim(dir, name, contents) {
  const p = path.join(dir, name);
  fs.writeFileSync(p, contents);
  fs.chmodSync(p, 0o755);
  return p;
}

const FAKE_NPM_AUDIT_MULTI = JSON.stringify({
  metadata: { vulnerabilities: { info: 0, low: 0, moderate: 2, high: 1, critical: 0, total: 3 } },
  vulnerabilities: {
    '@humanfs/node': { name: '@humanfs/node', severity: 'moderate', isDirect: false, range: '<0.16.8', fixAvailable: true, title: null, via: [{ title: 'humanfs: Recursive copy follows symlinked files and copies data from outside the source tree', severity: 'moderate' }] },
    browserslist: { name: 'browserslist', severity: 'high', isDirect: false, range: '<=4.28.6', fixAvailable: true, title: null, via: [
      { title: 'Browserslist: Unbounded memory growth (no cache eviction) via distinct query results, leading to eventual OOM', severity: 'high' },
      { title: 'Browserslist: Uncaught crash / prototype write via untrusted browserslist-stats.json custom stats (normalizeStats)', severity: 'high' }
    ] },
    qs: { name: 'qs', severity: 'moderate', isDirect: false, range: '2.2.5 - 6.15.3', fixAvailable: true, title: null, via: [{ title: 'qs: Denial of Service via Attacker Controlled isBuffer', severity: 'moderate' }] }
  }
}, null, 2);

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`✓ ${name}`); }
  catch (e) { failed++; console.error(`✗ ${name}: ${e.message}`); }
}

// ---------- fixture: a fake project with a real-looking secret ----------
const proj = path.join(tmp, 'demo');
fs.mkdirSync(path.join(proj, 'src'), { recursive: true });
fs.writeFileSync(path.join(proj, 'package.json'), JSON.stringify({ name: 'demo', version: '1.0.0', dependencies: { lodash: '^4.17.20' } }));
fs.writeFileSync(path.join(proj, 'src', 'config.js'), `module.exports = { apiKey: "sk_live_REPLACEME_51HxQb3Kc9XyZvWq8rT2mNp4Ld6JfGh0AbCdEf1234567890", url: "https://example.com" };\n`);
fs.writeFileSync(path.join(proj, 'src', 'auth.js'), `const token = "ghp_REPLACEME_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGH";\n`);
fs.writeFileSync(path.join(proj, 'src', 'ok.js'), `export const greeting = "hello world";\n`);

// ---------- regex engine ----------
test('regex engine catches sk_live_ and ghp_ with file:line', () => {
  const r = run(['scan', '--path', proj, '--skip', 'gitleaks,trivy,npm', '--json']);
  const out = JSON.parse(r.stdout);
  const secrets = out.findings.filter(f => f.engine === 'regex');
  const sk = secrets.find(f => f.rule === 'stripe-live-secret');
  const gh = secrets.find(f => f.rule === 'github-token');
  assert.ok(sk, 'stripe secret not found');
  assert.ok(gh, 'github token not found');
  assert.strictEqual(sk.file, 'src/config.js');
  assert.strictEqual(sk.severity, 'critical');
  assert.ok(sk.match.startsWith('sk_live_'));
  assert.ok(sk.match.includes('REPLACEME') || sk.match.includes('redacted') || sk.match.includes('…'));
  assert.strictEqual(gh.line, 1);
});

test('regex engine ignores ok.js', () => {
  const r = run(['scan', '--path', proj, '--skip', 'gitleaks,trivy,npm', '--json']);
  const out = JSON.parse(r.stdout);
  const ok = out.findings.find(f => f.file.includes('ok.js'));
  assert.strictEqual(ok, undefined, 'ok.js should have no findings');
});

test('fail-on critical sets exit code 1', () => {
  const r = run(['scan', '--path', proj, '--skip', 'gitleaks,trivy,npm']);
  assert.strictEqual(r.status, 1);
});

test('report.md generated with AI-ready section', () => {
  const report = fs.readFileSync(path.join(proj, '.secflow', 'report.md'), 'utf8');
  assert.ok(report.includes('# secflow report'));
  assert.ok(report.includes('AI-ready fixes'));
  assert.ok(report.includes('CI BLOCKED'));
});

// ---------- gitleaks engine (if installed) ----------
let hasGitleaks = false;
try { execFileSync('which', ['gitleaks'], { stdio: 'ignore' }); hasGitleaks = true; } catch {}

if (hasGitleaks) {
  test('gitleaks engine detects secret in committed fixture', () => {
    // init git repo, commit the secret, scan
    spawnSync('git', ['init', '-q'], { cwd: proj });
    spawnSync('git', ['add', '-A'], { cwd: proj });
    spawnSync('git', ['-c', 'user.email=t@t.t', '-c', 'user.name=t', 'commit', '-qm', 'fixture'], { cwd: proj });
    const r = run(['scan', '--path', proj, '--skip', 'trivy,npm,regex', '--json']);
    const out = JSON.parse(r.stdout);
    const g = out.findings.filter(f => f.engine === 'gitleaks');
    assert.ok(g.length > 0, `gitleaks found nothing (${r.stderr.slice(0,200)})`);
  });
} else {
  console.log('⚠ gitleaks not installed — skipping gitleaks engine test');
}

// ---------- ci mode ----------
test('ci mode blocks on critical', () => {
  const r = run(['ci', '--path', proj, '--skip', 'trivy,npm,regex']);
  assert.strictEqual(r.status, 1);
});

test('init writes secflow.yml', () => {
  const p2 = path.join(tmp, 'init-test');
  fs.mkdirSync(p2, { recursive: true });
  const r = run(['init', '--path', p2]);
  assert.strictEqual(r.status, 0);
  assert.ok(fs.existsSync(path.join(p2, 'secflow.yml')));
});

// ---------- config: customRegex from secflow.yml + --fail-on override ----------
const cfgProj = path.join(tmp, 'cfg-test');
fs.mkdirSync(path.join(cfgProj, 'src'), { recursive: true });
fs.writeFileSync(path.join(cfgProj, 'secflow.yml'), [
  'engines:',
  '  gitleaks: false',
  '  trivy: false',
  '  npmAudit: false',
  '  regex: true',
  'failOn: critical, high',
  'customRegex:',
  "  acme-internal-token: { pattern: 'ACME_[A-Za-z0-9]{20,}', severity: warning }",
  '',
].join('\n'));
fs.writeFileSync(path.join(cfgProj, 'src', 'client.js'), 'const t = "ACME_REPLACEME00000000000000000000";\n');

test('customRegex rules from secflow.yml are parsed, matched, and tolerate default failOn', () => {
  const r = run(['scan', '--path', cfgProj, '--json']);
  assert.strictEqual(r.status, 0, `expected exit 0 (warning < default threshold), got ${r.status}`);
  const out = JSON.parse(r.stdout);
  const f = out.findings.find(x => x.rule === 'acme-internal-token');
  assert.ok(f, 'custom rule from secflow.yml not matched');
  assert.strictEqual(f.severity, 'warning');
  assert.strictEqual(f.file, 'src/client.js');
});

test('--fail-on overrides secflow.yml failOn and blocks', () => {
  const r = run(['scan', '--path', cfgProj, '--fail-on', 'warning']);
  assert.strictEqual(r.status, 1, 'CLI --fail-on warning should exit 1');
});

test('install-hook writes executable pre-commit', () => {
  spawnSync('git', ['init', '-q'], { cwd: proj });
  const r = run(['install-hook', '--path', proj]);
  assert.strictEqual(r.status, 0);
  const hook = path.join(proj, '.git', 'hooks', 'pre-commit');
  assert.ok(fs.existsSync(hook));
  const st = fs.statSync(hook);
  assert.ok(st.mode & 0o100, 'hook not executable');
});

// ---------- regression: invalid custom pattern (P0-2) ----------
const badProj = path.join(tmp, 'bad-pattern-test');
fs.mkdirSync(path.join(badProj, 'src'), { recursive: true });
fs.writeFileSync(path.join(badProj, 'secflow.yml'), [
  'engines:',
  '  gitleaks: false',
  '  trivy: false',
  '  npmAudit: false',
  '  regex: true',
  'failOn: critical, high',
  'customRegex:',
  "  broken-rule: { pattern: '[unclosed', severity: critical }",
  "  good-rule: { pattern: 'GOOD_[A-Za-z0-9]+', severity: info }",
  '',
].join('\n'));
fs.writeFileSync(path.join(badProj, 'src', 'a.js'), 'const t = "GOOD_REPLACEME_000";\n');

test('invalid custom pattern warns and other rules still run (exit 0)', () => {
  const r = run(['scan', '--path', badProj, '--json']);
  assert.strictEqual(r.status, 0, `expected exit 0, got ${r.status}: ${r.stderr.slice(0, 300)}`);
  assert.ok(/invalid pattern/.test(r.stderr), `stderr missing 'invalid pattern' warning: ${r.stderr.slice(0, 300)}`);
  const out = JSON.parse(r.stdout);
  assert.ok(out.findings.find(f => f.rule === 'good-rule'), 'valid rule after invalid one should still match');
});

// ---------- regression: zero-width custom pattern (P0-1) ----------
const zeroProj = path.join(tmp, 'zero-width-test');
fs.mkdirSync(path.join(zeroProj, 'src'), { recursive: true });
fs.writeFileSync(path.join(zeroProj, 'secflow.yml'), [
  'engines:',
  '  gitleaks: false',
  '  trivy: false',
  '  npmAudit: false',
  '  regex: true',
  'failOn: critical, high',
  'customRegex:',
  "  zero-rule: { pattern: '(?:a+)?', severity: info }",
  '',
].join('\n'));
fs.writeFileSync(path.join(zeroProj, 'src', 'a.js'), 'aaa\n');

test('zero-width pattern terminates (no infinite loop)', () => {
  const r = run(['scan', '--path', zeroProj, '--json'], { timeout: 10000 });
  assert.notStrictEqual(r.status, null, 'scan was killed — zero-width pattern hung');
  assert.ok(r.error === undefined || r.error.code !== 'ETIMEDOUT', 'scan timed out on zero-width pattern');
  assert.strictEqual(r.status, 0, `expected exit 0, got ${r.status}`);
});

// ---------- regression: ci runs full pipeline when gitleaks skipped (P0-3) ----------
const ciProj = path.join(tmp, 'ci-test');
fs.mkdirSync(path.join(ciProj, 'src'), { recursive: true });
fs.writeFileSync(path.join(ciProj, 'src', 'auth.js'), 'const token = "ghp_REPLACEME_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGH";\n');

test('ci --skip gitleaks,trivy,npm still scans regex and blocks', () => {
  const r = run(['ci', '--path', ciProj, '--skip', 'gitleaks,trivy,npm']);
  assert.strictEqual(r.status, 1, `expected exit 1, got ${r.status}: ${r.stderr.slice(0, 300)}`);
  assert.ok(r.stdout.startsWith('secflow ci:'), `ci summary line missing: ${r.stdout.slice(0, 200)}`);
  assert.ok(r.stdout.includes('BLOCKED'), 'ci should report BLOCKED');
  assert.ok(fs.existsSync(path.join(ciProj, '.secflow', 'report.md')), 'report.md should exist');
});

// ---------- regression: bare --skip flag (P0-4) ----------
test('bare --skip does not crash', () => {
  const r = run(['scan', '--path', cfgProj, '--skip']);
  assert.ok(r.status === 0 || r.status === 1, `expected exit 0/1, got ${r.status}`);
  assert.ok(!r.stderr.includes('TypeError'), `TypeError leaked: ${r.stderr.slice(0, 300)}`);
});

// ---------- regression: --version (P2-12) ----------
test('--version prints secflow v', () => {
  const r = run(['--version']);
  assert.strictEqual(r.status, 0);
  assert.match(r.stdout, /^secflow v\d+\.\d+\.\d+/);
});

// ---------- regression: --json must still block (exit 1) ----------
test('scan --json exits 1 when blocked and stdout stays valid JSON', () => {
  const r = run(['scan', '--path', proj, '--skip', 'gitleaks,trivy,npm', '--json']);
  assert.strictEqual(r.status, 1, `expected exit 1 with blocked findings, got ${r.status}`);
  const out = JSON.parse(r.stdout);
  assert.ok(out.findings.length > 0, 'expected findings in JSON');
});

// ---------- regression: inline comments / quoted scalars in secflow.yml ----------
const commentProj = path.join(tmp, 'comment-config-test');
fs.mkdirSync(path.join(commentProj, 'src'), { recursive: true });
fs.writeFileSync(path.join(commentProj, 'secflow.yml'), [
  'engines:',
  '  gitleaks: false   # skip engine',
  '  trivy: false      # skip engine',
  '  npmAudit: false   # skip engine',
  '  regex: true       # keep this on',
  'failOn: "critical, high"  # quoted scalar',
  'customRegex:',
  "  commented-rule: { pattern: 'COMMENTED_[A-Za-z0-9]+', severity: warning } # note",
  '',
].join('\n'));
fs.writeFileSync(path.join(commentProj, 'src', 'a.js'), 'const t = "COMMENTED_REPLACEME_000";\n');

test('trailing inline comments do not disable engines or break quoted scalars', () => {
  const r = run(['scan', '--path', commentProj, '--json']);
  assert.strictEqual(r.status, 0, `expected exit 0, got ${r.status}: ${r.stderr.slice(0, 300)}`);
  const out = JSON.parse(r.stdout);
  const f = out.findings.find(x => x.rule === 'commented-rule');
  assert.ok(f, 'custom rule with trailing comment should still match (regex engine stayed on)');
});

// ---------- regression: install-hook backs up foreign hook ----------
test('install-hook backs up a foreign pre-commit, idempotent on its own', () => {
  const p3 = path.join(tmp, 'hook-test');
  fs.mkdirSync(path.join(p3, '.git', 'hooks'), { recursive: true });
  const hook = path.join(p3, '.git', 'hooks', 'pre-commit');
  fs.writeFileSync(hook, '#!/bin/sh\nexit 0 # not secflow\n');
  let r = run(['install-hook', '--path', p3]);
  assert.strictEqual(r.status, 0);
  assert.ok(fs.existsSync(hook + '.secflow-bak'), 'foreign hook should be backed up');
  assert.ok(fs.readFileSync(hook, 'utf8').includes('secflow pre-commit'), 'hook should be replaced by secflow hook');
  r = run(['install-hook', '--path', p3]); // re-run on secflow's own hook: idempotent, no second backup churn
  assert.strictEqual(r.status, 0);
  assert.ok(fs.readFileSync(hook, 'utf8').includes('secflow pre-commit'));
});

// ---------- regression: report before any scan exits 2 (documented contract) ----------
test('report with no prior scan exits 2', () => {
  const p4 = path.join(tmp, 'no-report-test');
  fs.mkdirSync(p4, { recursive: true });
  const r = run(['report', '--path', p4]);
  assert.strictEqual(r.status, 2);
});

// ---------- supabase-key rule: HS256 header form ----------
test('supabase-key matches HS256-header anon key', () => {
  const p5 = path.join(tmp, 'supabase-test');
  fs.mkdirSync(path.join(p5, 'src'), { recursive: true });
  fs.writeFileSync(path.join(p5, 'src', 'client.js'),
    'const key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.REPLACEMEREPLACEMEREPLACEME.REPLACEMEREPLACEME";\n');
  const r = run(['scan', '--path', p5, '--skip', 'gitleaks,trivy,npm', '--json']);
  const out = JSON.parse(r.stdout);
  const sb = out.findings.find(f => f.rule === 'supabase-key');
  assert.ok(sb, 'HS256-header supabase key should match supabase-key rule');
  assert.strictEqual(sb.severity, 'high');
  assert.strictEqual(sb.file, 'src/client.js');
  assert.strictEqual(sb.line, 1);
});

// ---------- regression: npm audit multi-vuln dedupe collapse (P1) ----------
test('npm audit reports EVERY vuln (no dedupe collapse), high blocks CI', () => {
  const dir = path.join(tmp, 'npm-multi-vuln');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'demo', version: '1.0.0', dependencies: {} }));
  const binDir = path.join(dir, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  shim(binDir, 'npm', `#!/bin/sh\ncat >&2 <<'EOF'\n[secflow] fake npm\nEOF\necho '${FAKE_NPM_AUDIT_MULTI.replace(/'/g, "'\\''")}'\nexit 1\n`);
  const env = { ...process.env, PATH: `${binDir}:${process.env.PATH}` };
  const r = spawnSync('node', [BIN, 'scan', '--path', dir, '--skip', 'gitleaks,trivy,regex', '--json'], { encoding: 'utf8', env });
  const out = JSON.parse(r.stdout);
  const npmFindings = out.findings.filter(f => f.engine === 'npm-audit');
  // Every distinct vulnerable package must survive dedupe (bug: all shared one rule → collapsed to 1)
  assert.strictEqual(npmFindings.length, 3, `expected 3 npm-audit findings, got ${npmFindings.length}: ${JSON.stringify(npmFindings.map(f => f.match))}`);
  const sev = npmFindings.map(f => f.severity).sort();
  assert.deepStrictEqual(sev, ['high', 'warning', 'warning'], `expected severities [high, warning, warning], got ${JSON.stringify(sev)}`);
  const bl = npmFindings.find(f => f.match.startsWith('browserslist'));
  assert.ok(bl, 'browserslist (high) must be present');
  assert.ok(bl.rule.startsWith('Browserslist:'), `browserslist rule should carry advisory title, got: ${bl.rule}`);
  assert.deepStrictEqual(out.blocked, ['high'], 'high-severity npm vuln must block CI');
});

// ---------- verify: re-attack comparison ----------
test('verify: no prior report exits 2', () => {
  const p6 = path.join(tmp, 'verify-noreport');
  fs.mkdirSync(p6, { recursive: true });
  const r = run(['verify', '--path', p6]);
  assert.strictEqual(r.status, 2);
});

test('verify: detects new regressions and fixed findings', () => {
  const p7 = path.join(tmp, 'verify-regression');
  fs.mkdirSync(path.join(p7, 'src'), { recursive: true });
  fs.writeFileSync(path.join(p7, 'package.json'), JSON.stringify({ name: 'v', version: '1.0.0', dependencies: {} }));
  // First scan: has a secret (TEST-only format, matches sk_live_[A-Za-z0-9_]{24,})
  fs.writeFileSync(path.join(p7, 'src', 'config.js'), 'const key = "sk_live_TEST_0000000000000000000000000000";\n');
  let r = run(['scan', '--path', p7, '--skip', 'gitleaks,trivy,npm']);
  assert.strictEqual(r.status, 1);
  // Second scan: same secret + new one
  fs.writeFileSync(path.join(p7, 'src', 'config.js'), 'const key = "sk_live_TEST_0000000000000000000000000000";\n');
  fs.writeFileSync(path.join(p7, 'src', 'new.js'), 'const token = "ghp_TEST_000000000000000000000000000000000000";\n');
  r = run(['scan', '--path', p7, '--skip', 'gitleaks,trivy,npm']);
  assert.strictEqual(r.status, 1);
  // Verify: should detect 1 new regression
  r = run(['verify', '--path', p7, '--skip', 'gitleaks,trivy,npm']);
  assert.strictEqual(r.status, 1);
  const verifyReport = JSON.parse(fs.readFileSync(path.join(p7, '.secflow', 'verify.json'), 'utf8'));
  assert.strictEqual(verifyReport.summary.new_regressions, 1);
  assert.strictEqual(verifyReport.summary.still_present, 1);
  assert.ok(verifyReport.new_regressions, 'verify.json should have new_regressions array');
  assert.ok(fs.existsSync(path.join(p7, '.secflow', 'verify.md')), 'verify.md should be written');
});

test('verify: reports fixed findings', () => {
  const p8 = path.join(tmp, 'verify-fixed');
  fs.mkdirSync(path.join(p8, 'src'), { recursive: true });
  fs.writeFileSync(path.join(p8, 'package.json'), JSON.stringify({ name: 'v', version: '1.0.0', dependencies: {} }));
  // First scan: has secrets
  fs.writeFileSync(path.join(p8, 'src', 'a.js'), 'const key = "sk_live_TEST_0000000000000000000000000000";\n');
  fs.writeFileSync(path.join(p8, 'src', 'b.js'), 'const token = "ghp_TEST_000000000000000000000000000000000000";\n');
  let r = run(['scan', '--path', p8, '--skip', 'gitleaks,trivy,npm']);
  assert.strictEqual(r.status, 1);
  // Fix: remove secrets
  fs.writeFileSync(path.join(p8, 'src', 'a.js'), 'const key = process.env.KEY;\n');
  fs.writeFileSync(path.join(p8, 'src', 'b.js'), 'const token = process.env.TOKEN;\n');
  r = run(['scan', '--path', p8, '--skip', 'gitleaks,trivy,npm']);
  assert.strictEqual(r.status, 0);
  // Verify: should report fixed findings
  r = run(['verify', '--path', p8, '--skip', 'gitleaks,trivy,npm']);
  assert.strictEqual(r.status, 0);
  const verifyReport = JSON.parse(fs.readFileSync(path.join(p8, '.secflow', 'verify.json'), 'utf8'));
  assert.strictEqual(verifyReport.summary.new_regressions, 0);
  assert.strictEqual(verifyReport.summary.fixed, 2);
});

// ---------- baseline: snapshot accepted findings ----------
test('baseline: no prior report exits 2', () => {
  const p9 = path.join(tmp, 'baseline-noreport');
  fs.mkdirSync(p9, { recursive: true });
  const r = run(['baseline', '--path', p9]);
  assert.strictEqual(r.status, 2);
});

test('baseline: saves snapshot and scan --baseline subtracts it', () => {
  const p10 = path.join(tmp, 'baseline-subtract');
  fs.mkdirSync(path.join(p10, 'src'), { recursive: true });
  fs.writeFileSync(path.join(p10, 'package.json'), JSON.stringify({ name: 'b', version: '1.0.0', dependencies: {} }));
  fs.writeFileSync(path.join(p10, 'src', 'config.js'), 'const key = "sk_live_TEST_0000000000000000000000000000";\n');
  let r = run(['scan', '--path', p10, '--skip', 'gitleaks,trivy,npm']);
  assert.strictEqual(r.status, 1);
  // Save baseline
  r = run(['baseline', '--path', p10]);
  assert.strictEqual(r.status, 0);
  const baseline = JSON.parse(fs.readFileSync(path.join(p10, '.secflow', 'baseline.json'), 'utf8'));
  assert.strictEqual(baseline.total_accepted, 1);
  assert.ok(baseline.commit, 'baseline should have commit info');
  // Scan with --baseline: should show 0 new findings
  r = run(['scan', '--path', p10, '--skip', 'gitleaks,trivy,npm', '--baseline']);
  assert.strictEqual(r.status, 0);
  // Clear baseline
  r = run(['baseline', '--path', p10, '--clear']);
  assert.strictEqual(r.status, 0);
  assert.ok(!fs.existsSync(path.join(p10, '.secflow', 'baseline.json')), 'baseline file should be removed');
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
