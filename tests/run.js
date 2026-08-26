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

test('install-hook writes executable pre-commit', () => {
  spawnSync('git', ['init', '-q'], { cwd: proj });
  const r = run(['install-hook', '--path', proj]);
  assert.strictEqual(r.status, 0);
  const hook = path.join(proj, '.git', 'hooks', 'pre-commit');
  assert.ok(fs.existsSync(hook));
  const st = fs.statSync(hook);
  assert.ok(st.mode & 0o100, 'hook not executable');
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
