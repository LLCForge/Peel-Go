// CLI uçtan uca: dosya, dizin ve stdin girdisi, çıktı biçimleri, rapor, --fail-on, --only, kullanım hataları, çıkış kodları.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixture, synthetic } from './helpers.js';

const bin = fileURLToPath(new URL('../bin/peel-go.js', import.meta.url));
const run = (...args) => spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', timeout: 180_000, maxBuffer: 64 << 20 });

const dir = mkdtempSync(join(tmpdir(), 'peel-go-cli-'));
try {
  const gl = join(dir, 'gl');
  writeFileSync(gl, fixture('garblelike.linux-amd64.gz'));
  // stdout'a listeleme, özet stderr'e
  const a = run(gl, '--lang', 'en');
  assert.equal(a.status, 0, a.stderr);
  assert.match(a.stdout, /^; Peel-Go · gl/);
  assert.match(a.stdout, /\[split\] "peel-fixture: split literal recovered"/);
  assert.match(a.stderr, /\[none 0\/100\].*Obfuscator: garble/);
  // -o .py (Ghidra) + --ida + --r2 + JSON rapor dosyası
  const out = join(dir, 'g.ghidra.py');
  const ida = join(dir, 'g.ida.py');
  const r2 = join(dir, 'g.r2');
  const rep = join(dir, 'rep.json');
  const b = run(gl, '-o', out, '--ida', ida, '--r2', r2, '-r', rep, '-q');
  assert.equal(b.status, 0, b.stderr);
  assert.equal(b.stdout, '');
  assert.match(readFileSync(out, 'utf8'), /from ghidra\.program\.model\.symbol import SourceType/);
  assert.match(readFileSync(ida, 'utf8'), /import ida_name/);
  assert.match(readFileSync(r2, 'utf8'), /^afn Wq8eZtLp_kQ8wZr3T\.Yt5Kc0Vd @ 0x/m);
  const json = JSON.parse(readFileSync(rep, 'utf8'));
  assert.equal(json.ok, true);
  assert.equal(json.report.literals.length, 7);
  assert.ok(json.report.detection.some((d) => d.id === 'garble'));
  // -f json stdout; --only ile gizli dizge geçişi kapalı
  const c = run(gl, '-f', 'json', '--only', 'strings', '-q');
  assert.equal(c.status, 0, c.stderr);
  const cj = JSON.parse(c.stdout);
  assert.equal(cj.literals.recovered.length, 0);
  assert.ok(cj.strings.length > 100);

  // dizin: yalnızca ikililer alınır, yapı korunur, rapor dizisi; tehlikeli dizgeler --fail-on high → 4
  const tree = join(dir, 'tree');
  mkdirSync(join(tree, 'sub'), { recursive: true });
  writeFileSync(join(tree, 'clean.exe'), fixture('basic.windows-amd64.gz'));
  const enc = new TextEncoder();
  const evil = ['Software\\Microsoft\\Windows\\CurrentVersion\\Run', ['https://discord.com/api/', 'webhooks/1234567890/abcdefghijklmnop'].join('')].join('\0');
  writeFileSync(join(tree, 'sub', 'evil'), synthetic({ rodata: enc.encode(`\0${evil}\0`), literal: null }).bytes);
  writeFileSync(join(tree, 'notes.md'), 'yok sayılır');
  const outDir = join(dir, 'outdir');
  const d = run(tree, '-d', outDir, '-f', 'r2', '--json', '--fail-on', 'high', '-q');
  assert.equal(d.status, 4, d.stderr);
  const arr = JSON.parse(d.stdout);
  assert.deepEqual(arr.map((e) => e.file), ['clean.exe', 'sub/evil']);
  assert.ok(existsSync(join(outDir, 'sub', 'evil.r2')));
  assert.ok(existsSync(join(outDir, 'clean.exe.r2')));
  assert.equal(arr[0].report.threat.level, 'none');

  // stdin; metin rapor
  const s = spawnSync(process.execPath, [bin, '-', '-r', 'text'], { input: synthetic().bytes, encoding: 'utf8', timeout: 120_000 });
  assert.equal(s.status, 0, s.stderr);
  assert.match(s.stdout, /Çözülen gizli dizgeler \(1\)/);

  // UPX benzeri / Go olmayan ikili: hata değil, rapor
  const notgo = join(dir, 'notgo');
  const { buildContainer } = await import('../src/core/synth.js');
  writeFileSync(notgo, buildContainer({ format: 'elf', sections: [{ name: '.text', data: new Uint8Array(16), exec: true }, { name: '.data', data: new Uint8Array(16), write: true }] }).bytes);
  const n = run(notgo, '-r', 'json', '-q');
  assert.equal(n.status, 0, n.stderr);
  assert.equal(JSON.parse(n.stdout).report.metrics.functions, 0);

  // hatalar
  assert.equal(run('--nope').status, 2);
  assert.equal(run(gl, '-f', 'pdf').status, 2);
  assert.equal(run(gl, '--only', 'nosuch').status, 2);
  assert.equal(run(gl, '--fail-on', 'maybe').status, 2);
  assert.equal(run(gl, '--timeout', '0').status, 2);
  assert.equal(run(tree, '-o', join(dir, 'x.txt')).status, 2);
  const txt = join(dir, 'bad.txt');
  writeFileSync(txt, 'Go ikilisi değil');
  const e = run(txt, '-q');
  assert.equal(e.status, 1);
  assert.equal(run(join(dir, 'missing')).status, 1);
  // süre sınırı: bekçi işi keser, çıkış 1
  const to = run(gl, '--timeout', '0.001', '-q');
  assert.equal(to.status, 1);
  assert.match(run('--help', '--lang', 'en').stdout, /peel-go <file\|dir\|->/);
  assert.match(run('--help').stdout, /Çıkış kodları/);
  console.log('cli: ok');
} finally {
  rmSync(dir, { recursive: true, force: true });
}
