// Tarayıcı yolunun Node'daki karşılığı: web-worker.js'teki ileti işleyicisi (handler.js) örnek ikiliyi soyabilmeli,
// _headers kuralları ayrıştırılmalı, worker CSP'si dış ağı ve eval'i kapatmalı, PWA dosyaları tutarlı olmalı.
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { handle } from '../src/sandbox/handler.js';
import { sampleBytes, SAMPLE_NAME } from '../src/sample.js';
import { parseHeaders } from '../vite.config.js';

const progress = [];
const res = await handle({ id: 1, type: 'peel', bytes: sampleBytes(), name: SAMPLE_NAME, lang: 'en' }, (m) => progress.push(m));
assert.equal(res.ok, true, res.result?.error);
const r = res.result;
assert.ok(r.report.detection.some((d) => d.id === 'garble'), 'örnekte garble tanınmalı');
assert.deepEqual(r.literals.recovered.map((l) => l.value), ['https://cdn.peel-fixture.test/cfg']);
assert.ok(r.listing.includes('main.main') && r.rawView.includes('sub_'));
assert.ok(progress.every((p) => p.id === 1 && p.type === 'progress'));
assert.equal((await handle({ type: 'nope' }, () => {})).ok, false);
assert.equal((await handle({ type: 'peel', bytes: 'x' }, () => {})).ok, false);

// barındırma başlıkları
const rules = parseHeaders(readFileSync(new URL('../public/_headers', import.meta.url), 'utf8'));
const worker = rules.find((r) => r.path === '/assets/web-worker-*')?.headers['Content-Security-Policy'] ?? '';
assert.match(worker, /default-src 'none'/);
assert.match(worker, /connect-src 'self'/);
assert.doesNotMatch(worker, /'unsafe-eval'|'unsafe-inline'|'wasm-unsafe-eval'/);
const page = rules.find((r) => r.path === '/index.html')?.headers['Content-Security-Policy'] ?? '';
assert.ok(page.includes("frame-ancestors 'none'") && page.includes("object-src 'none'") && !page.includes('unsafe-eval'));

// PWA
const manifest = JSON.parse(readFileSync(new URL('../public/manifest.webmanifest', import.meta.url), 'utf8'));
assert.equal(manifest.short_name, 'PEEL Go');
for (const icon of manifest.icons) assert.match(icon.src, /^peel-icon/);
assert.match(readFileSync(new URL('../public/sw.js', import.meta.url), 'utf8'), /const VERSION = 'peel-go-v\d+'/);
const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
assert.ok(html.includes('<title>PEEL · Go Deobfuscator</title>') && html.includes('id="btn-format"'));
const logos = ['peel-icon.svg', 'peel-icon-512.png', 'peel-logo-horizontal-1600.png'].filter((f) => existsSync(new URL(`../public/${f}`, import.meta.url)));
console.log(`web: örnek ${r.functions.length} fonksiyon, ${r.literals.recovered.length} gizli dizge, ${rules.length} başlık kuralı, ${logos.length} logo dosyası mevcut`);
