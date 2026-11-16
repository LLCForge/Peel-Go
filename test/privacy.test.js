// Kişisel bilgi denetimi: derlenmiş fixture'larda (Go derleme yolları gömer) kullanıcı dizini, geçici dizin ve bu
// makinenin kullanıcı/ana bilgisayar adı olmamalı; depo metin dosyalarında yerel yol ve e-posta olmamalı.
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { userInfo, hostname, tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { manifest, fixture } from './helpers.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const PATHS = [
  /[A-Za-z]:[\\/]+(?:Users|Documents and Settings)[\\/]+[^\\/\s"']+/i,
  /\/(?:home|Users)\/[A-Za-z0-9._-]+\//,
  /AppData[\\/]+(?:Local|Roaming)/i,
  /\\\\[A-Za-z0-9-]+\\[A-Za-z$]/, // UNC paylaşımı
];
// bu makineye özgü adlar (çok kısa olanlar yanlış pozitif verir, atlanır)
const local = [userInfo().username, hostname(), tmpdir()].filter((s) => s && s.length >= 4);

let scanned = 0;
for (const fx of manifest.fixtures) {
  const text = Buffer.from(fixture(fx.file)).toString('latin1');
  for (const re of PATHS) assert.doesNotMatch(text, re, `${fx.file}: yerel yol`);
  for (const s of local) assert.ok(!text.includes(s), `${fx.file}: yerel ad`);
  // -trimpath: Go kaynak yolları modül/paket göreli olmalı
  assert.ok(text.includes('example.com/') || text.includes('Wq8eZtLp/') || text.includes('kzqvtrwxbnmplhgd/'), `${fx.file}: modül göreli yol yok`);
  scanned += text.length;
}

// depo metin dosyaları
// gizli dizinler (araç ayarları, .git) ve üretilen çıktılar taranmaz
const SKIP = new Set(['node_modules', 'dist', 'fixtures']);
const TEXT = /\.(?:js|json|md|html|css|webmanifest|txt|py)$|^_headers$|^LICENSE$|^\.gitignore$/;
const words = [['clau', 'de'], ['anthro', 'pic'], ['generated', ' by'], ['co-authored', '-by']].map((p) => new RegExp(p.join(''), 'i'));
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/;
const files = [];
const walk = (d) => {
  for (const e of readdirSync(d)) {
    const p = join(d, e);
    const dir = statSync(p).isDirectory();
    if (SKIP.has(e) || (dir && e.startsWith('.'))) continue;
    if (dir) walk(p);
    else if (TEXT.test(e)) files.push(p);
  }
};
walk(root);
for (const f of files) {
  const text = readFileSync(f, 'utf8');
  const rel = relative(root, f);
  for (const re of PATHS) assert.doesNotMatch(text, re, `${rel}: yerel yol`);
  for (const s of local) assert.ok(!text.includes(s), `${rel}: yerel ad`);
  for (const re of words) assert.doesNotMatch(text, re, `${rel}: yasak ifade`);
  assert.doesNotMatch(text, EMAIL, `${rel}: e-posta adresi`);
}
console.log(`privacy: ${manifest.fixtures.length} fixture (${(scanned / 1048576).toFixed(1)} MB) ve ${files.length} metin dosyası temiz`);
