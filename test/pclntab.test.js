// pclntab: dört düzen (1.2, 1.16, 1.18, 1.20+) × ELF64/ELF32/PE/Mach-O × LE/BE, bölüm adı / sembol / sihirli değer
// taraması ile bulma, satır tabloları ve 1.18+ functab tabanı. Bozuk tablolar çökme değil ParseError verir.
import assert from 'node:assert/strict';
import { openImage } from '../src/core/container.js';
import { findPclntab, parsePclntab, LIMITS } from '../src/core/pclntab.js';
import { buildGoBinary } from '../src/core/synth.js';
import { ParseError } from '../src/core/reader.js';
import { fixture } from './helpers.js';

const FUNCS = [
  { name: 'runtime.main', file: 'runtime/proc.go', line: 145, size: 48 },
  { name: 'example.com/x/pkg.(*T).Method', file: 'example.com/x/pkg/t.go', line: 30, size: 64, lines: [[16, 30], [32, 31], [16, 33]] },
  { name: 'main.main', file: 'example.com/x/main.go', line: 7, size: 32 },
];

let cases = 0;
for (const version of ['1.2', '1.16', '1.18', '1.20']) {
  for (const [format, bits, le] of [['elf', 64, true], ['elf', 32, true], ['elf', 64, false], ['pe', 64, true], ['pe', 32, true], ['macho', 64, true]]) {
    for (const named of [true, false]) {
      const b = buildGoBinary({ format, bits, le, pclntab: version, funcs: FUNCS, pclntabSection: named, arch: le ? 'amd64' : 'ppc64' });
      const img = openImage(b.bytes);
      const found = findPclntab(img);
      const tag = `${version} ${format}${bits} ${le ? 'LE' : 'BE'} ${named ? 'bölüm' : 'tarama'}`;
      assert.ok(found?.tab, `${tag}: ${found?.error}`);
      const { tab, cand } = found;
      assert.equal(tab.version, version, tag);
      assert.equal(tab.le, le, tag);
      assert.equal(cand.how, named && format !== 'pe' ? 'section' : 'scan', tag);
      assert.deepEqual(tab.funcs.map((f) => f.name), FUNCS.map((f) => f.name), tag);
      assert.deepEqual(tab.funcs.map((f) => f.entry), b.funcs.map((f) => f.entry), `${tag}: girişler`);
      assert.deepEqual(tab.funcs.map((f) => f.end - f.entry), b.funcs.map((f) => f.size), `${tag}: boyutlar`);
      const m = tab.details(tab.funcs[1], { lines: true });
      assert.equal(m.file, 'example.com/x/pkg/t.go', tag);
      assert.equal(m.startLine, 30, tag);
      assert.equal(m.endLine, 33, tag);
      assert.deepEqual(m.lines.map((l) => l[2]), [30, 31, 33], `${tag}: satır tablosu`);
      cases++;
    }
  }
}

// 1.18+: functab girişleri text'e görelidir; yanlış taban verilirse girişler kayar, doğru tabanla yeniden ayrıştırılır
const b120 = buildGoBinary({ pclntab: '1.20', funcs: FUNCS });
const img = openImage(b120.bytes);
const off = img.section('.gopclntab').offset;
const wrong = parsePclntab(b120.bytes, off, { textStart: 0x1000 });
assert.notEqual(wrong.funcs[0].entry, b120.funcs[0].entry);
assert.equal(parsePclntab(b120.bytes, off, { textStart: b120.text }).funcs[0].entry, b120.funcs[0].entry);

// gerçek: Go 1.26 (1.20 düzeni, textStart yazılmamış), PE'de bölüm adı yok → tarama
for (const [file, how] of [['basic.linux-amd64.gz', 'section'], ['basic.windows-amd64.gz', 'scan'], ['basic.darwin-arm64.gz', 'section']]) {
  const r = findPclntab(openImage(fixture(file)));
  assert.equal(r.tab.version, '1.20', file);
  assert.equal(r.tab.headerText, 0, `${file}: Go 1.22+ textStart yazmaz`);
  assert.equal(r.cand.how, how, file);
  assert.ok(r.tab.funcs.length > 1500);
}

// bozuk / kötü niyetli tablolar: sınır dışı okuma ParseError, akla yatkın olmayan fonksiyon sayısı reddedilir
const bad = b120.bytes.slice();
const dv = new DataView(bad.buffer);
dv.setBigUint64(off + 8, 10n ** 12n, true);
assert.throws(() => parsePclntab(bad, off), ParseError);
dv.setBigUint64(off + 8, BigInt(LIMITS.maxFuncs + 1), true);
assert.throws(() => parsePclntab(bad, off), ParseError);
const trunc = b120.bytes.slice(0, off + 40);
assert.throws(() => parsePclntab(trunc, off), ParseError);
// sihirli değer var ama başlık geçersiz
const fake = b120.bytes.slice();
fake[off + 6] = 3;
assert.throws(() => parsePclntab(fake, off), ParseError);
// rastgele bayt bombardımanı: ya ayrıştırır ya ParseError (başka istisna yok)
let seed = 7;
const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed; };
for (let i = 0; i < 300; i++) {
  const x = b120.bytes.slice();
  for (let k = 0; k < 8; k++) x[off + 8 + (rnd() % 900)] = rnd() & 0xff;
  try { parsePclntab(x, off, { textStart: b120.text }); } catch (e) { assert.ok(e instanceof ParseError || e instanceof RangeError, e.stack); }
}
console.log(`pclntab: ${cases} sentetik durum (4 düzen × 6 kapsayıcı × bölüm/tarama), 3 gerçek, bozuk tablolar`);
