// Kapsayıcı ayrıştırıcıları: ELF (32/64, LE/BE, bölümsüz), PE (PE32/PE32+, içe aktarmalar, COFF sembolleri),
// Mach-O (64, evrensel/fat) — gerçek fixture'lar ve sentetik ikililer.
import assert from 'node:assert/strict';
import { openImage, detectFormat } from '../src/core/container.js';
import { buildContainer } from '../src/core/synth.js';
import { fixture, synthetic } from './helpers.js';

// gerçek: ELF amd64 (sembol tablolu ve silinmiş)
const syms = openImage(fixture('basic.linux-amd64-syms.gz'));
assert.equal(syms.format, 'elf');
assert.equal(syms.arch, 'amd64');
assert.equal(syms.bits, 64);
assert.ok(syms.section('.gopclntab') && syms.section('.go.buildinfo') && syms.section('.text').exec);
assert.ok(syms.symbol('main.main')?.func, '.symtab: main.main');
assert.ok(syms.symbols.length > 1000);
const stripped = openImage(fixture('basic.linux-amd64.gz'));
assert.equal(stripped.symbols.length, 0);
assert.equal(stripped.hasDwarf, false);

// gerçek: ELF 386 / arm64, PE amd64 / 386, Mach-O amd64 / arm64
for (const [file, format, arch, bits] of [
  ['basic.linux-386.gz', 'elf', '386', 32], ['basic.linux-arm64.gz', 'elf', 'arm64', 64],
  ['basic.windows-amd64.gz', 'pe', 'amd64', 64], ['basic.windows-386.gz', 'pe', '386', 32],
  ['basic.darwin-amd64.gz', 'macho', 'amd64', 64], ['basic.darwin-arm64.gz', 'macho', 'arm64', 64],
]) {
  const img = openImage(fixture(file));
  assert.deepEqual([img.format, img.arch, img.bits], [format, arch, bits], file);
  assert.ok(img.text && img.regionOf(img.text.addr)?.exec, `${file}: .text yürütülebilir`);
  const at = img.text.addr + 16;
  assert.equal(img.read(at, 4)?.length, 4, `${file}: read`);
  assert.equal(img.read(0x10, 4), null, `${file}: eşlenmemiş adres null`);
}
const pe = openImage(fixture('basic.windows-amd64.gz'));
assert.ok(pe.imports.some((i) => /kernel32/i.test(i.lib) && /^(?:LoadLibraryW|GetProcAddress|VirtualAlloc)$/.test(i.name)), 'PE içe aktarma tablosu');
assert.ok(pe.imageBase >= 0x400000);
const mac = openImage(fixture('basic.darwin-arm64.gz'));
assert.ok(mac.section('__gopclntab') && mac.libs.some((l) => l.includes('libSystem')), 'Mach-O bölüm ve dylib');
// Mach-O'da rodata __TEXT içindedir ama yürütülebilir sayılmaz
assert.equal(mac.regionOf(mac.section('__rodata').addr).exec, false);

// sentetik: ELF32 BE (ör. ppc), PE32, Mach-O
const be = openImage(synthetic({ bits: 32, le: false, arch: 'ppc64', literal: null }).bytes);
assert.deepEqual([be.format, be.bits, be.le], ['elf', 32, false]);
const pe32 = openImage(synthetic({ format: 'pe', bits: 32, arch: '386', literal: null }).bytes);
assert.deepEqual([pe32.format, pe32.bits, pe32.arch], ['pe', 32, '386']);

// evrensel (fat) Mach-O: arm64 + amd64 dilimi; amd64 seçilir
const a = synthetic({ format: 'macho', arch: 'arm64', literal: null }).bytes;
const b = synthetic({ format: 'macho' }).bytes;
const align = (n) => Math.ceil(n / 0x1000) * 0x1000;
const offA = 0x1000;
const offB = align(offA + a.length);
const fat = new Uint8Array(offB + b.length);
const dv = new DataView(fat.buffer);
dv.setUint32(0, 0xcafebabe);
dv.setUint32(4, 2);
[[0x0100000c, offA, a.length], [0x01000007, offB, b.length]].forEach(([cpu, off, size], i) => {
  dv.setUint32(8 + i * 20, cpu); dv.setUint32(16 + i * 20, off); dv.setUint32(20 + i * 20, size); dv.setUint32(24 + i * 20, 12);
});
fat.set(a, offA);
fat.set(b, offB);
const fm = openImage(fat);
assert.equal(fm.arch, 'amd64');
assert.deepEqual(fm.fat, ['arm64', 'amd64']);
assert.ok(fm.read(fm.section('__gopclntab').addr, 4).every((x, i) => x === [0xf1, 0xff, 0xff, 0xff][i]), 'fat: dilim konumu düzeltildi');

// bölüm tablosu olmayan ELF (paketleyiciler): program başlıklarıyla okunur
const bare = buildContainer({ format: 'elf', sections: [{ name: '.text', data: new Uint8Array(64).fill(0x90), exec: true }, { name: '.data', data: new Uint8Array(32), write: true }], noSectionHeaders: true });
const bi = openImage(bare.bytes);
assert.equal(bi.noSections, true);
assert.ok(bi.regions.length === 2 && bi.regions[0].exec);

// tanınmayan / bozuk girdi
assert.equal(detectFormat(new TextEncoder().encode('#!/bin/sh\necho hi\n')), null);
assert.throws(() => openImage(new Uint8Array(100)));
const cut = fixture('basic.linux-amd64.gz').slice(0, 4096);
const partial = openImage(cut);
assert.equal(partial.format, 'elf');
console.log(`formats: ELF/PE/Mach-O, fat, BE, bölümsüz ELF, ${syms.symbols.length} sembol`);
