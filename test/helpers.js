// Test yardımcıları: gerçek fixture'lar (gzip, test/fixtures/manifest.json) ve sentetik ikililer.
import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { buildGoBinary, xorLiteralFunc, stringCallFunc } from '../src/core/synth.js';

export const manifest = JSON.parse(readFileSync(new URL('./fixtures/manifest.json', import.meta.url), 'utf8'));

/** test/fixtures/<ad>.gz → Uint8Array */
export const fixture = (file) => new Uint8Array(gunzipSync(readFileSync(new URL(`./fixtures/${file}`, import.meta.url))));

export const RO = 'peel synthetic rodata string';

/** Küçük sentetik Go ikilisi: runtime.slicebytetostring, gizli dizgeli bir fonksiyon, main.main */
export function synthetic({ format = 'elf', bits = 64, le = true, pclntab = '1.20', buildinfo = { version: 'go1.21.4', modinfo: 'path\texample.com/syn\nmod\texample.com/syn\t(devel)\t\nbuild\tGOOS=linux\nbuild\tGOARCH=amd64\n' }, literal = 'https://syn.peel-fixture.test/x', names = null, files = true, ...rest } = {}) {
  const code64 = bits === 64 && le;
  const n = names ?? { lit: 'main.decode', main: 'main.main' };
  return buildGoBinary({
    format, bits, le, pclntab, buildinfo,
    rodata: new TextEncoder().encode(RO),
    funcs: [
      { name: 'runtime.slicebytetostring', file: files ? 'runtime/string.go' : '', line: files ? 81 : 0 },
      { name: 'runtime.printstring', file: files ? 'runtime/print.go' : '', line: files ? 251 : 0 },
      { name: n.lit, file: files ? 'example.com/syn/main.go' : '', line: files ? 10 : 0, size: 400, code: code64 && literal ? xorLiteralFunc(literal) : undefined },
      { name: n.main, file: files ? 'example.com/syn/main.go' : '', line: files ? 20 : 0, size: 64, code: code64 ? stringCallFunc(0, RO.length, 'runtime.printstring', [n.lit]) : undefined },
    ],
    ...rest,
  });
}
