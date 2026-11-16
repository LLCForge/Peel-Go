// Arayüz örneği: zararsız, sentetik bir Go ikilisi (ELF amd64, pclntab 1.20). garble ile gizlenmiş bir programın
// izlerini taşır: karma görünümlü paket/fonksiyon adları, boşaltılmış modül bilgisi, sembol tablosu yok ve gizli bir
// dizge (yığına yazılan veri + anahtar, xor döngüsü, runtime.slicebytetostring). Gerçek bir program değildir: kod
// gövdeleri elle derlenmiş birkaç komuttur ve hiçbir yerde çalıştırılmaz. Dizge bir .test alan adıdır.
import { buildGoBinary, xorLiteralFunc, stringCallFunc } from './core/synth.js';

export const SAMPLE_NAME = 'sample-garbled.elf';
const enc = new TextEncoder();

export function sampleBytes() {
  const banner = 'peel sample: garbled Go binary';
  const rodata = enc.encode(`${banner}\0`);
  const { bytes } = buildGoBinary({
    format: 'elf',
    pclntab: '1.20',
    rodata,
    buildinfo: { version: 'go1.26.1', modinfo: '' },
    funcs: [
      { name: 'runtime.rt0_go', file: 'runtime/asm_amd64.s', line: 159 },
      { name: 'runtime.morestack_noctxt', file: 'runtime/asm_amd64.s', line: 625 },
      { name: 'runtime.slicebytetostring', file: 'runtime/string.go', line: 81 },
      { name: 'runtime.printstring', file: 'runtime/print.go', line: 251 },
      { name: 'runtime.main', file: 'runtime/proc.go', line: 145 },
      { name: 'Wq8eZtLp/kQ8wZr3T.Fx3qLm9P', file: 'Wq8eZtLp/kQ8wZr3T/Zx9qLm2V.go', line: 7 },
      { name: 'Wq8eZtLp/kQ8wZr3T.Yt5Kc0Vd', file: 'Wq8eZtLp/kQ8wZr3T/Zx9qLm2V.go', line: 11, size: 400, code: xorLiteralFunc('https://cdn.peel-fixture.test/cfg', 0x4d) },
      { name: 'Wq8eZtLp/kQ8wZr3T.(*Hx3kL2pm).Wn9qXb', file: 'Wq8eZtLp/kQ8wZr3T/Zx9qLm2V.go', line: 19 },
      { name: 'main.main', file: 'Wq8eZtLp/Qm4vN8sT.go', line: 5, size: 64, code: stringCallFunc(0, banner.length, 'Wq8eZtLp/kQ8wZr3T.Fx3qLm9P', ['Wq8eZtLp/kQ8wZr3T.Yt5Kc0Vd']) },
    ],
  });
  return bytes;
}
