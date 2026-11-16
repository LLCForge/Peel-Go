// Gizli dizge geri kazanımı ve x86-64 öykünücüsü: çözücü komut anlamları, aile sınıflandırması, "tahmin yok"
// (bilinmeyen veri → çözülemedi), sonsuz döngüde bütçe sınırı ve amd64 dışı mimaride atlama.
import assert from 'node:assert/strict';
import { decode, format } from '../src/core/x86.js';
import { createEmu, K } from '../src/core/emu.js';
import { recoverLiterals, classify } from '../src/core/literals.js';
import { buildGoBinary } from '../src/core/synth.js';
import { openImage } from '../src/core/container.js';
import { findPclntab } from '../src/core/pclntab.js';
import { fixture, manifest, synthetic } from './helpers.js';

const bytes = (...b) => Uint8Array.from(b);
// çözücü: uzunluklar ve işlenenler
const cases = [
  [[0x48, 0x8d, 0x05, 0x10, 0, 0, 0], 'lea rax, [0x1017]'],
  [[0x0f, 0xb6, 0x4c, 0x04, 0x48], 'movzx rcx:4, [rsp+rax*1+0x48]'],
  [[0x41, 0x88, 0x54, 0x24, 0x08], 'mov [r12+0x8], rdx:1'],
  [[0xf3, 0x44, 0x0f, 0x6f, 0x36], 'movx xmm14, [rsi]'],
  [[0x49, 0x3b, 0x66, 0x10], 'cmp rsp, [r14+0x10]'],
  [[0x7c, 0xf0], 'jl 0xff2'],
  [[0x48, 0xc7, 0x44, 0x24, 0x18, 0xff, 0xff, 0xff, 0xff], 'mov [rsp+0x18], 0xffffffffffffffff'],
];
for (const [b, want] of cases) assert.equal(format(decode(bytes(...b), 0, 0x1000)), want);
assert.equal(decode(bytes(0xf0, 0x48, 0x0f, 0xb1, 0x0a), 0, 0), null, 'lock önekli komut desteklenmez');
// 32 bit kip: 0x40-0x4f inc/dec, [disp32] mutlak
assert.equal(format(decode(bytes(0x8d, 0x05, 0x00, 0x20, 0x00, 0x00), 0, 0x1000, false)), 'lea rax:4, [0x2000]');
assert.equal(decode(bytes(0x40), 0, 0, false).op, 'inc');

// öykünücü anlamları: tek tek komut (küçük bir ELF içinde)
function runCode(code, setup = () => {}) {
  const { bytes: bin } = buildGoBinary({ funcs: [{ name: 'main.f', size: 256, code: () => Uint8Array.from([...code, 0xc3]) }] });
  const img = openImage(bin);
  const emu = createEmu(img, { funcAt: () => null });
  const st = emu.newState(0x401000);
  setup(st);
  const end = emu.runPath(st, { maxSteps: 1000, fork: () => {}, onCall: () => ({}) });
  return { st, end };
}
const r = (st, i) => (st.regs[i].m === 0xffffffffffffffffn ? st.regs[i].v : null);
// lea r32 negatif yerdeğiştirme: 32 bitte kırpılır (BigInt hassasiyeti)
let { st } = runCode([0xb8, 8, 0, 0, 0, 0x8d, 0x40, 0xc4]); // mov eax,8 ; lea eax,[rax-60]
assert.equal(r(st, 0), 0xffffffccn);
// movzx: üst bitler bilinen sıfır; xor r,r bilinmeyeni de sıfırlar; 8 bit yazma üstü korur
({ st } = runCode([0x31, 0xc9, 0xb1, 0x7f, 0x0f, 0xb6, 0xd1]));
assert.equal(r(st, 2), 0x7fn);
({ st } = runCode([0xb0, 0x41], (s) => { s.regs[0] = K(0x1122334455667700n); }));
assert.equal(r(st, 0), 0x1122334455667741n);
// bilinmeyen yazmaç: kısmi bilgi bayt düzeyinde korunur
({ st } = runCode([0x48, 0x31, 0xd8], (s) => { s.regs[0] = { v: 0xffn, m: 0xffn }; s.regs[3] = K(0x0fn); }));
assert.equal(st.regs[0].m & 0xffn, 0xffn);
assert.equal(st.regs[0].v & 0xffn, 0xf0n);
// bayraklar: cmp + jl alınır / alınmaz
({ st } = runCode([0xb8, 5, 0, 0, 0, 0x83, 0xf8, 0x07, 0x7c, 0x02, 0x31, 0xc0]));
assert.equal(r(st, 0), 5n, 'jl alınmalıydı');
// rol/imul/div
({ st } = runCode([0xb8, 0x81, 0, 0, 0, 0xd0, 0xc0, 0x6b, 0xc0, 0x03, 0x31, 0xd2, 0xb9, 7, 0, 0, 0, 0xf7, 0xf1]));
assert.equal(r(st, 0), BigInt(Math.floor((((0x81 << 1) & 0xff | 1) * 3) / 7)));
// bilinmeyen koşul → çatal
let forks = 0;
{
  const { bytes: bin } = buildGoBinary({ funcs: [{ name: 'main.f', size: 64, code: () => bytes(0x48, 0x85, 0xc0, 0x74, 0x01, 0x90, 0xc3) }] });
  const img = openImage(bin);
  const emu = createEmu(img, { funcAt: () => null });
  emu.runPath(emu.newState(0x401000), { maxSteps: 100, fork: () => forks++, onCall: () => ({}) });
}
assert.equal(forks, 1);

// sentetik gizli dizge: kurtarılır, aile 'simple'
const syn = synthetic({ literal: 'harmless-literal.peel-fixture.test' });
const img = openImage(syn.bytes);
const { tab } = findPclntab(img);
const lit = recoverLiterals(img, tab.funcs);
assert.equal(lit.literals.length, 1);
assert.equal(lit.literals[0].value, 'harmless-literal.peel-fixture.test');
assert.equal(lit.literals[0].family, 'simple');
assert.equal(lit.literals[0].func, 'main.decode');

// tahmin yok: dizge baytları argümandan (bilinmeyen) geliyorsa "çözülemedi"
const unk = buildGoBinary({
  funcs: [
    { name: 'runtime.slicebytetostring' },
    {
      name: 'main.decodeArg',
      size: 96,
      code: (entry, ctx) => {
        // xor döngüsü RBX'in gösterdiği (bilinmeyen) bayt üzerinde, sonra string(b)
        const c = [0x31, 0xc9, 0x80, 0x34, 0x0b, 0x5a, 0x48, 0xff, 0xc1, 0x48, 0x83, 0xf9, 0x08, 0x7c, 0xf3, 0x31, 0xc0, 0xb9, 8, 0, 0, 0];
        const rel = ctx.fn['runtime.slicebytetostring'] - (entry + c.length + 5);
        return Uint8Array.from([...c, 0xe8, rel & 0xff, (rel >> 8) & 0xff, (rel >> 16) & 0xff, (rel >>> 24) & 0xff, 0xc3]);
      },
    },
  ],
});
const ui = openImage(unk.bytes);
const ur = recoverLiterals(ui, findPclntab(ui).tab.funcs);
assert.equal(ur.literals.length, 0, 'bilinmeyen bayt tahmin edilmemeli');
assert.equal(ur.unresolved.length, 1);
assert.match(ur.unresolved[0].reason, /unknown/);

// sonsuz döngü: bütçe sınırında durur, hızla
const loop = buildGoBinary({ funcs: [{ name: 'runtime.slicebytetostring' }, { name: 'main.spin', size: 64, code: (entry, ctx) => { const rel = ctx.fn['runtime.slicebytetostring'] - (entry + 7); return bytes(0x31, 0xc0, 0xeb, 0xfe, 0x90, 0x90, 0x90, 0xe8, ...[0, 0, 0, 0].map((_, i) => ((rel - 5) >> (8 * i)) & 0xff)); } }] });
const li = openImage(loop.bytes);
const t0 = Date.now();
const lr = recoverLiterals(li, findPclntab(li).tab.funcs, { limits: { stepsPerRoot: 50_000, pathsPerRoot: 4, totalSteps: 100_000, timeMs: 5000, maxDepth: 2, maxRoots: 10, maxLen: 1024, perSite: 2 } });
assert.ok(Date.now() - t0 < 5000);
assert.ok(lr.steps <= 100_000 && lr.literals.length === 0);

// aile sınıflandırması (özellik vektörleri)
const F = (o) => ({ xor: 0, arith: 0, back: 0, indirect: 0, cmpImm: new Set(), idxMem: 0, grow: 0, steps: 10, ...o });
assert.equal(classify(F({ indirect: 20 }), 20), 'seed');
assert.equal(classify(F({ back: 9, cmpImm: new Set(['1', '2', '3', '4']), xor: 30 }), 30), 'split');
assert.equal(classify(F({ back: 9, idxMem: 18, xor: 18 }), 18), 'swap');
assert.equal(classify(F({ xor: 30 }), 30), 'shuffle');
assert.equal(classify(F({ back: 30, xor: 30 }), 30), 'simple');
assert.equal(classify(F({}), 10), 'plain');

// gerçek garble benzeri fixture: yedi dizge, beş aile; arm64 ikilide öykünme atlanır
const real = openImage(fixture('garblelike.linux-amd64.gz'));
const rr = recoverLiterals(real, findPclntab(real).tab.funcs);
assert.deepEqual(rr.literals.map((l) => [l.family, l.value]).sort(), manifest.literals.garble.map((l) => [l.family, l.value]).sort());
const arm = openImage(fixture('basic.linux-arm64.gz'));
assert.equal(recoverLiterals(arm, findPclntab(arm).tab.funcs).skipped, 'arch');
// gobfuscate tarzı maske xor
const gb = openImage(fixture('gobflike.linux-amd64.gz'));
assert.deepEqual(recoverLiterals(gb, findPclntab(gb).tab.funcs).literals.map((l) => l.value).sort(), [...manifest.literals.gobf].sort());
console.log(`literals: çözücü, öykünücü anlamları, ${rr.literals.length} gerçek gizli dizge (${rr.steps} komut, ${rr.ms} ms), tahmin yok, bütçe`);
