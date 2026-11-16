// garble -literals (ve benzeri) dizge gizleme geri kazanımı, yalnızca amd64.
// Kökler: runtime.slicebytetostring'i doğrudan çağıran kullanıcı fonksiyonları (std dışı). Her kök, öykünücüde
// argümanlar bilinmez kabul edilerek baştan yürütülür; çözme gövdesi sabit veriden çalıştığı için bayt dizisi
// tamamen bilinir. slicebytetostring'e ulaşıldığında baytların HEPSİ biliniyorsa dizge kaydedilir; biri bile
// bilinmiyorsa "çözülemedi" olarak raporlanır (tahmin yok).
//
// Aile (garble'ın obfuscator'ları), çözme sırasında görülen yapıdan çıkarılır:
//   seed     her bayt için kapanış çağrısı (fnc(x)(y)(z)…), dolaylı çağrılar
//   split    switch tabanlı durum makinesi: döngü + çok sayıda sabit karşılaştırma + append
//   swap     döngüde, dizinleri bellekteki bir konum dizisinden gelen bayt takasları
//   shuffle  döngüsüz, bayt başına iki bellek okumasının xor'u
//   simple   döngüde anahtarla xor/add/sub (gobfuscate'in maske xor'u da bu aileye düşer)
//   plain    gizleme izi yok: sabit baytlardan string(b) dönüşümü
import { createEmu, K } from './emu.js';
import { isStdFunc } from './gonames.js';

export const LIMITS = { stepsPerRoot: 400_000, pathsPerRoot: 48, totalSteps: 6_000_000, timeMs: 12_000, maxDepth: 3, maxRoots: 4000, maxLen: 65_536, perSite: 8 };

const PANIC = /^runtime\.(?:panic|goPanic|throw|fatal|morestack|abort|unreachable|gopanic|sigpanic)/;

/** E8 rel32 çağrı hedefleri bu adrese giden fonksiyonlar (doğrusal tarama; komut sınırı denetlenmez, öykünme doğrular) */
function callers(img, funcs, target) {
  const out = [];
  for (const f of funcs) {
    const code = img.read(f.entry, f.end - f.entry);
    if (!code) continue;
    for (let i = code.indexOf(0xe8); i >= 0 && i + 5 <= code.length; i = code.indexOf(0xe8, i + 1)) {
      const rel = code[i + 1] | (code[i + 2] << 8) | (code[i + 3] << 16) | (code[i + 4] << 24);
      if (f.entry + i + 5 + rel === target) { out.push(f); break; }
    }
  }
  return out;
}

export function classify(f, n) {
  if (f.indirect >= 2) return 'seed';
  if (f.back >= 2 && f.cmpImm.size >= 3 && f.grow + f.arith + f.xor > 0) return 'split';
  if (f.back >= 1 && f.idxMem >= 2) return 'swap';
  if (f.back === 0 && f.xor >= Math.max(2, Math.floor(n / 2))) return 'shuffle';
  if (f.back >= 1 && f.xor + f.arith >= 1) return 'simple';
  return 'plain';
}

const printable = (b) => {
  try {
    const s = new TextDecoder('utf-8', { fatal: true }).decode(b);
    return { text: s, binary: /[\u0000-\u0008\u000e-\u001f\u007f]/.test(s) };
  } catch {
    return { text: [...b].map((x) => (x >= 0x20 && x < 0x7f ? String.fromCharCode(x) : `\\x${x.toString(16).padStart(2, '0')}`)).join(''), binary: true };
  }
};

/**
 * @param {object} img Image (amd64)
 * @param {Array<{entry,end,name}>} funcs pclntab fonksiyonları (entry'ye göre sıralı)
 * @returns {{ literals, unresolved, roots, steps, ms, skipped?: string }}
 */
export function recoverLiterals(img, funcs, { limits = LIMITS, signal = null } = {}) {
  const t0 = Date.now();
  const result = { literals: [], unresolved: [], roots: 0, steps: 0, ms: 0 };
  if (img.arch !== 'amd64') { result.skipped = 'arch'; return result; }
  const byName = new Map();
  for (const f of funcs) if (!byName.has(f.name)) byName.set(f.name, f);
  const s2s = byName.get('runtime.slicebytetostring');
  if (!s2s) { result.skipped = 'no-slicebytetostring'; return result; }
  const funcAt = (a) => {
    let lo = 0;
    let hi = funcs.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (a < funcs[mid].entry) hi = mid - 1;
      else if (a >= funcs[mid].end) lo = mid + 1;
      else return funcs[mid];
    }
    return null;
  };
  const user = funcs.filter((f) => !isStdFunc(f.name));
  const roots = callers(img, user, s2s.entry).slice(0, limits.maxRoots);
  result.roots = roots.length;
  const emu = createEmu(img, { funcAt });
  const { RAX, RBX, RCX, RDI, RSI } = emu.regs;
  const reg = (st, r) => st.regs[r];
  const num = (x) => (emu.known(x) ? Number(x.v) : null);
  const sizeOfType = (st, t) => {
    if (t == null) return null;
    const x = st.mem.read(t, 8);
    return emu.known(x) && x.v < 1n << 32n ? Number(x.v) : null;
  };
  const sites = new Map();
  let total = 0;

  const model = {
    'runtime.slicebytetostring': (st, ins) => {
      const p = num(reg(st, RBX));
      const n = num(reg(st, RCX));
      const at = funcAt(ins.addr);
      const where = { site: ins.addr, func: at?.name ?? '', root: st.root };
      const obf = st.feat.xor + st.feat.arith + st.feat.back + st.feat.indirect > 0;
      const bytes = p != null && n != null && n <= limits.maxLen ? st.mem.bytes(p, n) : null;
      if (!bytes) {
        if (obf) result.unresolved.push({ ...where, reason: n == null || p == null ? 'unknown-pointer' : n > limits.maxLen ? 'too-long' : 'unknown-bytes' });
      } else {
        const list = sites.get(ins.addr) ?? [];
        const { text, binary } = printable(bytes);
        if (!list.some((x) => x.value === text) && list.length < limits.perSite) {
          const lit = { ...where, value: text, length: n, binary, family: classify(st.feat, n), clean: st.dirty === 0 };
          list.push(lit);
          sites.set(ins.addr, list);
          result.literals.push(lit);
        }
      }
      // dönüş: öbekte kopya
      const a = n != null && n <= limits.maxLen ? emu.zeroAlloc(st, n) : null;
      if (a != null && p != null) for (let i = 0; i < n; i++) { const b = st.mem.byte(p + i); st.mem.setByte(a + i, Math.max(0, b), b >= 0); }
      st.regs[RAX] = a != null ? K(a) : { v: 0n, m: 0n };
      st.regs[RBX] = n != null ? K(n) : { v: 0n, m: 0n };
      st.feat = { xor: 0, arith: 0, back: 0, indirect: 0, cmpImm: new Set(), idxMem: 0, grow: 0, steps: 0 };
      return { handled: true };
    },
    'runtime.stringtoslicebyte': (st) => {
      const buf = num(reg(st, RAX));
      const p = num(reg(st, RBX));
      const n = num(reg(st, RCX));
      if (p == null || n == null || n > limits.maxLen) return {};
      const dst = buf && n <= 32 ? buf : emu.zeroAlloc(st, n);
      for (let i = 0; i < n; i++) { const b = st.mem.byte(p + i); st.mem.setByte(dst + i, Math.max(0, b), b >= 0); }
      st.regs[RAX] = K(dst);
      st.regs[RBX] = K(n);
      st.regs[RCX] = K(buf && n <= 32 ? 32 : n);
      return { handled: true };
    },
    'runtime.growslice': (st) => {
      const old = num(reg(st, RAX));
      const newLen = num(reg(st, RBX));
      const oldCap = num(reg(st, RCX));
      const added = num(reg(st, RDI));
      const es = sizeOfType(st, num(reg(st, RSI)));
      if (newLen == null || oldCap == null || added == null || es == null || newLen > limits.maxLen) return {};
      const cap = Math.max(newLen, oldCap * 2, 8);
      const a = emu.zeroAlloc(st, cap * es);
      const oldLen = newLen - added;
      if (old != null) for (let i = 0; i < oldLen * es; i++) { const b = st.mem.byte(old + i); st.mem.setByte(a + i, Math.max(0, b), b >= 0); }
      st.regs[RAX] = K(a);
      st.regs[RBX] = K(newLen);
      st.regs[RCX] = K(cap);
      st.feat.grow++;
      return { handled: true };
    },
    'runtime.makeslice': (st) => {
      const es = sizeOfType(st, num(reg(st, RAX)));
      const cap = num(reg(st, RCX));
      if (es == null || cap == null || cap * es > limits.maxLen * 8) return {};
      st.regs[RAX] = K(emu.zeroAlloc(st, cap * es));
      return { handled: true };
    },
    'runtime.newobject': (st) => {
      const es = sizeOfType(st, num(reg(st, RAX)));
      if (es == null || es > 1 << 20) return {};
      st.regs[RAX] = K(emu.zeroAlloc(st, es));
      return { handled: true };
    },
    'runtime.memmove': (st) => {
      const to = num(reg(st, RAX));
      const from = num(reg(st, RBX));
      const n = num(reg(st, RCX));
      if (to == null || from == null || n == null || n > limits.maxLen * 8) return {};
      const tmp = [];
      for (let i = 0; i < n; i++) tmp.push(st.mem.byte(from + i));
      tmp.forEach((b, i) => st.mem.setByte(to + i, Math.max(0, b), b >= 0));
      return { handled: true };
    },
    'runtime.memclrNoHeapPointers': (st) => {
      const p = num(reg(st, RAX));
      const n = num(reg(st, RBX));
      if (p == null || n == null || n > limits.maxLen * 8) return {};
      for (let i = 0; i < n; i++) st.mem.setByte(p + i, 0, true);
      return { handled: true };
    },
  };

  const onCall = (st, ins, target, fn) => {
    if (!fn) return {};
    const name = fn.name;
    if (PANIC.test(name)) return { end: 'panic' };
    if (name === 'runtime.duffzero' || name === 'runtime.duffcopy') return { descend: true };
    if (target !== fn.entry) return {};
    if (model[name]) return model[name](st, ins);
    if (name.startsWith('runtime.mallocgc')) {
      const n = num(reg(st, RAX));
      if (n == null || n > 1 << 20) return {};
      st.regs[RAX] = K(emu.zeroAlloc(st, n));
      return { handled: true };
    }
    if (/^runtime\.gcWriteBarrier|^runtime\.wb(?:Zero|Move)$/.test(name)) return { handled: true };
    if (!isStdFunc(name) && st.depth < limits.maxDepth) return { descend: true };
    return {};
  };

  for (const root of roots) {
    if (signal?.aborted) break;
    if (Date.now() - t0 > limits.timeMs || total > limits.totalSteps) { result.truncated = true; break; }
    const queue = [];
    const start = emu.newState(root.entry);
    start.root = root.name;
    queue.push(start);
    let paths = 0;
    let steps = 0;
    while (queue.length && paths < limits.pathsPerRoot && steps < limits.stepsPerRoot) {
      const st = queue.pop();
      paths++;
      const before = st.steps;
      const end = emu.runPath(st, {
        maxSteps: before + Math.min(limits.stepsPerRoot - steps, 200_000),
        fork: (s) => { if (queue.length + paths < limits.pathsPerRoot) queue.push(s); },
        onCall,
      });
      steps += st.steps - before;
      const obf = st.feat.xor + st.feat.arith + st.feat.back + st.feat.indirect > 0;
      if ((end.reason === 'unsupported' || end.reason === 'budget') && obf && st.feat.steps > 8) {
        const code = img.read(end.at, 6);
        result.unresolved.push({ site: end.at, func: funcAt(end.at)?.name ?? '', root: root.name, reason: end.reason === 'budget' ? 'budget' : `unsupported ${code ? [...code].map((b) => b.toString(16).padStart(2, '0')).join(' ') : ''}` });
      }
    }
    total += steps;
  }
  // aynı yerden çözülmüş bir dizge varsa o yerin "çözülemedi" kaydı düşer
  const solved = new Set(result.literals.map((l) => l.site));
  const seen = new Set();
  result.unresolved = result.unresolved.filter((u) => !solved.has(u.site) && !seen.has(u.site) && seen.add(u.site));
  result.literals.sort((a, b) => a.site - b.site);
  result.steps = total;
  result.ms = Date.now() - t0;
  return result;
}
