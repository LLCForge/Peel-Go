// Sınırlı x86-64 öykünücüsü. Hedef ikili ASLA çalıştırılmaz: komutlar bu dosyada tek tek yorumlanır, sistem çağrısı
// yoktur, bellek yalnızca ikilinin kendi bölümleri + öykünücünün yığın/öbek alanıdır.
//
// Her değer { v: BigInt, m: BigInt } çiftidir: m bilinen bitlerin maskesi. Bilinmeyen bir şey asla tahmin edilmez;
// bilinmeyen koşula bağlı dallanmada yol çatallanır (sınırlı), bilinmeyen adrese yazma yolu "kirli" işaretler.
// Go ABIInternal: argümanlar RAX, RBX, RCX, RDI, RSI, R8–R11; R14 = g, X15 = 0; çağrıdan sonra RSP, RBP, R14, R15 korunur.
import { decode } from './x86.js';

const M64 = 0xffff_ffff_ffff_ffffn;
const MASK = { 1: 0xffn, 2: 0xffffn, 4: 0xffff_ffffn, 8: M64 };
const SIGN = { 1: 0x80n, 2: 0x8000n, 4: 0x8000_0000n, 8: 0x8000_0000_0000_0000n };
const BITS = { 1: 8, 2: 16, 4: 32, 8: 64 };
export const K = (v) => ({ v: BigInt.asUintN(64, BigInt(v)), m: M64 });
export const U = { v: 0n, m: 0n };
const known = (x, size = 8) => (x.m & MASK[size]) === MASK[size];
const RAX = 0; const RCX = 1; const RDX = 2; const RBX = 3; const RSP = 4; const RBP = 5; const RSI = 6; const RDI = 7; const R14 = 14; const R15 = 15;
const ARG_REGS = [RAX, RBX, RCX, RDI, RSI, 8, 9, 10, 11];

export const STACK_TOP = 0x7ffe_0000_0000;
export const HEAP_BASE = 0x7e00_0000_0000;
export const G_BASE = 0x7d00_0000_0000;
const PAGE = 4096;

/** Sayfalı bellek: { d: değer baytları, k: bilinen baytlar } ; ikilinin bölgeleri ilk yazmada kopyalanır */
class Mem {
  constructor(img) { this.img = img; this.pages = new Map(); }
  clone() {
    const m = new Mem(this.img);
    for (const [k, p] of this.pages) m.pages.set(k, { d: p.d.slice(), k: p.k.slice() });
    return m;
  }
  page(pn) {
    let p = this.pages.get(pn);
    if (p) return p;
    p = { d: new Uint8Array(PAGE), k: new Uint8Array(PAGE) };
    const base = pn * PAGE;
    // ikiliye ait sayfa: dosya (ve bss sıfırları) bilinen değerdir
    for (let i = 0; i < PAGE;) {
      const r = this.img.regionOf(base + i);
      if (!r) { i++; continue; }
      const n = Math.min(PAGE - i, r.addr + r.memSize - (base + i));
      const b = this.img.read(base + i, n);
      if (b) { p.d.set(b, i); p.k.fill(1, i, i + n); }
      i += n;
    }
    // öykünücünün kendi alanları: g yapısı ve öbek sıfırla başlar (bilinen), yığın bilinmez
    if (base >= G_BASE && base < G_BASE + 0x10000) p.k.fill(1);
    this.pages.set(pn, p);
    return p;
  }
  byte(a) {
    const pn = Math.floor(a / PAGE);
    const p = this.pages.get(pn);
    if (p) return p.k[a % PAGE] ? p.d[a % PAGE] : -1;
    if (a >= G_BASE && a < G_BASE + 0x10000) return 0;
    const b = this.img.read(a, 1);
    return b ? b[0] : -1;
  }
  setByte(a, v, k) {
    const p = this.page(Math.floor(a / PAGE));
    p.d[a % PAGE] = v;
    p.k[a % PAGE] = k ? 1 : 0;
  }
  read(a, size) {
    let v = 0n;
    let m = 0n;
    for (let i = size - 1; i >= 0; i--) {
      const b = this.byte(a + i);
      v <<= 8n;
      m <<= 8n;
      if (b >= 0) { v |= BigInt(b); m |= 0xffn; }
    }
    return { v, m };
  }
  write(a, size, x) {
    for (let i = 0; i < size; i++) {
      const sh = BigInt(8 * i);
      this.setByte(a + i, Number((x.v >> sh) & 0xffn), ((x.m >> sh) & 0xffn) === 0xffn);
    }
  }
  bytes(a, n) {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) { const b = this.byte(a + i); if (b < 0) return null; out[i] = b; }
    return out;
  }
  invalidate(a, n) { for (let i = 0; i < n; i++) this.setByte(a + i, 0, false); }
}

const ccEval = (cc, f) => {
  const not = (x) => (x == null ? null : !x);
  const or = (a, b) => (a === true || b === true ? true : a == null || b == null ? null : false);
  const neq = (a, b) => (a == null || b == null ? null : a !== b);
  switch (cc) {
    case 0: return f.of; case 1: return not(f.of);
    case 2: return f.cf; case 3: return not(f.cf);
    case 4: return f.zf; case 5: return not(f.zf);
    case 6: return or(f.cf, f.zf); case 7: return not(or(f.cf, f.zf));
    case 8: return f.sf; case 9: return not(f.sf);
    case 10: return f.pf; case 11: return not(f.pf);
    case 12: return neq(f.sf, f.of); case 13: return not(neq(f.sf, f.of));
    case 14: return or(f.zf, neq(f.sf, f.of)); case 15: return not(or(f.zf, neq(f.sf, f.of)));
    default: return null;
  }
};
const parity = (v) => { let x = Number(v & 0xffn); x ^= x >> 4; x ^= x >> 2; x ^= x >> 1; return (x & 1) === 0; };
const UNK_FLAGS = { cf: null, zf: null, sf: null, of: null, pf: null };

export class EmuError extends Error {}

/**
 * Öykünücü. o.funcAt(addr) → { name, entry } | null ; o.model(name) → işleyici | undefined ;
 * o.descend(name) → çağrıya inilsin mi ; o.onStop(state, reason)
 */
export function createEmu(img, o) {
  const cache = new Map();
  const fetch = (pc) => {
    let ins = cache.get(pc);
    if (ins !== undefined) return ins;
    const b = img.read(pc, 15) ?? (() => { const r = img.regionOf(pc); return r ? img.read(pc, Math.min(15, r.addr + r.memSize - pc)) : null; })();
    ins = b && img.regionOf(pc)?.exec ? decode(b, 0, pc) : null;
    if (cache.size > 200_000) cache.clear();
    cache.set(pc, ins);
    return ins;
  };

  function newState(entry) {
    const regs = Array.from({ length: 16 }, () => U);
    const xmm = Array.from({ length: 16 }, () => [U, U]);
    xmm[15] = [K(0), K(0)];
    const st = { regs, xmm, flags: { ...UNK_FLAGS }, mem: new Mem(img), pc: entry, depth: 0, heap: HEAP_BASE, steps: 0, dirty: 0, fromMem: new Uint8Array(16), feat: newFeat(), ret: [] };
    regs[RSP] = K(STACK_TOP - 0x1000);
    regs[R14] = K(G_BASE);
    // dönüş adresi: kök fonksiyondan RET yolun sonudur
    st.mem.write(STACK_TOP - 0x1000, 8, K(0xdead_0000));
    return st;
  }
  const newFeat = () => ({ xor: 0, arith: 0, back: 0, indirect: 0, cmpImm: new Set(), idxMem: 0, grow: 0, steps: 0 });
  function clone(st) {
    return {
      ...st, regs: st.regs.slice(), xmm: st.xmm.map((x) => x.slice()), flags: { ...st.flags }, mem: st.mem.clone(), fromMem: st.fromMem.slice(),
      feat: { ...st.feat, cmpImm: new Set(st.feat.cmpImm) }, ret: st.ret.slice(),
    };
  }

  // ── işlenenler ──
  const getReg = (st, op) => {
    const x = st.regs[op.r];
    if (op.hi) return { v: (x.v >> 8n) & 0xffn, m: (x.m >> 8n) & 0xffn };
    return { v: x.v & MASK[op.size], m: x.m & MASK[op.size] };
  };
  const setReg = (st, op, x) => {
    const r = op.r;
    st.fromMem[r] = 0;
    if (op.hi) {
      const cur = st.regs[r];
      st.regs[r] = { v: (cur.v & ~0xff00n) | ((x.v & 0xffn) << 8n), m: (cur.m & ~0xff00n) | ((x.m & 0xffn) << 8n) };
      return;
    }
    if (op.size >= 4) { st.regs[r] = { v: x.v & MASK[op.size], m: (x.m & MASK[op.size]) | (M64 ^ MASK[op.size]) }; return; }
    const cur = st.regs[r];
    const mk = MASK[op.size];
    st.regs[r] = { v: (cur.v & ~mk) | (x.v & mk), m: (cur.m & ~mk) | (x.m & mk) };
  };
  // adres hesabı BigInt'tir (lea ile 32 bit kırpma ve negatif yerdeğiştirmeler kesin kalsın)
  const addrBig = (st, op) => {
    let v = BigInt.asUintN(64, op.disp);
    let ok = true;
    if (op.base >= 0) { const b = st.regs[op.base]; if (!known(b)) ok = false; v += b.v; if (st.fromMem[op.base]) st.feat.idxMem++; }
    if (op.index >= 0) { const x = st.regs[op.index]; if (!known(x)) ok = false; v += x.v * BigInt(op.scale); if (st.fromMem[op.index]) st.feat.idxMem++; }
    if (op.seg) ok = false;
    return ok ? BigInt.asUintN(64, v) : null;
  };
  const addrOf = (st, op) => {
    const v = addrBig(st, op);
    return v == null || v > 0x7fff_ffff_ffffn ? null : Number(v);
  };
  const read = (st, op, size = op.size) => {
    if (op.t === 'reg') return getReg(st, op);
    if (op.t === 'imm') return { v: BigInt.asUintN(64, op.v) & MASK[size], m: MASK[size] };
    if (op.t === 'mem') { const a = addrOf(st, op); return a == null ? U : st.mem.read(a, size); }
    throw new EmuError('işlenen');
  };
  const write = (st, op, x, size = op.size) => {
    if (op.t === 'reg') { setReg(st, { ...op, size }, x); return; }
    if (op.t === 'mem') {
      const a = addrOf(st, op);
      if (a == null) { st.dirty++; return; }
      st.mem.write(a, size, x);
      return;
    }
    throw new EmuError('yazılamaz işlenen');
  };

  // ── aritmetik (bilinmeyen girdiler bilinmeyen sonuç verir; xor/and/or bit düzeyinde kısmen bilinir) ──
  function arith(st, op, a, b, size) {
    const mk = MASK[size];
    const full = known(a, size) && known(b, size);
    const f = st.flags;
    let r;
    switch (op) {
      case 'xor': r = { v: (a.v ^ b.v) & mk, m: a.m & b.m & mk }; break;
      case 'and': r = { v: a.v & b.v & mk, m: ((a.m & b.m) | (a.m & ~a.v) | (b.m & ~b.v)) & mk }; break;
      case 'or': r = { v: (a.v | b.v) & mk, m: ((a.m & b.m) | (a.m & a.v) | (b.m & b.v)) & mk }; break;
      case 'add': case 'sub': case 'cmp': case 'adc': case 'sbb': {
        if (!full || ((op === 'adc' || op === 'sbb') && f.cf == null)) { r = U; break; }
        const c = op === 'adc' || op === 'sbb' ? BigInt(f.cf ? 1 : 0) : 0n;
        const sum = op === 'add' || op === 'adc' ? a.v + b.v + c : a.v - b.v - c;
        r = { v: BigInt.asUintN(BITS[size], sum), m: mk };
        const sign = SIGN[size];
        st.flags = {
          cf: op === 'add' || op === 'adc' ? sum > mk : a.v < b.v + c,
          zf: r.v === 0n,
          sf: (r.v & sign) !== 0n,
          of: op === 'add' || op === 'adc' ? ((~(a.v ^ b.v) & (a.v ^ r.v) & sign) !== 0n) : (((a.v ^ b.v) & (a.v ^ r.v) & sign) !== 0n),
          pf: parity(r.v),
        };
        return r;
      }
      default: throw new EmuError(op);
    }
    if (known(r, size)) st.flags = { cf: false, of: false, zf: r.v === 0n, sf: (r.v & SIGN[size]) !== 0n, pf: parity(r.v) };
    else st.flags = { ...UNK_FLAGS, cf: false, of: false };
    return r;
  }

  function shift(st, op, a, cnt, size) {
    const bits = BITS[size];
    const c = Number(cnt.v & (size === 8 ? 63n : 31n));
    if (!known(cnt, 1)) return U;
    if (c === 0) return a;
    if (!known(a, size)) { st.flags = { ...UNK_FLAGS }; return U; }
    const mk = MASK[size];
    const bc = BigInt(c);
    let r;
    let cf;
    if (op === 'shl') { r = (a.v << bc) & mk; cf = ((a.v >> BigInt(bits - c)) & 1n) === 1n; }
    else if (op === 'shr') { r = a.v >> bc; cf = ((a.v >> BigInt(c - 1)) & 1n) === 1n; }
    else if (op === 'sar') { r = BigInt.asUintN(bits, BigInt.asIntN(bits, a.v) >> bc); cf = ((BigInt.asIntN(bits, a.v) >> BigInt(c - 1)) & 1n) === 1n; }
    else {
      const k = BigInt(c % bits);
      r = op === 'rol' ? ((a.v << k) | (a.v >> BigInt(bits) - k)) & mk : ((a.v >> k) | (a.v << BigInt(bits) - k)) & mk;
      st.flags = { ...st.flags, cf: op === 'rol' ? (r & 1n) === 1n : (r & SIGN[size]) !== 0n, of: null };
      return { v: r, m: mk };
    }
    st.flags = { cf, zf: r === 0n, sf: (r & SIGN[size]) !== 0n, of: null, pf: parity(r) };
    return { v: r, m: mk };
  }

  /** Bilinmeyen çağrı: çağıranın korumadığı yazmaçlar ve yığındaki argüman bölgeleri bilinmez olur */
  function clobber(st) {
    for (const r of ARG_REGS) {
      const x = st.regs[r];
      if (known(x)) {
        const a = Number(x.v);
        if (a >= STACK_TOP - 0x100000 && a < STACK_TOP) st.mem.invalidate(a, 256);
      }
    }
    for (let i = 0; i < 16; i++) if (i !== RSP && i !== RBP && i !== R14 && i !== R15) st.regs[i] = U;
    for (let i = 0; i < 15; i++) st.xmm[i] = [U, U];
    st.fromMem.fill(0);
    st.flags = { ...UNK_FLAGS };
  }
  const alloc = (st, n) => {
    const a = st.heap;
    st.heap += Math.ceil(Math.max(1, n) / 16) * 16 + 16;
    return a;
  };
  /** öbekte n sıfır bayt (bilinen) */
  const zeroAlloc = (st, n) => {
    const a = alloc(st, n);
    for (let i = 0; i < n; i++) st.mem.setByte(a + i, 0, true);
    return a;
  };

  /**
   * Bir yolu yürütür. Dönüş: { reason, at } — 'ret' | 'budget' | 'unsupported' | 'unknown-branch' (çatal) | 'panic' | 'stop' | 'unknown-target'
   * fork(st) ile çatal yığına eklenir.
   */
  function runPath(st, { maxSteps, fork, onCall }) {
    while (st.steps < maxSteps) {
      const ins = fetch(st.pc);
      if (!ins) return { reason: 'unsupported', at: st.pc };
      st.steps++;
      st.feat.steps++;
      const next = st.pc + ins.len;
      const [d, s] = ins.ops;
      const size = ins.size;
      switch (ins.op) {
        case 'nop': break;
        case 'mov': write(st, d, read(st, s, size), size); if (d.t === 'reg' && s.t === 'mem' && size === 1) st.fromMem[d.r] = 1; break;
        case 'movzx': case 'movsx': {
          const ss = s.size;
          const x = read(st, s, ss);
          // sıfır genişletme: üst bitler bilinen sıfırdır
          let r = { v: x.v, m: x.m | (M64 ^ MASK[ss]) };
          if (ins.op === 'movsx' && known(x, ss)) r = { v: BigInt.asUintN(64, BigInt.asIntN(BITS[ss], x.v)), m: M64 };
          else if (ins.op === 'movsx') r = U;
          write(st, d, r, size);
          if (s.t === 'mem' && d.t === 'reg') st.fromMem[d.r] = 1;
          break;
        }
        case 'lea': {
          const a = addrBig(st, s);
          write(st, d, a == null ? U : K(a), size);
          break;
        }
        case 'add': case 'or': case 'adc': case 'sbb': case 'and': case 'sub': case 'xor': case 'cmp': case 'test': {
          // xor r,r / sub r,r: her zaman sıfır
          if ((ins.op === 'xor' || ins.op === 'sub') && d.t === 'reg' && s.t === 'reg' && d.r === s.r && !d.hi && !s.hi) {
            write(st, d, K(0), size);
            st.flags = { cf: false, of: false, zf: true, sf: false, pf: true };
            break;
          }
          const a = read(st, d, size);
          const b = read(st, s, size);
          const r = arith(st, ins.op === 'test' ? 'and' : ins.op, a, b, size);
          if (ins.op === 'xor') st.feat.xor++;
          // bellekten okunmuş bayt üzerinde toplama/çıkarma: anahtarla çözme izi
          const byteish = size === 1 || d.t === 'mem' || s.t === 'mem' || (d.t === 'reg' && st.fromMem[d.r]) || (s.t === 'reg' && st.fromMem[s.r]);
          if ((ins.op === 'add' || ins.op === 'sub') && byteish) st.feat.arith++;
          if (ins.op === 'cmp' && s.t === 'imm') st.feat.cmpImm.add(String(s.v));
          if (ins.op !== 'cmp' && ins.op !== 'test') write(st, d, r, size);
          break;
        }
        case 'inc': case 'dec': {
          const a = read(st, d, size);
          const cf = st.flags.cf;
          const r = arith(st, ins.op === 'inc' ? 'add' : 'sub', a, K(1), size);
          st.flags.cf = cf;
          write(st, d, r, size);
          break;
        }
        case 'neg': case 'not': {
          const a = read(st, d, size);
          if (!known(a, size)) { write(st, d, U, size); if (ins.op === 'neg') st.flags = { ...UNK_FLAGS }; break; }
          if (ins.op === 'not') { write(st, d, { v: ~a.v & MASK[size], m: MASK[size] }, size); break; }
          const r = arith(st, 'sub', K(0), a, size);
          write(st, d, r, size);
          break;
        }
        case 'shl': case 'shr': case 'sar': case 'rol': case 'ror':
          write(st, d, shift(st, ins.op, read(st, d, size), read(st, s, 1), size), size);
          break;
        case 'imul': {
          const a = read(st, ins.ops[1], size);
          const b = read(st, ins.ops[2], size);
          if (!known(a, size) || !known(b, size)) { write(st, d, U, size); st.flags = { ...UNK_FLAGS }; break; }
          const bits = BITS[size];
          const full = BigInt.asIntN(bits, a.v) * BigInt.asIntN(bits, b.v);
          const r = BigInt.asUintN(bits, full);
          const ovf = BigInt.asIntN(bits, r) !== full;
          st.flags = { cf: ovf, of: ovf, zf: null, sf: null, pf: null };
          write(st, d, { v: r, m: MASK[size] }, size);
          break;
        }
        case 'mul1': case 'imul1': case 'div': case 'idiv': {
          const bits = BITS[size];
          const src = read(st, d, size);
          const lo = read(st, { t: 'reg', r: RAX, size }, size);
          const hi = read(st, { t: 'reg', r: RDX, size }, size);
          const loOp = { t: 'reg', r: RAX, size: size === 1 ? 1 : size };
          const hiOp = size === 1 ? { t: 'reg', r: RAX, size: 1, hi: true } : { t: 'reg', r: RDX, size };
          if (size === 1) return { reason: 'unsupported', at: st.pc };
          if (!known(src, size) || !known(lo, size) || ((ins.op === 'div' || ins.op === 'idiv') && !known(hi, size))) {
            write(st, loOp, U, size); write(st, hiOp, U, size); st.flags = { ...UNK_FLAGS }; break;
          }
          if (ins.op === 'mul1' || ins.op === 'imul1') {
            const p = ins.op === 'mul1' ? lo.v * src.v : BigInt.asIntN(bits, lo.v) * BigInt.asIntN(bits, src.v);
            const pu = BigInt.asUintN(2 * bits, p);
            write(st, loOp, { v: pu & MASK[size], m: MASK[size] }, size);
            write(st, hiOp, { v: pu >> BigInt(bits), m: MASK[size] }, size);
            st.flags = { ...UNK_FLAGS };
            break;
          }
          if (src.v === 0n) return { reason: 'panic', at: st.pc };
          const num = (hi.v << BigInt(bits)) | lo.v;
          let q;
          let rem;
          if (ins.op === 'div') { q = num / src.v; rem = num % src.v; } else {
            const n = BigInt.asIntN(2 * bits, num);
            const dv = BigInt.asIntN(bits, src.v);
            q = n / dv; rem = n % dv;
          }
          if ((ins.op === 'div' && q > MASK[size]) || (ins.op === 'idiv' && BigInt.asIntN(bits, BigInt.asUintN(bits, q)) !== q)) return { reason: 'panic', at: st.pc };
          write(st, loOp, { v: BigInt.asUintN(bits, q), m: MASK[size] }, size);
          write(st, hiOp, { v: BigInt.asUintN(bits, rem), m: MASK[size] }, size);
          break;
        }
        case 'xchg': {
          const a = read(st, d, size);
          const b = read(st, s, size);
          write(st, d, b, size);
          write(st, s, a, size);
          break;
        }
        case 'cext': {
          const half = size / 2;
          const x = read(st, { t: 'reg', r: RAX, size: half }, half);
          write(st, { t: 'reg', r: RAX, size }, known(x, half) ? { v: BigInt.asUintN(BITS[size], BigInt.asIntN(BITS[half], x.v)), m: MASK[size] } : U, size);
          break;
        }
        case 'cdq': {
          const x = read(st, { t: 'reg', r: RAX, size }, size);
          write(st, { t: 'reg', r: RDX, size }, known(x, size) ? { v: (x.v & SIGN[size]) ? MASK[size] : 0n, m: MASK[size] } : U, size);
          break;
        }
        case 'bswap': {
          const x = read(st, d, size);
          let v = 0n;
          let m = 0n;
          for (let i = 0; i < size; i++) { v = (v << 8n) | ((x.v >> BigInt(8 * i)) & 0xffn); m = (m << 8n) | ((x.m >> BigInt(8 * i)) & 0xffn); }
          write(st, d, { v, m }, size);
          break;
        }
        case 'setcc': { const c = ccEval(ins.cc, st.flags); write(st, d, c == null ? U : K(c ? 1 : 0), 1); break; }
        case 'cmovcc': {
          const c = ccEval(ins.cc, st.flags);
          if (c == null) { write(st, d, U, size); break; }
          // 32 bit cmov koşul yanlışken de üst yarıyı sıfırlar
          write(st, d, c ? read(st, s, size) : read(st, d, size), size);
          break;
        }
        case 'movx': {
          if (d.t === 'xmm' && s.t === 'xmm') st.xmm[d.r] = st.xmm[s.r].slice();
          else if (d.t === 'xmm') { const a = addrOf(st, s); st.xmm[d.r] = a == null ? [U, U] : [st.mem.read(a, 8), st.mem.read(a + 8, 8)]; }
          else { const a = addrOf(st, d); if (a == null) st.dirty++; else { st.mem.write(a, 8, st.xmm[s.r][0]); st.mem.write(a + 8, 8, st.xmm[s.r][1]); } }
          break;
        }
        case 'movxs': {
          const mk = MASK[size];
          if (d.t === 'xmm') {
            if (s.t === 'xmm') { const lo = st.xmm[d.r][0]; const x = st.xmm[s.r][0]; st.xmm[d.r] = [{ v: (lo.v & ~mk) | (x.v & mk), m: (lo.m & ~mk) | (x.m & mk) }, st.xmm[d.r][1]]; }
            else { const a = addrOf(st, s); st.xmm[d.r] = [a == null ? U : { ...st.mem.read(a, size), m: st.mem.read(a, size).m | (M64 ^ mk) }, K(0)]; }
          } else { const a = addrOf(st, d); if (a == null) st.dirty++; else st.mem.write(a, size, st.xmm[s.r][0]); }
          break;
        }
        case 'movgx': {
          if (d.t === 'xmm') { const x = read(st, s, size); st.xmm[d.r] = [{ v: x.v, m: x.m | (M64 ^ MASK[size]) }, K(0)]; }
          else write(st, d, st.xmm[s.r][0], size);
          break;
        }
        case 'pxor': {
          if (s.t === 'xmm' && s.r === d.r) { st.xmm[d.r] = [K(0), K(0)]; break; }
          const b = s.t === 'xmm' ? st.xmm[s.r] : (() => { const a = addrOf(st, s); return a == null ? [U, U] : [st.mem.read(a, 8), st.mem.read(a + 8, 8)]; })();
          st.xmm[d.r] = st.xmm[d.r].map((x, i) => ({ v: x.v ^ b[i].v, m: x.m & b[i].m }));
          break;
        }
        case 'movs': case 'stos': {
          let n = 1n;
          if (ins.rep) { const c = st.regs[RCX]; if (!known(c)) return { reason: 'unsupported', at: st.pc }; n = c.v; }
          if (n > 1_000_000n) return { reason: 'budget', at: st.pc };
          const di = st.regs[RDI];
          const si = st.regs[RSI];
          if (!known(di) || (ins.op === 'movs' && !known(si))) { st.dirty++; clobber(st); break; }
          let a = Number(di.v);
          let b = Number(si.v);
          const val = read(st, { t: 'reg', r: RAX, size }, size);
          for (let i = 0n; i < n; i++) {
            st.mem.write(a, size, ins.op === 'stos' ? val : st.mem.read(b, size));
            a += size; b += size;
          }
          st.regs[RDI] = K(a);
          if (ins.op === 'movs') st.regs[RSI] = K(b);
          if (ins.rep) st.regs[RCX] = K(0);
          break;
        }
        case 'push': {
          const x = read(st, d, 8);
          const sp = st.regs[RSP];
          if (!known(sp)) return { reason: 'unsupported', at: st.pc };
          const nsp = Number(sp.v) - 8;
          st.mem.write(nsp, 8, x);
          st.regs[RSP] = K(nsp);
          break;
        }
        case 'pop': {
          const sp = st.regs[RSP];
          if (!known(sp)) return { reason: 'unsupported', at: st.pc };
          const x = st.mem.read(Number(sp.v), 8);
          st.regs[RSP] = K(Number(sp.v) + 8);
          write(st, d, x, 8);
          break;
        }
        case 'jmp': case 'jcc': {
          let target = ins.target;
          if (ins.op === 'jmp' && target == null) {
            const t = read(st, d, 8);
            if (!known(t)) return { reason: 'unknown-target', at: st.pc };
            target = Number(t.v);
          }
          let take = true;
          if (ins.op === 'jcc') {
            const c = ccEval(ins.cc, st.flags);
            if (c == null) {
              // bilinmeyen koşul: diğer kol çatal olarak kuyruğa
              const other = clone(st);
              other.pc = target;
              if (target <= st.pc) other.feat.back++;
              fork(other);
              take = false;
            } else take = c;
          }
          if (take) {
            if (target <= st.pc) st.feat.back++;
            st.pc = target;
            continue;
          }
          break;
        }
        case 'call': {
          let target = ins.target;
          if (target == null) {
            const t = read(st, d, 8);
            if (known(t)) { target = Number(t.v); st.feat.indirect++; }
          }
          const fn = target != null ? o.funcAt(target) : null;
          const verdict = onCall(st, ins, target, fn);
          if (verdict.end) return { reason: verdict.end, at: st.pc };
          if (verdict.descend) {
            const sp = Number(st.regs[RSP].v) - 8;
            st.mem.write(sp, 8, K(next));
            st.regs[RSP] = K(sp);
            st.ret.push(next);
            st.depth++;
            st.pc = target;
            continue;
          }
          if (!verdict.handled) clobber(st);
          break;
        }
        case 'ret': {
          if (!st.depth) return { reason: 'ret', at: st.pc };
          const sp = st.regs[RSP];
          const back = st.ret.pop();
          st.regs[RSP] = K(Number(sp.v) + 8);
          st.depth--;
          st.pc = back;
          continue;
        }
        case 'stop': return { reason: 'stop', at: st.pc };
        default: return { reason: 'unsupported', at: st.pc };
      }
      st.pc = next;
    }
    return { reason: 'budget', at: st.pc };
  }

  return { newState, clone, runPath, fetch, zeroAlloc, alloc, known, read, regs: { RAX, RBX, RCX, RDX, RSI, RDI, RSP } };
}
