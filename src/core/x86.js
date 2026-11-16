// Küçük, sınırlı bir x86-64 çözücüsü: Go derleyicisinin dizge çözme gövdelerinde ürettiği komut alt kümesi
// (mov/movzx/movsx/lea, aritmetik ve mantık, kaydırma/döndürme, imul, test/cmp, jcc/setcc/cmovcc, call/jmp/ret,
// push/pop, SSE taşıma ve sıfırlama, rep movs/stos). Tanınmayan komut null döner; öykünücü yolu orada keser.
//
// Komut: { addr, len, op, size, ops: [işlenen], cc?, target?, rep? }
// İşlenen: { t: 'reg', r, size, hi? } | { t: 'xmm', r } | { t: 'mem', base, index, scale, disp, rip, size, seg }
//          | { t: 'imm', v (BigInt, işaret genişletilmiş), size }

const GRP1 = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp'];
const GRP2 = ['rol', 'ror', 'rcl', 'rcr', 'shl', 'shr', 'shl', 'sar'];
export const CC = ['o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g'];
export const REGS = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'];

const sx = (v, bits) => BigInt.asIntN(bits, BigInt(v));

/**
 * @param {Uint8Array} code
 * @param {number} off code içindeki konum
 * @param {number} addr bu konumun sanal adresi
 * @param {boolean} mode64 false: 32 bit kip (386; REX yok, 0x40-0x4f inc/dec, [disp32] mutlak)
 */
export function decode(code, off, addr, mode64 = true) {
  let p = off;
  const end = Math.min(code.length, off + 15);
  const byte = () => { if (p >= end) throw new RangeError('kısa'); return code[p++]; };
  const imm = (n) => {
    let v = 0n;
    for (let i = 0; i < n; i++) v |= BigInt(byte()) << BigInt(8 * i);
    return sx(v, n * 8);
  };
  try {
    let opsz16 = false;
    let rep = null;
    let seg = null;
    let rex = 0;
    let operandAbs = false;
    let b;
    for (;;) {
      b = byte();
      if (b === 0x66) opsz16 = true;
      else if (b === 0xf2 || b === 0xf3) rep = b;
      else if (b === 0x64 || b === 0x65) seg = b === 0x64 ? 'fs' : 'gs';
      else if (b === 0x2e || b === 0x3e || b === 0x26 || b === 0x36 || b === 0xf0) { if (b === 0xf0) return null; }
      else break;
    }
    if (mode64 && b >= 0x40 && b <= 0x4f) { rex = b; b = byte(); }
    const W = Boolean(rex & 8);
    const R = (rex & 4) ? 8 : 0;
    const X = (rex & 2) ? 8 : 0;
    const B = (rex & 1) ? 8 : 0;
    const osz = W ? 8 : opsz16 ? 2 : 4;

    const reg8 = (n, ext) => (rex || n < 4 || ext ? { t: 'reg', r: n + ext, size: 1 } : { t: 'reg', r: n - 4, size: 1, hi: true });
    const regOf = (n, size) => (size === 1 ? reg8(n & 7, n & 8) : { t: 'reg', r: n, size });
    // ModRM: [reg alanı (R ile), r/m işleneni]
    const modrm = (size, regIsXmm = false, rmIsXmm = false) => {
      const m = byte();
      const mod = m >> 6;
      const regf = ((m >> 3) & 7) | R;
      const rm = m & 7;
      let operand;
      if (mod === 3) {
        operand = rmIsXmm ? { t: 'xmm', r: rm | B } : size === 1 ? reg8(rm, B) : { t: 'reg', r: rm | B, size };
      } else {
        let base = rm | B;
        let index = -1;
        let scale = 1;
        let disp = 0n;
        let rip = false;
        if (rm === 4) {
          const sib = byte();
          scale = 1 << (sib >> 6);
          const idx = ((sib >> 3) & 7) | X;
          index = idx === 4 ? -1 : idx;
          base = (sib & 7) | B;
          if ((sib & 7) === 5 && mod === 0) { base = -1; disp = imm(4); }
        } else if (rm === 5 && mod === 0) {
          base = -1;
          rip = mode64;
          if (!mode64) operandAbs = true;
          disp = imm(4);
        }
        if (mod === 1) disp = imm(1);
        else if (mod === 2) disp = imm(4);
        operand = { t: 'mem', base, index, scale, disp, rip, size, seg };
      }
      return { regf, operand, regOp: regIsXmm ? { t: 'xmm', r: regf } : regOf(regf, size) };
    };
    const I = (op, size, ops, extra = {}) => ({ op, size, ops, ...extra });
    let ins = null;

    if (b === 0x0f) {
      const b2 = byte();
      if (b2 >= 0x80 && b2 <= 0x8f) ins = I('jcc', 0, [], { cc: b2 - 0x80, rel: imm(4) });
      else if (b2 >= 0x90 && b2 <= 0x9f) { const m = modrm(1); ins = I('setcc', 1, [m.operand], { cc: b2 - 0x90 }); }
      else if (b2 >= 0x40 && b2 <= 0x4f) { const m = modrm(osz); ins = I('cmovcc', osz, [m.regOp, m.operand], { cc: b2 - 0x40 }); }
      else if (b2 === 0xb6 || b2 === 0xbe) { const m = modrm(1); ins = I(b2 === 0xb6 ? 'movzx' : 'movsx', osz, [regOf(m.regf, osz), m.operand]); }
      else if (b2 === 0xb7 || b2 === 0xbf) { const m = modrm(2); ins = I(b2 === 0xb7 ? 'movzx' : 'movsx', osz, [regOf(m.regf, osz), m.operand]); }
      else if (b2 === 0xaf) { const m = modrm(osz); ins = I('imul', osz, [m.regOp, m.regOp, m.operand]); }
      else if (b2 === 0x1f || b2 === 0x18 || b2 === 0x0d) { modrm(osz); ins = I('nop', 0, []); }
      else if (b2 >= 0xc8 && b2 <= 0xcf) ins = I('bswap', osz, [{ t: 'reg', r: (b2 - 0xc8) | B, size: osz }]);
      else if (b2 === 0x0b || b2 === 0x05 || b2 === 0xa2) ins = I('stop', 0, []);
      else if (b2 === 0x10 || b2 === 0x11 || b2 === 0x28 || b2 === 0x29) {
        // movups/movupd/movaps/movapd (128), movss (32, F3), movsd (64, F2)
        const size = rep === 0xf3 ? 4 : rep === 0xf2 ? 8 : 16;
        const m = modrm(size, true, true);
        const store = b2 === 0x11 || b2 === 0x29;
        ins = I(size === 16 ? 'movx' : 'movxs', size, store ? [m.operand, m.regOp] : [m.regOp, m.operand]);
      } else if (b2 === 0x6f || b2 === 0x7f) {
        if (!opsz16 && rep !== 0xf3) return null; // MMX
        const m = modrm(16, true, true);
        ins = I('movx', 16, b2 === 0x7f ? [m.operand, m.regOp] : [m.regOp, m.operand]);
      } else if (b2 === 0x57 || b2 === 0xef) {
        if (b2 === 0xef && !opsz16) return null;
        const m = modrm(16, true, true);
        ins = I('pxor', 16, [m.regOp, m.operand]);
      } else if (b2 === 0xd6 && opsz16) {
        const m = modrm(8, true, true);
        ins = I('movxs', 8, [m.operand, m.regOp]);
      } else if (b2 === 0x7e && rep === 0xf3) {
        const m = modrm(8, true, true);
        ins = I('movxs', 8, [m.regOp, m.operand]);
      } else if ((b2 === 0x6e || b2 === 0x7e) && opsz16) {
        const size = W ? 8 : 4;
        const m = modrm(size, true, false);
        ins = I('movgx', size, b2 === 0x6e ? [m.regOp, m.operand] : [m.operand, m.regOp]);
      } else return null;
    } else if (b < 0x40 && (b & 7) < 6) {
      const op = GRP1[b >> 3];
      const k = b & 7;
      if (k === 0 || k === 2) { const m = modrm(1); ins = I(op, 1, k === 0 ? [m.operand, m.regOp] : [m.regOp, m.operand]); }
      else if (k === 1 || k === 3) { const m = modrm(osz); ins = I(op, osz, k === 1 ? [m.operand, m.regOp] : [m.regOp, m.operand]); }
      else if (k === 4) ins = I(op, 1, [{ t: 'reg', r: 0, size: 1 }, { t: 'imm', v: imm(1), size: 1 }]);
      else ins = I(op, osz, [{ t: 'reg', r: 0, size: osz }, { t: 'imm', v: imm(osz === 2 ? 2 : 4), size: osz }]);
    } else if (!mode64 && b >= 0x40 && b <= 0x4f) ins = I(b < 0x48 ? 'inc' : 'dec', osz, [{ t: 'reg', r: b & 7, size: osz }]);
    else if (b >= 0x50 && b <= 0x57) ins = I('push', 8, [{ t: 'reg', r: (b - 0x50) | B, size: 8 }]);
    else if (b >= 0x58 && b <= 0x5f) ins = I('pop', 8, [{ t: 'reg', r: (b - 0x58) | B, size: 8 }]);
    else if (b === 0x63) { const m = modrm(4); ins = I('movsx', osz, [regOf(m.regf, osz), m.operand]); }
    else if (b === 0x68) ins = I('push', 8, [{ t: 'imm', v: imm(4), size: 8 }]);
    else if (b === 0x6a) ins = I('push', 8, [{ t: 'imm', v: imm(1), size: 8 }]);
    else if (b === 0x69 || b === 0x6b) { const m = modrm(osz); ins = I('imul', osz, [m.regOp, m.operand, { t: 'imm', v: imm(b === 0x6b ? 1 : osz === 2 ? 2 : 4), size: osz }]); }
    else if (b >= 0x70 && b <= 0x7f) ins = I('jcc', 0, [], { cc: b - 0x70, rel: imm(1) });
    else if (b === 0x80 || b === 0x81 || b === 0x83) {
      const size = b === 0x80 ? 1 : osz;
      const m = modrm(size);
      const v = imm(b === 0x81 ? (osz === 2 ? 2 : 4) : 1);
      ins = I(GRP1[m.regf & 7], size, [m.operand, { t: 'imm', v, size }]);
    } else if (b === 0x84 || b === 0x85) { const size = b === 0x84 ? 1 : osz; const m = modrm(size); ins = I('test', size, [m.operand, m.regOp]); }
    else if (b === 0x86 || b === 0x87) { const size = b === 0x86 ? 1 : osz; const m = modrm(size); ins = I('xchg', size, [m.operand, m.regOp]); }
    else if (b >= 0x88 && b <= 0x8b) {
      const size = b & 1 ? osz : 1;
      const m = modrm(size);
      ins = I('mov', size, b < 0x8a ? [m.operand, m.regOp] : [m.regOp, m.operand]);
    } else if (b === 0x8d) { const m = modrm(osz); if (m.operand.t !== 'mem') return null; ins = I('lea', osz, [m.regOp, m.operand]); }
    else if (b === 0x90) ins = I('nop', 0, []);
    else if (b >= 0x91 && b <= 0x97) ins = I('xchg', osz, [{ t: 'reg', r: 0, size: osz }, { t: 'reg', r: (b - 0x90) | B, size: osz }]);
    else if (b === 0x98) ins = I('cext', osz, []);
    else if (b === 0x99) ins = I('cdq', osz, []);
    else if (b === 0xa8) ins = I('test', 1, [{ t: 'reg', r: 0, size: 1 }, { t: 'imm', v: imm(1), size: 1 }]);
    else if (b === 0xa9) ins = I('test', osz, [{ t: 'reg', r: 0, size: osz }, { t: 'imm', v: imm(osz === 2 ? 2 : 4), size: osz }]);
    else if (b === 0xa4 || b === 0xa5 || b === 0xaa || b === 0xab) {
      const size = b & 1 ? osz : 1;
      ins = I(b < 0xaa ? 'movs' : 'stos', size, [], { rep: rep === 0xf3 });
    } else if (b >= 0xb0 && b <= 0xb7) ins = I('mov', 1, [reg8(b - 0xb0, B), { t: 'imm', v: imm(1), size: 1 }]);
    else if (b >= 0xb8 && b <= 0xbf) {
      const v = W ? imm(8) : opsz16 ? imm(2) : imm(4);
      ins = I('mov', osz, [{ t: 'reg', r: (b - 0xb8) | B, size: osz }, { t: 'imm', v, size: osz }]);
    } else if (b === 0xc0 || b === 0xc1 || (b >= 0xd0 && b <= 0xd3)) {
      const size = b === 0xc0 || b === 0xd0 || b === 0xd2 ? 1 : osz;
      const m = modrm(size);
      const cnt = b <= 0xc1 ? { t: 'imm', v: imm(1), size: 1 } : b <= 0xd1 ? { t: 'imm', v: 1n, size: 1 } : { t: 'reg', r: 1, size: 1 };
      const op = GRP2[m.regf & 7];
      if (op === 'rcl' || op === 'rcr') return null;
      ins = I(op, size, [m.operand, cnt]);
    } else if (b === 0xc2) { imm(2); ins = I('ret', 0, []); }
    else if (b === 0xc3) ins = I('ret', 0, []);
    else if (b === 0xc6 || b === 0xc7) {
      const size = b === 0xc6 ? 1 : osz;
      const m = modrm(size);
      if ((m.regf & 7) !== 0) return null;
      ins = I('mov', size, [m.operand, { t: 'imm', v: imm(size === 1 ? 1 : size === 2 ? 2 : 4), size }]);
    } else if (b === 0xcc || b === 0xf4) ins = I('stop', 0, []);
    else if (b === 0xe8) ins = I('call', 8, [], { rel: imm(4) });
    else if (b === 0xe9) ins = I('jmp', 8, [], { rel: imm(4) });
    else if (b === 0xeb) ins = I('jmp', 8, [], { rel: imm(1) });
    else if (b === 0xf6 || b === 0xf7) {
      const size = b === 0xf6 ? 1 : osz;
      const m = modrm(size);
      const k = m.regf & 7;
      if (k <= 1) ins = I('test', size, [m.operand, { t: 'imm', v: imm(size === 1 ? 1 : size === 2 ? 2 : 4), size }]);
      else ins = I(['', '', 'not', 'neg', 'mul1', 'imul1', 'div', 'idiv'][k], size, [m.operand]);
    } else if (b === 0xfe || b === 0xff) {
      const size = b === 0xfe ? 1 : osz;
      const m = modrm(size);
      const k = m.regf & 7;
      if (k === 0) ins = I('inc', size, [m.operand]);
      else if (k === 1) ins = I('dec', size, [m.operand]);
      else if (b === 0xff && (k === 2 || k === 4 || k === 6)) {
        m.operand.size = 8;
        ins = I(k === 2 ? 'call' : k === 4 ? 'jmp' : 'push', 8, [m.operand]);
      } else return null;
    } else return null;

    ins.addr = addr;
    ins.len = p - off;
    if (ins.rel != null) { ins.target = addr + ins.len + Number(ins.rel); delete ins.rel; }
    // RIP göreli bellek işlenenleri mutlak adrese çevrilir
    for (const o of ins.ops) {
      if (o.t === 'mem' && o.rip) { o.disp = BigInt(addr + ins.len) + o.disp; o.rip = false; o.abs = true; }
      else if (o.t === 'mem' && operandAbs && o.base < 0 && o.index < 0) o.abs = true;
    }
    return ins;
  } catch (e) {
    if (e instanceof RangeError) return null;
    throw e;
  }
}

/** Tek satır çözümleme (hata ayıklama ve rapor kanıtı için) */
export function format(ins) {
  if (!ins) return '(bilinmeyen)';
  const op = (o) => {
    if (o.t === 'reg') return o.hi ? ['ah', 'ch', 'dh', 'bh'][o.r] : `${REGS[o.r]}${o.size === 8 ? '' : `:${o.size}`}`;
    if (o.t === 'xmm') return `xmm${o.r}`;
    if (o.t === 'imm') return `0x${BigInt.asUintN(64, o.v).toString(16)}`;
    const parts = [];
    if (o.base >= 0) parts.push(REGS[o.base]);
    if (o.index >= 0) parts.push(`${REGS[o.index]}*${o.scale}`);
    if (o.disp || !parts.length) parts.push(`0x${BigInt.asUintN(64, o.disp).toString(16)}`);
    return `${o.seg ? `${o.seg}:` : ''}[${parts.join('+')}]`;
  };
  const name = ins.op === 'jcc' || ins.op === 'setcc' || ins.op === 'cmovcc' ? ins.op.replace('cc', CC[ins.cc]) : ins.op;
  const args = ins.target != null ? [`0x${ins.target.toString(16)}`] : ins.ops.map(op);
  return `${name} ${args.join(', ')}`.trim();
}
