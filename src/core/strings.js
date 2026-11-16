// Go dizge sabitleri. Go dizgeleri NUL ile bitmez ve rodata'da art arda dizilir; bu yüzden sınırlar koddan okunur:
//   amd64  LEA reg, [rip+X] komutunun ±3 komut yakınında MOV ..., imm (uzunluk)
//   386    LEAL X, reg (mutlak [disp32]) için aynı ±3 komut penceresi
//   arm64  ADRP + ADD #lo12 (+ yakında MOVZ #n)
// Kod referansı bulunamayan mimaride yazdırılabilir diziler (en az 6 karakter) kullanılır.
import { decode } from './x86.js';

export const LIMITS = { maxStrings: 100_000, maxLen: 4096, minLen: 3, maxDecode: 3_000_000, perFunc: 64, maxRunsBytes: 32 << 20 };
const utf8 = new TextDecoder('utf-8', { fatal: true });

/** arm64 MOVZ (#imm16, kaydırmasız) ya da ORR Xd, XZR, #bitmask sabiti; değilse null */
export function arm64Const(m) {
  if (((m & 0x7f800000) >>> 0) === 0x52800000 && ((m >>> 21) & 3) === 0) return (m >>> 5) & 0xffff;
  // ORR (bit maskesi anlık), Rn = XZR
  if (((m & 0x7f8003e0) >>> 0) !== 0x320003e0) return null;
  const sf = m >>> 31;
  const N = (m >>> 22) & 1;
  const immr = (m >>> 16) & 0x3f;
  const imms = (m >>> 10) & 0x3f;
  const combined = (N << 6) | (~imms & 0x3f);
  const len = 31 - Math.clz32(combined);
  if (len < 1 || (!sf && N)) return null;
  const esize = 1 << len;
  const levels = esize - 1;
  const S = imms & levels;
  const R = immr & levels;
  if (S === levels) return null;
  const ones = (1n << BigInt(S + 1)) - 1n;
  const emask = (1n << BigInt(esize)) - 1n;
  const elem = ((ones >> BigInt(R)) | (ones << BigInt(esize - R))) & emask;
  let v = 0n;
  for (let k = 0; k < (sf ? 64 : 32); k += esize) v |= elem << BigInt(k);
  return v <= 0xffffn ? Number(v) : null;
}

/** Yazdırılabilir UTF-8 mi (tab/satır sonu dışında denetim karakteri yok) */
export function cleanString(b) {
  if (b.length < LIMITS.minLen) return null;
  let s;
  try { s = utf8.decode(b); } catch { return null; }
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f�]/.test(s)) return null;
  // çoğu harf/rakam/noktalama olmalı
  if (!/[\p{L}\p{N}]/u.test(s)) return null;
  return s;
}

/**
 * @param {object} img
 * @param {Array<{entry,end,name}>} funcs
 * @returns {{ strings: Array<{addr, value, refs: number[]}>, byFunc: Map<number, string[]>, method: string }}
 */
export function extractStrings(img, funcs) {
  const found = new Map(); // addr → { addr, value, refs }
  const byFunc = new Map();
  const isData = (a) => { const r = img.regionOf(a); return r && !r.exec; };
  const add = (addr, len, site, fn) => {
    if (len < LIMITS.minLen || len > LIMITS.maxLen || !isData(addr)) return;
    let e = found.get(addr);
    if (!e) {
      if (found.size >= LIMITS.maxStrings) return;
      const b = img.read(addr, len);
      const value = b && cleanString(b);
      if (!value) return;
      e = { addr, value, refs: [] };
      found.set(addr, e);
    } else if (e.value.length !== len) return;
    if (e.refs.length < 16) e.refs.push(site);
    const list = byFunc.get(fn.entry) ?? [];
    if (list.length < LIMITS.perFunc && !list.includes(e.value)) list.push(e.value);
    byFunc.set(fn.entry, list);
  };

  let method = 'runs';
  if (img.arch === 'amd64' || img.arch === '386') {
    const mode64 = img.arch === 'amd64';
    const P = mode64 ? 8 : 4;
    const ABI = [0, 3, 1, 7, 6, 8, 9, 10, 11];
    const sameSlot = (a, b, delta) => a.t === 'mem' && b.t === 'mem' && a.base === b.base && a.index === b.index && a.scale === b.scale && b.disp - a.disp === BigInt(delta);
    method = 'code';
    let budget = LIMITS.maxDecode;
    for (const fn of funcs) {
      const code = img.read(fn.entry, fn.end - fn.entry);
      if (!code) continue;
      const win = [];
      for (let o = 0; o < code.length && budget-- > 0;) {
        const ins = decode(code, o, fn.entry + o, mode64);
        if (!ins) break;
        win.push(ins);
        o += ins.len;
        // LEA ile 3 komut sonrası birlikte değerlendirilir; pencere: [-3, +3]
        const k = win.length - 4;
        if (k >= 0) check(win, k, fn);
        if (win.length > 8) win.shift();
      }
      for (let k = Math.max(0, win.length - 3); k < win.length; k++) check(win, k, fn);
    }
    // Go dizgesi (işaretçi, uzunluk) çifti: ABIInternal'da ardışık argüman yazmaçları (AX,BX), (BX,CX), …;
    // bellekte [m] ve [m+P]. Uzunluk yalnızca bu eşleşmelerden alınır (yakındaki ilgisiz sabitler elenir).
    function check(win, k, fn) {
      const ins = win[k];
      if (ins.op !== 'lea' || !ins.ops[1].abs || ins.ops[0].t !== 'reg') return;
      const addr = Number(ins.ops[1].disp);
      const r = ins.ops[0].r;
      const lo = Math.max(0, k - 3);
      const hi = Math.min(win.length, k + 4);
      const imm = (m) => (m.op === 'mov' && m.ops[1].t === 'imm' ? Number(m.ops[1].v) : null);
      let best = null;
      const take = (v, j) => {
        if (v == null || v < LIMITS.minLen || v > LIMITS.maxLen) return;
        if (!best || Math.abs(j - k) < best.d) best = { v, d: Math.abs(j - k) };
      };
      const next = mode64 ? ABI[ABI.indexOf(r) + 1] : undefined;
      // işaretçinin yazıldığı bellek yuvaları (LEA'dan sonra, yazmaç değişmeden)
      const slots = [];
      for (let j = k + 1; j < hi; j++) {
        const m = win[j];
        if (m.op === 'mov' && m.ops[0].t === 'mem' && m.ops[1].t === 'reg' && m.ops[1].r === r && m.ops[1].size === P) slots.push(m.ops[0]);
        if (m.ops[0]?.t === 'reg' && m.ops[0].r === r && m.op !== 'cmp' && m.op !== 'test') break;
      }
      for (let j = lo; j < hi; j++) {
        if (j === k) continue;
        const m = win[j];
        const v = imm(m);
        if (v == null) continue;
        if (next !== undefined && m.ops[0].t === 'reg' && m.ops[0].r === next) take(v, j);
        else if (m.ops[0].t === 'mem' && slots.some((s) => sameSlot(s, m.ops[0], P))) take(v, j);
      }
      if (best) add(addr, best.v, ins.addr, fn);
    }
  } else if (img.arch === 'arm64') {
    method = 'code';
    for (const fn of funcs) {
      const c = img.read(fn.entry, fn.end - fn.entry);
      if (!c) continue;
      const dv = new DataView(c.buffer, c.byteOffset, c.byteLength);
      const n = Math.floor(c.length / 4);
      for (let i = 0; i + 1 < n; i++) {
        const a = dv.getUint32(i * 4, true);
        if (((a & 0x9f000000) >>> 0) !== 0x90000000) continue;
        const rd = a & 31;
        const imm = ((((a >>> 5) & 0x7ffff) << 2) | ((a >>> 29) & 3));
        const signed = imm & 0x100000 ? imm - 0x200000 : imm;
        const pc = fn.entry + i * 4;
        const page = Math.floor(pc / 4096) * 4096 + signed * 4096;
        const b = dv.getUint32((i + 1) * 4, true);
        // ADD Xd, Xd, #imm12
        if (((b & 0xff800000) >>> 0) !== 0x91000000 || (b & 31) !== rd || ((b >>> 5) & 31) !== rd) continue;
        const addr = page + (((b >>> 10) & 0xfff) << ((b >>> 22) & 1 ? 12 : 0));
        // uzunluk: işaretçi Rd'deyken R(d+1)'e yüklenen sabit (ABI çifti; 3 komut önceye kadar da bakılır) ya da
        // bellekte [taban+k] işaretçi, [taban+k+8] sabit (STR/STP ile yapı alanları)
        const val = new Map();
        for (let j = Math.max(0, i - 3); j < i; j++) { const m = dv.getUint32(j * 4, true); const v = arm64Const(m); if (v != null) val.set(m & 31, { c: v }); }
        val.set(rd, { p: true });
        const slots = new Map();
        let len = null;
        const before = val.get(rd + 1)?.c ?? null;
        val.delete(rd + 1);
        for (let j = i + 2; j < Math.min(n, i + 10) && len == null; j++) {
          const m = dv.getUint32(j * 4, true);
          const v = arm64Const(m);
          const op = (m & 0xffc00000) >>> 0;
          if (v != null) {
            val.set(m & 31, { c: v });
            if ((m & 31) === rd + 1 && val.get(rd)?.p) len = v;
          } else if (op === 0xf9000000) { // STR Xt, [Xn, #imm*8]
            const k = `${(m >>> 5) & 31}:${((m >>> 10) & 0xfff) * 8}`;
            slots.set(k, val.get(m & 31));
          } else if (op === 0xa9000000) { // STP Xt1, Xt2, [Xn, #imm7*8]
            const off = (((m >>> 15) & 0x7f) << 25 >> 25) * 8;
            const base = (m >>> 5) & 31;
            slots.set(`${base}:${off}`, val.get(m & 31));
            slots.set(`${base}:${off + 8}`, val.get((m >>> 10) & 31));
          } else if ((m & 0x1f000000) !== 0x1000000 && ((m >>> 26) & 7) !== 5) val.delete(m & 31); // diğer yazmaç yazımları
          for (const [k, x] of slots) {
            if (!x?.p) continue;
            const [b, o] = k.split(':');
            const nxt = slots.get(`${b}:${Number(o) + 8}`);
            if (nxt?.c != null) { len = nxt.c; break; }
          }
        }
        len ??= before;
        if (len != null && len >= LIMITS.minLen && len <= LIMITS.maxLen) add(addr, len, pc, fn);
      }
    }
  }
  if (found.size < 16) {
    method = 'runs';
    let budget = LIMITS.maxRunsBytes;
    for (const r of img.regions.filter((x) => !x.exec && x.fileSize)) {
      const b = img.bytes.subarray(r.fileOff, r.fileOff + Math.min(r.fileSize, budget));
      budget -= b.length;
      let start = -1;
      for (let i = 0; i <= b.length; i++) {
        const c = i < b.length ? b[i] : 0;
        if (c >= 0x20 && c < 0x7f) { if (start < 0) start = i; continue; }
        if (start >= 0 && i - start >= 6 && found.size < LIMITS.maxStrings && !found.has(r.addr + start)) {
          const value = String.fromCharCode(...b.subarray(start, Math.min(i, start + LIMITS.maxLen)));
          found.set(r.addr + start, { addr: r.addr + start, value, refs: [] });
        }
        start = -1;
      }
      if (budget <= 0) break;
    }
  }
  return { strings: [...found.values()].sort((a, b) => a.addr - b.addr), byFunc, method };
}
