// Go pclntab ayrıştırıcı: dört düzen (sihirli değerle seçilir)
//   0xfffffffb  Go 1.2 – 1.15   functab mutlak PC'ler, adlar ve dosya tablosu pclntab'a göre
//   0xfffffffa  Go 1.16 – 1.17  pcHeader + funcnametab / cutab / filetab / pctab
//   0xfffffff0  Go 1.18 – 1.19  functab text'e göre 32 bit konumlar
//   0xfffffff1  Go 1.20+        _func'a startLine eklendi; 1.22+ textStart artık yazılmıyor (moduledata.text kullanılır)
// Bölüm adı (.gopclntab / __gopclntab), COFF sembolü (runtime.pclntab) ya da sihirli değer taraması ile bulunur;
// sembolleri silinmiş ikililerde de çalışır. Her konum dosya sınırına karşı denetlenir.
import { reader, ParseError, findAll } from './reader.js';

export const MAGICS = new Map([[0xfffffffb, '1.2'], [0xfffffffa, '1.16'], [0xfffffff0, '1.18'], [0xfffffff1, '1.20']]);
export const LIMITS = { maxFuncs: 400_000, maxPcValueSteps: 200_000, maxScan: 64 };

const headerOk = (b, o) => b[o + 4] === 0 && b[o + 5] === 0 && [1, 2, 4].includes(b[o + 6]) && (b[o + 7] === 4 || b[o + 7] === 8);

/** pclntab adayları: [{ fileOff, addr, how }] */
export function locatePclntab(img) {
  const out = [];
  const add = (fileOff, how) => {
    if (fileOff < 0 || out.some((c) => c.fileOff === fileOff)) return;
    out.push({ fileOff, how });
  };
  const sec = img.section('.gopclntab', '__gopclntab');
  if (sec && sec.fileSize) add(sec.offset, 'section');
  const sym = img.symbol('runtime.pclntab') ?? img.symbol('pclntab');
  if (sym) add(img.fileOffset(sym.addr), 'symbol');
  // sihirli değer taraması (silinmiş bölüm/sembol): hem LE hem BE
  for (const [magic] of MAGICS) {
    const le = [magic & 0xff, (magic >>> 8) & 0xff, (magic >>> 16) & 0xff, magic >>> 24];
    for (const pat of [le, [...le].reverse()]) {
      for (const off of findAll(img.bytes, pat, LIMITS.maxScan)) if (headerOk(img.bytes, off)) add(off, 'scan');
    }
  }
  // dosya konumu → sanal adres
  for (const c of out) {
    const r = img.regions.find((x) => c.fileOff >= x.fileOff && c.fileOff < x.fileOff + x.fileSize);
    c.addr = r ? r.addr + (c.fileOff - r.fileOff) : null;
  }
  return out;
}

/**
 * @param {Uint8Array} bytes tüm dosya
 * @param {number} off pclntab dosya konumu
 * @param {{ textStart?: number }} o 1.18+ için functab tabanı (başlıkta 0 ise)
 */
export function parsePclntab(bytes, off, { textStart = 0 } = {}) {
  const magicLE = bytes[off] | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] << 24);
  let le = true;
  let version = MAGICS.get(magicLE >>> 0);
  if (!version) {
    const be = ((bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3]) >>> 0;
    version = MAGICS.get(be);
    le = false;
  }
  if (!version || !headerOk(bytes, off)) throw new ParseError('pclntab başlığı geçersiz');
  const r = reader(bytes.subarray(off), le);
  const quantum = r.u8(6);
  const P = r.u8(7);
  const ptr = (o) => r.ptr(o, P);

  let nfunc;
  let ftab; // functab başlangıcı
  let nameBase;
  let pcBase; // pcvalue tabloları
  let fileName;
  let headerText = 0;
  let nfiles = 0;
  if (version === '1.2') {
    nfunc = ptr(8);
    ftab = 8 + P;
    nameBase = 0;
    pcBase = 0;
    const filetab = r.u32(ftab + nfunc * 2 * P + P);
    nfiles = r.u32(filetab);
    fileName = (_fn, idx) => (idx > 0 && idx < nfiles ? r.cstr(r.u32(filetab + idx * 4)) : null);
  } else {
    nfunc = ptr(8);
    nfiles = ptr(8 + P);
    let k = 8 + 2 * P;
    if (version !== '1.16') { headerText = ptr(k); k += P; }
    const funcname = ptr(k);
    const cu = ptr(k + P);
    const filetab = ptr(k + 2 * P);
    const pctab = ptr(k + 3 * P);
    const pcln = ptr(k + 4 * P);
    ftab = pcln;
    nameBase = funcname;
    pcBase = pctab;
    fileName = (fn, idx) => {
      if (idx < 0) return null;
      const fo = r.u32(cu + (fn.cuOffset + idx) * 4);
      if (fo === 0xffffffff) return null;
      return r.cstr(filetab + fo);
    };
  }
  if (!Number.isInteger(nfunc) || nfunc <= 0 || nfunc > LIMITS.maxFuncs) throw new ParseError(`pclntab fonksiyon sayısı geçersiz: ${nfunc}`);
  const rel32 = version === '1.18' || version === '1.20';
  const base = rel32 ? (headerText || textStart) : 0;
  const entW = rel32 ? 4 : P;
  const entryAt = (i) => (rel32 ? base + r.u32(ftab + i * 2 * entW) : ptr(ftab + i * 2 * P));
  const funcOffAt = (i) => (rel32 ? r.u32(ftab + i * 2 * entW + entW) : ptr(ftab + i * 2 * P + P));
  // _func'un konumu: 1.2'de pclntab'a, 1.16+'da functab'a göre
  const funcBase = version === '1.2' ? 0 : ftab;

  const readFunc = (i) => {
    const fo = funcBase + funcOffAt(i);
    const x = rel32 ? 4 : P; // entry alanının boyutu
    const fn = {
      entry: entryAt(i),
      nameOff: r.i32(fo + x),
      args: r.i32(fo + x + 4),
      pcsp: r.u32(fo + x + 12),
      pcfile: r.u32(fo + x + 16),
      pcln: r.u32(fo + x + 20),
      cuOffset: version === '1.2' ? 0 : r.u32(fo + x + 28),
      startLine: version === '1.20' ? r.i32(fo + x + 32) : 0,
      funcID: version === '1.2' ? 0 : r.u8(fo + x + (version === '1.20' ? 36 : 32)),
    };
    return fn;
  };

  /** pcvalue tablosu → [[pc, değer]] çiftleri (aralık sonu pc, değer) */
  const pcvalue = (tabOff, entry) => {
    if (!tabOff) return [];
    const out = [];
    let p = pcBase + tabOff;
    let pc = entry;
    let val = -1;
    for (let step = 0; step < LIMITS.maxPcValueSteps; step++) {
      const [uv, n1] = r.uvarint(p);
      if (uv === 0 && step > 0) break;
      p += n1;
      const dv = uv % 2 ? -((uv + 1) / 2) : uv / 2;
      const [pcd, n2] = r.uvarint(p);
      p += n2;
      val += dv;
      pc += pcd * quantum;
      out.push([pc, val]);
    }
    return out;
  };

  const funcs = [];
  for (let i = 0; i < nfunc; i++) {
    const fn = readFunc(i);
    const end = entryAt(i + 1);
    let name;
    try { name = r.cstr(nameBase + fn.nameOff); } catch { name = ''; }
    funcs.push({ index: i, entry: fn.entry, end, name, raw: fn });
  }
  // functab sıralı olmalı: değilse yanlış düzen ya da yanlış taban
  for (let i = 1; i < funcs.length; i++) if (funcs[i].entry < funcs[i - 1].entry) throw new ParseError('functab sıralı değil');

  const fileCache = new Map();
  const fileOf = (fn, idx) => {
    const key = version === '1.2' ? idx : `${fn.cuOffset}:${idx}`;
    if (!fileCache.has(key)) { let v = null; try { v = fileName(fn, idx); } catch { v = null; } fileCache.set(key, v); }
    return fileCache.get(key);
  };

  /** Ayrıntılar: dosya(lar), satır aralığı, satır tablosu (isteğe bağlı) */
  const details = (f, { lines = false } = {}) => {
    const fn = f.raw;
    let files = [];
    let lineTab = [];
    let pf = [];
    try {
      pf = pcvalue(fn.pcfile, f.entry);
      files = [...new Set(pf.map(([, v]) => v))].map((v) => fileOf(fn, v)).filter((x) => x != null);
      lineTab = pcvalue(fn.pcln, f.entry);
    } catch { /* bozuk tablo: ayrıntısız */ }
    // satır aralığı yalnızca fonksiyonun kendi dosyasından (satır içine alınan kodun satırları başka dosyalardandır)
    const own = pf[0]?.[1];
    const ls = [];
    let k = 0;
    let prev = f.entry;
    for (const [pc, v] of lineTab) {
      while (k < pf.length && pf[k][0] <= prev) k++;
      if (v > 0 && (own == null || pf[Math.min(k, pf.length - 1)]?.[1] === own)) ls.push(v);
      prev = pc;
    }
    const out = {
      file: files[0] ?? null,
      files,
      startLine: fn.startLine || (ls.length ? Math.min(...ls) : 0),
      endLine: ls.length ? Math.max(...ls) : 0,
    };
    if (lines) out.lines = lineTab.map(([pc, v], k) => [k ? lineTab[k - 1][0] : f.entry, pc, v]);
    return out;
  };

  return { version, le, ptrSize: P, quantum, nfunc, nfiles, textStart: base, headerText, funcs, details };
}

/**
 * Bul + ayrıştır: geçerli ilk aday (sıralı functab, akla yatkın adlar). textBase: 1.18+ için yedek taban.
 * Dönüş: { tab, cand } ya da null
 */
export function findPclntab(img, { textBase = null } = {}) {
  const errors = [];
  for (const cand of locatePclntab(img)) {
    const bases = [textBase, img.text?.addr, ...img.regions.filter((r) => r.exec).map((r) => r.addr)].filter((x) => x != null);
    for (const textStart of [...new Set(bases)].concat(bases.length ? [] : [0])) {
      try {
        const tab = parsePclntab(img.bytes, cand.fileOff, { textStart });
        const named = tab.funcs.filter((f) => f.name).length;
        if (named < tab.funcs.length * 0.9) throw new ParseError('adların çoğu okunamadı');
        // 1.18+: girişler yürütülebilir bir bölgeye düşmeli (yanlış taban seçimini eler)
        if (tab.funcs.length && !img.regionOf(tab.funcs[0].entry)?.exec && img.regions.some((x) => x.exec)) throw new ParseError('girişler kod bölgesinde değil');
        return { tab, cand };
      } catch (e) {
        errors.push(`${cand.how}@0x${cand.fileOff.toString(16)}: ${e.message}`);
        if (!(e instanceof ParseError)) throw e;
      }
    }
  }
  return errors.length ? { error: errors.slice(0, 4).join('; ') } : null;
}
