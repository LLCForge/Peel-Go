// PE/COFF (PE32 ve PE32+) ayrıştırıcı: bölümler, COFF sembol tablosu (Go -s ile derlenmemişse runtime.pclntab burada),
// içe aktarma tablosu (DLL + fonksiyon adları).
import { reader, ParseError } from './reader.js';

const MACHINES = { 0x14c: '386', 0x8664: 'amd64', 0xaa64: 'arm64', 0x1c4: 'arm' };
const MAX_SYMBOLS = 400_000;

export const isPe = (b) => {
  if (b.length < 0x40 || b[0] !== 0x4d || b[1] !== 0x5a) return false;
  const off = b[0x3c] | (b[0x3d] << 8) | (b[0x3e] << 16) | (b[0x3f] << 24);
  return off > 0 && off + 4 <= b.length && b[off] === 0x50 && b[off + 1] === 0x45 && b[off + 2] === 0 && b[off + 3] === 0;
};

export function parsePe(bytes) {
  const r = reader(bytes, true);
  const pe = r.u32(0x3c);
  const coff = pe + 4;
  const machine = r.u16(coff);
  const nsec = r.u16(coff + 2);
  const symPtr = r.u32(coff + 8);
  const nsyms = r.u32(coff + 12);
  const optSize = r.u16(coff + 16);
  const opt = coff + 20;
  const magic = r.u16(opt);
  if (magic !== 0x10b && magic !== 0x20b) throw new ParseError('PE isteğe bağlı başlık geçersiz');
  const plus = magic === 0x20b;
  const entryRva = r.u32(opt + 16);
  const imageBase = plus ? r.u64(opt + 24) : r.u32(opt + 28);
  const subsystem = r.u16(opt + 68);
  const ddOff = opt + (plus ? 112 : 96);
  const ndd = r.u32(opt + (plus ? 108 : 92));
  const dir = (i) => (i < ndd ? { rva: r.u32(ddOff + i * 8), size: r.u32(ddOff + i * 8 + 4) } : { rva: 0, size: 0 });

  const strTab = symPtr ? symPtr + nsyms * 18 : 0;
  const longName = (s) => {
    // "/123" biçimindeki uzun bölüm adları COFF dizge tablosundadır
    if (!/^\/\d+$/.test(s) || !strTab) return s;
    try { return r.cstr(strTab + Number(s.slice(1)), 256); } catch { return s; }
  };
  const sections = [];
  const secOff = opt + optSize;
  for (let i = 0; i < Math.min(nsec, 96); i++) {
    const o = secOff + i * 40;
    const raw = r.slice(o, 8);
    let name = '';
    for (const c of raw) { if (!c) break; name += String.fromCharCode(c); }
    const vsize = r.u32(o + 8);
    const rva = r.u32(o + 12);
    const rawSize = r.u32(o + 16);
    const rawPtr = r.u32(o + 20);
    const ch = r.u32(o + 36);
    sections.push({
      name: longName(name), addr: imageBase + rva, rva, size: Math.max(vsize, rawSize), memSize: vsize || rawSize, offset: rawPtr,
      fileSize: Math.min(rawSize, Math.max(0, bytes.length - rawPtr)),
      exec: Boolean(ch & 0x20000000), write: Boolean(ch & 0x80000000), alloc: true,
    });
  }
  const regions = sections.map((s) => ({ name: s.name, addr: s.addr, memSize: s.memSize, fileOff: s.offset, fileSize: Math.min(s.fileSize, s.memSize || s.fileSize), exec: s.exec, write: s.write }));
  const rvaToOff = (rva) => {
    for (const s of sections) if (rva >= s.rva && rva < s.rva + Math.max(s.memSize, s.fileSize) && rva - s.rva < s.fileSize) return s.offset + (rva - s.rva);
    return -1;
  };

  // COFF sembolleri (Go: runtime.pclntab, main.main, ...); -s ile derlenen ikililerde yoktur
  const symbols = [];
  if (symPtr && nsyms && strTab <= bytes.length) {
    for (let i = 0; i < Math.min(nsyms, MAX_SYMBOLS); i++) {
      const o = symPtr + i * 18;
      if (o + 18 > bytes.length) break;
      let name;
      if (r.u32(o) === 0) { try { name = r.cstr(strTab + r.u32(o + 4), 1024); } catch { name = ''; } } else {
        name = '';
        for (let j = 0; j < 8; j++) { const c = bytes[o + j]; if (!c) break; name += String.fromCharCode(c); }
      }
      const value = r.u32(o + 8);
      const secNum = r.i16(o + 12);
      const type = r.u16(o + 14);
      const naux = r.u8(o + 17);
      i += naux;
      if (!name || secNum <= 0 || secNum > sections.length) continue;
      symbols.push({ name, addr: sections[secNum - 1].addr + value, size: 0, func: (type >> 4) === 2 || sections[secNum - 1].exec, dynamic: false, undef: false });
    }
  }

  // içe aktarma dizini
  const imports = [];
  const libs = [];
  const imp = dir(1);
  if (imp.rva) {
    let d = rvaToOff(imp.rva);
    for (let n = 0; d >= 0 && n < 512 && d + 20 <= bytes.length; n++, d += 20) {
      const oft = r.u32(d);
      const nameRva = r.u32(d + 12);
      const ft = r.u32(d + 16);
      if (!nameRva && !ft) break;
      let lib = '';
      const lo = rvaToOff(nameRva);
      if (lo >= 0) { try { lib = r.cstr(lo, 256); } catch { lib = ''; } }
      libs.push(lib);
      let t = rvaToOff(oft || ft);
      const step = plus ? 8 : 4;
      for (let k = 0; t >= 0 && k < 4096 && t + step <= bytes.length; k++, t += step) {
        const v = plus ? r.u64(t) : r.u32(t);
        if (!v) break;
        const ordinal = plus ? v >= 2 ** 63 : v >= 2 ** 31;
        if (ordinal) { imports.push({ lib, name: `#${v % 65536}` }); continue; }
        const ho = rvaToOff(v % 2 ** 31);
        if (ho < 0) continue;
        try { imports.push({ lib, name: r.cstr(ho + 2, 256) }); } catch { /* bozuk ad atlanır */ }
      }
    }
  }

  return {
    format: 'pe',
    bits: plus ? 64 : 32,
    le: true,
    arch: MACHINES[machine] ?? `pe-${machine.toString(16)}`,
    os: 'windows',
    kind: (r.u16(coff + 18) & 0x2000) ? 'dll' : subsystem === 2 ? 'gui' : 'console',
    entry: imageBase + entryRva,
    imageBase,
    regions,
    sections,
    symbols,
    imports,
    libs,
    noSections: false,
  };
}
