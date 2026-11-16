// Mach-O (32/64 bit) ve evrensel (fat) ikili ayrıştırıcı: segmentler/bölümler, LC_SYMTAB, bağlı dylib'ler.
// Evrensel ikilide önce amd64, sonra arm64 dilimi seçilir (yoksa ilki).
import { reader, ParseError } from './reader.js';

const CPU = { 7: '386', 0x01000007: 'amd64', 12: 'arm', 0x0100000c: 'arm64', 0x01000012: 'ppc64' };
const MAX_SYMBOLS = 400_000;

export const isMachO = (b) => {
  if (b.length < 28) return false;
  const m = (b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]) >>> 0;
  return [0xcefaedfe, 0xcffaedfe, 0xfeedface, 0xfeedfacf, 0xcafebabe].includes(m);
};

export function parseMachO(bytes) {
  const be = reader(bytes, false);
  if (be.u32(0) === 0xcafebabe) {
    const n = be.u32(4);
    // Java .class dosyaları da 0xcafebabe ile başlar: dilim sayısı küçük olmalı
    if (n === 0 || n > 16) throw new ParseError('evrensel Mach-O dilim sayısı geçersiz');
    const arches = [];
    for (let i = 0; i < n; i++) {
      const o = 8 + i * 20;
      arches.push({ cpu: be.u32(o), offset: be.u32(o + 8), size: be.u32(o + 12) });
    }
    const pick = arches.find((a) => a.cpu === 0x01000007) ?? arches.find((a) => a.cpu === 0x0100000c) ?? arches[0];
    if (pick.offset + pick.size > bytes.length) throw new ParseError('evrensel Mach-O dilimi dosya dışında');
    const inner = parseMachO(bytes.subarray(pick.offset, pick.offset + pick.size));
    // bölge/bölüm dosya konumları dış dosyaya göre kaydırılır
    for (const x of [...inner.regions, ...inner.sections]) { if (x.fileOff != null) x.fileOff += pick.offset; if (x.offset != null) x.offset += pick.offset; }
    return { ...inner, fat: arches.map((a) => CPU[a.cpu] ?? `cpu-${a.cpu.toString(16)}`) };
  }
  const magic = be.u32(0);
  const le = magic === 0xcefaedfe || magic === 0xcffaedfe;
  const r = reader(bytes, le);
  const is64 = magic === 0xcffaedfe || magic === 0xfeedfacf;
  const cpu = r.u32(4);
  const ncmds = r.u32(16);
  const P = is64 ? 8 : 4;
  let o = is64 ? 32 : 28;
  const sections = [];
  const regions = [];
  const libs = [];
  let symtab = null;
  let entry = 0;
  let textBase = 0;
  for (let i = 0; i < Math.min(ncmds, 512); i++) {
    const cmd = r.u32(o);
    const size = r.u32(o + 4);
    if (size < 8) throw new ParseError('Mach-O yükleme komutu bozuk');
    if (cmd === 0x19 || cmd === 0x1) {
      const seg = segName(r, o + 8);
      const vmaddr = r.ptr(o + 24, P);
      const vmsize = r.ptr(o + 24 + P, P);
      const fileoff = r.ptr(o + 24 + 2 * P, P);
      const filesize = r.ptr(o + 24 + 3 * P, P);
      const initprot = r.u32(o + 24 + 4 * P + 4);
      const nsects = r.u32(o + 24 + 4 * P + 8);
      if (seg === '__TEXT') textBase = vmaddr - fileoff;
      if (seg !== '__PAGEZERO') regions.push({ name: seg, addr: vmaddr, memSize: vmsize, fileOff: fileoff, fileSize: Math.min(filesize, Math.max(0, bytes.length - fileoff)), exec: Boolean(initprot & 4), write: Boolean(initprot & 2) });
      let s = o + (is64 ? 72 : 56);
      for (let k = 0; k < Math.min(nsects, 256); k++, s += is64 ? 80 : 68) {
        const name = segName(r, s);
        const addr = r.ptr(s + 32, P);
        const ssize = r.ptr(s + 32 + P, P);
        const offset = r.u32(s + 32 + 2 * P);
        const flags = r.u32(s + 32 + 2 * P + 16);
        const zerofill = (flags & 0xff) === 1 || (flags & 0xff) === 0xc;
        sections.push({
          name, segment: seg, addr, size: ssize, offset,
          fileSize: zerofill ? 0 : Math.min(ssize, Math.max(0, bytes.length - offset)),
          exec: Boolean(flags & 0x80000400), write: seg.startsWith('__DATA'), alloc: true,
        });
      }
    } else if (cmd === 0x2) {
      symtab = { symoff: r.u32(o + 8), nsyms: r.u32(o + 12), stroff: r.u32(o + 16), strsize: r.u32(o + 20) };
    } else if (cmd === 0xc || cmd === 0x80000018 || cmd === 0xd) {
      try { libs.push(r.cstr(o + r.u32(o + 8), 512)); } catch { /* bozuk ad atlanır */ }
    } else if (cmd === 0x80000028) {
      entry = r.u64(o + 8);
    }
    o += size;
  }
  if (entry) entry += textBase;

  const symbols = [];
  if (symtab) {
    const ent = is64 ? 16 : 12;
    for (let i = 0; i < Math.min(symtab.nsyms, MAX_SYMBOLS); i++) {
      const so = symtab.symoff + i * ent;
      if (so + ent > bytes.length) break;
      const strx = r.u32(so);
      const type = r.u8(so + 4);
      const sect = r.u8(so + 5);
      const value = r.ptr(so + 8, P);
      if (type & 0xe0) continue; // hata ayıklama (stab) girdileri
      let name;
      try { name = r.cstr(symtab.stroff + strx, 1024); } catch { continue; }
      if (!name) continue;
      // Mach-O C sembolleri '_' önekiyle yazılır (Go sembolleri de: _main.main)
      if (name.startsWith('_')) name = name.slice(1);
      const undef = (type & 0x0e) === 0;
      symbols.push({ name, addr: value, size: 0, func: sect > 0 && sections[sect - 1]?.exec, dynamic: undef, undef });
    }
  }
  // __TEXT segmenti rodata'yı da taşır (r-x): bölgeler, varsa bölümlerden kurulur ki yalnızca __text yürütülebilir sayılsın
  const secRegions = sections.filter((s) => s.size > 0).map((s) => ({ name: `${s.segment},${s.name}`, addr: s.addr, memSize: s.size, fileOff: s.offset, fileSize: s.fileSize, exec: s.exec, write: s.write }));
  return {
    format: 'macho',
    bits: is64 ? 64 : 32,
    le,
    arch: CPU[cpu] ?? `cpu-${cpu.toString(16)}`,
    os: 'darwin',
    kind: r.u32(12) === 2 ? 'exec' : `filetype-${r.u32(12)}`,
    entry,
    regions: secRegions.length ? secRegions : regions,
    sections,
    symbols,
    imports: symbols.filter((s) => s.undef).map((s) => ({ lib: '', name: s.name })),
    libs,
    noSections: false,
  };
}

function segName(r, o) {
  let s = '';
  for (let i = 0; i < 16; i++) { const c = r.u8(o + i); if (!c) break; s += String.fromCharCode(c); }
  return s;
}
