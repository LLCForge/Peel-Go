// ELF (32/64 bit, LE/BE) ayrıştırıcı: başlık, program başlıkları (bellek bölgeleri), bölümler, .symtab/.dynsym,
// DT_NEEDED kitaplıkları. Bölüm tablosu olmayan ikililer (UPX gibi paketleyiciler) program başlıklarıyla okunur.
import { reader, ParseError } from './reader.js';

const MACHINES = { 3: '386', 62: 'amd64', 183: 'arm64', 40: 'arm', 8: 'mips', 21: 'ppc64', 22: 's390x', 243: 'riscv64', 258: 'loong64' };
const MAX_SECTIONS = 4096;
const MAX_SYMBOLS = 400_000;

export const isElf = (b) => b.length >= 52 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46;

export function parseElf(bytes) {
  const cls = bytes[4];
  const data = bytes[5];
  if (cls !== 1 && cls !== 2) throw new ParseError('ELF sınıfı geçersiz');
  if (data !== 1 && data !== 2) throw new ParseError('ELF bayt sırası geçersiz');
  const is64 = cls === 2;
  const r = reader(bytes, data === 1);
  const P = is64 ? 8 : 4;
  const type = r.u16(16);
  const machine = r.u16(18);
  const entry = r.ptr(24, P);
  const phoff = r.ptr(is64 ? 32 : 28, P);
  const shoff = r.ptr(is64 ? 40 : 32, P);
  const phentsize = r.u16(is64 ? 54 : 42);
  const phnum = r.u16(is64 ? 56 : 44);
  const shentsize = r.u16(is64 ? 58 : 46);
  const shnum = r.u16(is64 ? 60 : 48);
  const shstrndx = r.u16(is64 ? 62 : 50);

  const regions = [];
  const segments = [];
  for (let i = 0; i < Math.min(phnum, 256); i++) {
    const o = phoff + i * phentsize;
    if (o + phentsize > bytes.length) break;
    const pType = r.u32(o);
    const flags = is64 ? r.u32(o + 4) : r.u32(o + 24);
    const offset = r.ptr(is64 ? o + 8 : o + 4, P);
    const vaddr = r.ptr(is64 ? o + 16 : o + 8, P);
    const filesz = r.ptr(is64 ? o + 32 : o + 16, P);
    const memsz = r.ptr(is64 ? o + 40 : o + 20, P);
    segments.push({ type: pType, flags, offset, vaddr, filesz, memsz });
    if (pType === 1) regions.push({ name: `LOAD${regions.length}`, addr: vaddr, memSize: memsz, fileOff: offset, fileSize: Math.min(filesz, Math.max(0, bytes.length - offset)), exec: Boolean(flags & 1), write: Boolean(flags & 2) });
  }

  const sections = [];
  if (shoff && shnum && shentsize && shoff + shnum * shentsize <= bytes.length) {
    const raw = [];
    for (let i = 0; i < Math.min(shnum, MAX_SECTIONS); i++) {
      const o = shoff + i * shentsize;
      raw.push({
        nameOff: r.u32(o),
        type: r.u32(o + 4),
        flags: r.ptr(o + 8, P),
        addr: r.ptr(is64 ? o + 16 : o + 12, P),
        offset: r.ptr(is64 ? o + 24 : o + 16, P),
        size: r.ptr(is64 ? o + 32 : o + 20, P),
        link: r.u32(is64 ? o + 40 : o + 24),
        entsize: r.ptr(is64 ? o + 56 : o + 36, P),
      });
    }
    const strtab = raw[shstrndx];
    for (const s of raw) {
      let name = '';
      if (strtab) { try { name = r.cstr(strtab.offset + s.nameOff, 256); } catch { name = ''; } }
      const nobits = s.type === 8;
      sections.push({
        name, type: s.type, addr: s.addr, size: s.size, offset: s.offset,
        fileSize: nobits ? 0 : Math.min(s.size, Math.max(0, bytes.length - s.offset)),
        exec: Boolean(s.flags & 4), write: Boolean(s.flags & 1), alloc: Boolean(s.flags & 2), link: s.link, entsize: s.entsize,
      });
    }
  }

  const symbols = [];
  const readSyms = (sec, dynamic) => {
    const strs = sections[sec.link];
    if (!strs || !sec.entsize) return;
    const n = Math.min(Math.floor(sec.fileSize / sec.entsize), MAX_SYMBOLS - symbols.length);
    for (let i = 1; i < n; i++) {
      const o = sec.offset + i * sec.entsize;
      const nameOff = r.u32(o);
      const value = is64 ? r.u64(o + 8) : r.u32(o + 4);
      const size = is64 ? r.u64(o + 16) : r.u32(o + 8);
      const info = is64 ? r.u8(o + 4) : r.u8(o + 12);
      const shndx = is64 ? r.u16(o + 6) : r.u16(o + 14);
      let name;
      try { name = r.cstr(strs.offset + nameOff, 1024); } catch { continue; }
      if (!name) continue;
      symbols.push({ name, addr: value, size, func: (info & 0xf) === 2, dynamic, undef: shndx === 0 });
    }
  };
  for (const s of sections) {
    if (s.type === 2) readSyms(s, false);
    else if (s.type === 11) readSyms(s, true);
  }

  // DT_NEEDED: dinamik bağlı kitaplıklar (Go statik ikililerinde genellikle yok)
  const libs = [];
  const dyn = sections.find((s) => s.type === 6);
  const dynstr = dyn ? sections[dyn.link] : null;
  if (dyn && dynstr) {
    const ent = is64 ? 16 : 8;
    for (let o = dyn.offset; o + ent <= dyn.offset + dyn.fileSize && libs.length < 256; o += ent) {
      const tag = r.ptr(o, P);
      if (tag === 0) break;
      if (tag === 1) { try { libs.push(r.cstr(dynstr.offset + r.ptr(o + P, P), 256)); } catch { /* bozuk girdi atlanır */ } }
    }
  }
  const imports = symbols.filter((s) => s.dynamic && s.undef).map((s) => ({ lib: '', name: s.name }));

  return {
    format: 'elf',
    bits: is64 ? 64 : 32,
    le: data === 1,
    arch: MACHINES[machine] ?? `elf-${machine}`,
    os: 'linux',
    kind: type === 3 ? 'dyn' : type === 2 ? 'exec' : `type-${type}`,
    entry,
    regions: regions.length ? regions : sections.filter((s) => s.alloc).map((s) => ({ name: s.name, addr: s.addr, memSize: s.size, fileOff: s.offset, fileSize: s.fileSize, exec: s.exec, write: s.write })),
    sections,
    symbols,
    imports,
    libs,
    noSections: sections.length === 0,
    phdrEnd: phoff + phnum * phentsize,
  };
}
