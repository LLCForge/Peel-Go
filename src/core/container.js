// Kapsayıcı katmanı: ELF / PE / Mach-O biçimini tanır, ayrıştırır ve sanal adres → bayt eşlemesi sunar.
// Image = { format, bits, le, arch, os, kind, entry, regions, sections, symbols, imports, libs, bytes,
//           read(addr, len) → Uint8Array|null, section(name), regionOf(addr), ptrSize }
import { isElf, parseElf } from './elf.js';
import { isPe, parsePe } from './pe.js';
import { isMachO, parseMachO } from './macho.js';
import { ParseError } from './reader.js';

export function detectFormat(bytes) {
  if (isElf(bytes)) return 'elf';
  if (isPe(bytes)) return 'pe';
  if (isMachO(bytes)) return 'macho';
  return null;
}

/** @returns {object} Image; tanınmayan biçimde ParseError */
export function openImage(bytes) {
  const fmt = detectFormat(bytes);
  if (!fmt) throw new ParseError('ELF, PE ya da Mach-O değil');
  const img = fmt === 'elf' ? parseElf(bytes) : fmt === 'pe' ? parsePe(bytes) : parseMachO(bytes);
  img.bytes = bytes;
  img.ptrSize = img.bits === 64 ? 8 : 4;
  const regions = img.regions.filter((r) => r.memSize > 0).sort((a, b) => a.addr - b.addr);
  img.regions = regions;
  img.regionOf = (addr) => {
    let lo = 0;
    let hi = regions.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const r = regions[mid];
      if (addr < r.addr) hi = mid - 1;
      else if (addr >= r.addr + r.memSize) lo = mid + 1;
      else return r;
    }
    return null;
  };
  /** Sanal adresten len bayt; dosyada olmayan (bss) kısım sıfırdır. Bölge dışına taşarsa null. */
  img.read = (addr, len) => {
    const r = img.regionOf(addr);
    if (!r || len < 0 || addr + len > r.addr + r.memSize) return null;
    const rel = addr - r.addr;
    if (rel + len <= r.fileSize) return bytes.subarray(r.fileOff + rel, r.fileOff + rel + len);
    const out = new Uint8Array(len);
    if (rel < r.fileSize) out.set(bytes.subarray(r.fileOff + rel, r.fileOff + r.fileSize));
    return out;
  };
  /** adres → dosya konumu (yalnızca dosyada karşılığı varsa) */
  img.fileOffset = (addr) => {
    const r = img.regionOf(addr);
    if (!r || addr - r.addr >= r.fileSize) return -1;
    return r.fileOff + (addr - r.addr);
  };
  img.section = (...names) => img.sections.find((s) => names.includes(s.name)) ?? null;
  img.symbol = (name) => img.symbols.find((s) => s.name === name) ?? null;
  img.text = img.section('.text', '__text') ?? regions.find((r) => r.exec) ?? null;
  img.hasDwarf = img.sections.some((s) => /^(?:\.z?debug_|__z?debug_)/.test(s.name));
  return img;
}
