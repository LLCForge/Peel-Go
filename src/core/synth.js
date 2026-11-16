// Sentetik Go ikilisi üretici: geçerli pclntab (1.2 / 1.16 / 1.18 / 1.20 düzenleri), runtime.buildinfo (satır içi ya
// da işaretçili eski biçim) ve elle derlenmiş amd64 kod gövdeleri taşıyan küçük ELF / PE / Mach-O dosyaları.
// Kullanım: tarayıcı örneği (src/sample.js) ve testler (eski Go sürümlerinin düzenleri, UPX ve -tiny izleri).
// Üretilen kod hiçbir yerde çalıştırılmaz; yalnızca ayrıştırıcıların ve öykünücünün girdisidir.

const MAGIC = { '1.2': 0xfffffffb, '1.16': 0xfffffffa, '1.18': 0xfffffff0, '1.20': 0xfffffff1 };
const enc = new TextEncoder();

class Buf {
  constructor(le = true) { this.a = []; this.le = le; }
  get length() { return this.a.length; }
  u8(v) { this.a.push(v & 0xff); return this; }
  u16(v) { return this.int(v, 2); }
  u32(v) { return this.int(v, 4); }
  u64(v) { return this.int(v, 8); }
  ptr(v, P) { return this.int(v, P); }
  int(v, n) {
    const b = [];
    let x = BigInt.asUintN(n * 8, BigInt(v));
    for (let i = 0; i < n; i++) { b.push(Number(x & 0xffn)); x >>= 8n; }
    this.a.push(...(this.le ? b : b.reverse()));
    return this;
  }
  bytes(b) { for (const x of b) this.a.push(x); return this; }
  str(s) { return this.bytes(enc.encode(s)).u8(0); }
  pad(n, v = 0) { while (this.a.length % n) this.a.push(v); return this; }
  zero(n) { for (let i = 0; i < n; i++) this.a.push(0); return this; }
  uvarint(v) { do { let b = v % 128; v = Math.floor(v / 128); if (v) b |= 0x80; this.a.push(b); } while (v); return this; }
  patch(at, v, n) {
    let x = BigInt.asUintN(n * 8, BigInt(v));
    const b = [];
    for (let i = 0; i < n; i++) { b.push(Number(x & 0xffn)); x >>= 8n; }
    (this.le ? b : b.reverse()).forEach((y, i) => { this.a[at + i] = y; });
  }
  out() { return Uint8Array.from(this.a); }
}

/** pcvalue tablosu: [[uzunluk, değer], ...] (değer ilk -1'den farkla, pc farkı quantum'a bölünmüş) */
function pcvalue(steps, quantum) {
  const b = new Buf();
  let val = -1;
  for (const [len, v] of steps) {
    const d = v - val;
    b.uvarint(d >= 0 ? d * 2 : -d * 2 - 1).uvarint(Math.ceil(len / quantum));
    val = v;
  }
  return b.u8(0).out();
}

/**
 * pclntab üretir.
 * @param {{ version, ptrSize, le, quantum, text, funcs: [{ name, entry, size, file, line, lines? }] }} o
 *   lines: [[uzunluk, satır]] (yoksa tek satır)
 */
export function buildPclntab({ version, ptrSize: P = 8, le = true, quantum = 1, text, funcs }) {
  const files = [...new Set(funcs.map((f) => f.file ?? ''))];
  const end = funcs.at(-1).entry + funcs.at(-1).size;
  const lineSteps = (f) => f.lines ?? [[f.size, f.line ?? 1]];
  if (version === '1.2') {
    // başlık + functab + _func'lar + adlar + dosyalar + pc tabloları; tüm konumlar pclntab başına göre
    const b = new Buf(le);
    b.u32(MAGIC['1.2']).u8(0).u8(0).u8(quantum).u8(P).ptr(funcs.length, P);
    const ftab = b.length;
    b.zero(funcs.length * 2 * P + P + 4);
    const funcOffs = [];
    const fixups = [];
    for (const f of funcs) {
      b.pad(P);
      funcOffs.push(b.length);
      fixups.push(b.length);
      b.ptr(f.entry, P).u32(0).u32(0).u32(0).u32(0).u32(0).u32(0).u32(0).u32(0);
    }
    const nameOffs = funcs.map((f) => { const o = b.length; b.str(f.name); return o; });
    const fileOffs = files.map((f) => { const o = b.length; b.str(f); return o; });
    b.pad(4);
    const filetab = b.length;
    b.u32(files.length + 1);
    for (const o of fileOffs) b.u32(o);
    funcs.forEach((f, i) => {
      const at = fixups[i];
      const pcfile = b.length;
      b.bytes(pcvalue([[f.size, files.indexOf(f.file ?? '') + 1]], quantum));
      const pcln = b.length;
      b.bytes(pcvalue(lineSteps(f), quantum));
      b.patch(at + P, nameOffs[i], 4);
      b.patch(at + P + 16, pcfile, 4);
      b.patch(at + P + 20, pcln, 4);
      b.patch(ftab + i * 2 * P, f.entry, P);
      b.patch(ftab + i * 2 * P + P, funcOffs[i], P);
    });
    b.patch(ftab + funcs.length * 2 * P, end, P);
    b.patch(ftab + funcs.length * 2 * P + P, filetab, 4);
    return b.out();
  }
  // 1.16+: ayrı tablolar
  const names = new Buf(le);
  const nameOffs = funcs.map((f) => { const o = names.length; names.str(f.name); return o; });
  const filetab = new Buf(le);
  const fileOffs = files.map((f) => { const o = filetab.length; filetab.str(f); return o; });
  const cutab = new Buf(le);
  for (const o of fileOffs) cutab.u32(o);
  const pctab = new Buf(le).u8(0); // 0 konumu "tablo yok" demektir
  const tabs = funcs.map((f) => {
    const pcfile = pctab.length;
    pctab.bytes(pcvalue([[f.size, files.indexOf(f.file ?? '')]], quantum));
    const pcln = pctab.length;
    pctab.bytes(pcvalue(lineSteps(f), quantum));
    return { pcfile, pcln };
  });
  const rel = version !== '1.16';
  const hdr = new Buf(le);
  hdr.u32(MAGIC[version]).u8(0).u8(0).u8(quantum).u8(P).ptr(funcs.length, P).ptr(files.length, P);
  if (rel) hdr.ptr(version === '1.20' ? 0 : text, P); // 1.20+ (Go 1.22+ gibi) textStart yazılmaz
  const hdrSize = hdr.length + 5 * P;
  const offs = {};
  let cur = hdrSize;
  for (const [k, part] of [['name', names], ['cu', cutab], ['file', filetab], ['pc', pctab]]) { offs[k] = cur; cur += part.length; cur += (8 - (cur % 8)) % 8; }
  offs.pcln = cur;
  for (const k of ['name', 'cu', 'file', 'pc', 'pcln']) hdr.ptr(offs[k], P);
  const ft = new Buf(le);
  const entW = rel ? 4 : P;
  ft.zero(funcs.length * 2 * entW + entW);
  const fpos = [];
  for (let i = 0; i < funcs.length; i++) {
    ft.pad(4);
    fpos.push(ft.length);
    const f = funcs[i];
    if (rel) ft.u32(f.entry - text); else ft.ptr(f.entry, P);
    ft.u32(nameOffs[i]).u32(0).u32(0).u32(0).u32(tabs[i].pcfile).u32(tabs[i].pcln).u32(0).u32(0);
    if (version === '1.20') ft.u32(f.line ?? 1);
    ft.u8(0).u8(0).u8(0).u8(0);
  }
  funcs.forEach((f, i) => {
    if (rel) { ft.patch(i * 8, f.entry - text, 4); ft.patch(i * 8 + 4, fpos[i], 4); } else { ft.patch(i * 2 * P, f.entry, P); ft.patch(i * 2 * P + P, fpos[i], P); }
  });
  if (rel) ft.patch(funcs.length * 8, end - text, 4); else ft.patch(funcs.length * 2 * P, end, P);
  const all = new Buf(le).bytes(hdr.a);
  for (const [k, part] of [['name', names], ['cu', cutab], ['file', filetab], ['pc', pctab], ['pcln', ft]]) { while (all.length < offs[k]) all.u8(0); all.bytes(part.a); }
  return all.out();
}

const SENTINEL_START = [0x30, 0x77, 0xaf, 0x0c, 0x92, 0x74, 0x08, 0x02, 0x41, 0xe1, 0xc1, 0x07, 0xe6, 0xd6, 0x18, 0xe6];
const SENTINEL_END = [0xf9, 0x32, 0x43, 0x31, 0x86, 0x18, 0x20, 0x72, 0x00, 0x82, 0x42, 0x10, 0x41, 0x16, 0xd8, 0xf2];

/** buildinfo bloğu. inline=false ise işaretçili eski biçim: dizge başlıkları ve verileri bloğun ardına, base adresine göre */
export function buildBuildinfo({ version, modinfo = '', inline = true, P = 8, le = true, base = 0 }) {
  const mod = modinfo ? [...SENTINEL_START, ...enc.encode(modinfo), ...SENTINEL_END] : [];
  const b = new Buf(le);
  b.u8(0xff).bytes(enc.encode(' Go buildinf:'));
  b.u8(P).u8(inline ? 2 : le ? 0 : 1);
  if (inline) {
    b.zero(16);
    const v = enc.encode(version);
    b.uvarint(v.length).bytes(v).uvarint(mod.length).bytes(mod);
    return b.out();
  }
  // eski biçim: [başlık 32][vers hdr 2P][mod hdr 2P][vers][mod]
  const vh = 32;
  const mh = vh + 2 * P;
  const vd = mh + 2 * P;
  const v = enc.encode(version);
  const md = vd + v.length;
  b.ptr(base + vh, P).ptr(base + mh, P);
  while (b.length < 32) b.u8(0);
  b.ptr(base + vd, P).ptr(v.length, P).ptr(base + md, P).ptr(mod.length, P).bytes(v).bytes(mod);
  return b.out();
}

/**
 * Kapsayıcı yazarı. sections: [{ name, data, exec?, write? }] ilk bölüm .text olmalı.
 * @returns {{ bytes: Uint8Array, addrs: Record<string, number> }}
 */
export function buildContainer({ format = 'elf', bits = 64, le = true, arch = 'amd64', sections, base, noSectionHeaders = false, extra = null }) {
  if (format === 'elf') return elf({ bits, le, arch, sections, base: base ?? (bits === 64 ? 0x400000 : 0x8048000), noSectionHeaders, extra });
  if (format === 'pe') return pe({ bits, arch, sections, base: base ?? (bits === 64 ? 0x140000000 : 0x400000) });
  return macho({ arch, sections, base: base ?? 0x100000000 });
}

/** Bölümlerin sanal adresleri (dosya ile aynı düzende, sayfa hizalı) */
export function layout(sections, base, first = 0x1000) {
  const addrs = {};
  let a = base + first;
  for (const s of sections) {
    a = Math.ceil(a / 0x1000) * 0x1000;
    addrs[s.name] = a;
    a += Math.max(1, s.data.length);
  }
  return addrs;
}

const ELF_MACHINE = { amd64: 62, '386': 3, arm64: 183, arm: 40, ppc64: 21 };
function elf({ bits, le, arch, sections, base, noSectionHeaders, extra }) {
  const P = bits === 64 ? 8 : 4;
  const ehsz = bits === 64 ? 64 : 52;
  const phsz = bits === 64 ? 56 : 32;
  const shsz = bits === 64 ? 64 : 40;
  const nph = 2;
  const addrs = layout(sections, base);
  // dosya düzeni: [ehdr][phdr x2][extra?] ... bölümler (adres - base ile aynı konumda)
  const end = Math.max(...sections.map((s) => addrs[s.name] - base + s.data.length));
  const shstr = new Buf();
  shstr.u8(0);
  const nameOff = {};
  for (const s of [...sections.map((x) => x.name), '.shstrtab']) { nameOff[s] = shstr.length; shstr.str(s); }
  const shstrOff = end;
  const shoff = Math.ceil((shstrOff + shstr.length) / 8) * 8;
  const total = noSectionHeaders ? end : shoff + (sections.length + 2) * shsz;
  const out = new Uint8Array(total);
  const w = (at, buf) => out.set(buf, at);
  const h = new Buf(le);
  h.bytes([0x7f, 0x45, 0x4c, 0x46, bits === 64 ? 2 : 1, le ? 1 : 2, 1, 0]).zero(8);
  h.u16(2).u16(ELF_MACHINE[arch] ?? 62).u32(1).ptr(addrs[sections[0].name], P).ptr(ehsz, P).ptr(noSectionHeaders ? 0 : shoff, P);
  h.u32(0).u16(ehsz).u16(phsz).u16(nph).u16(shsz).u16(noSectionHeaders ? 0 : sections.length + 2).u16(noSectionHeaders ? 0 : sections.length + 1);
  w(0, h.out());
  // PT_LOAD: kod (R+X) ve veri (R+W)
  const textEnd = addrs[sections[0].name] + sections[0].data.length;
  const ph = new Buf(le);
  const seg = (flags, off, va, sz) => {
    if (bits === 64) ph.u32(1).u32(flags).u64(off).u64(va).u64(va).u64(sz).u64(sz).u64(0x1000);
    else ph.u32(1).u32(off).u32(va).u32(va).u32(sz).u32(sz).u32(flags).u32(0x1000);
  };
  seg(5, 0, base, textEnd - base);
  const dataStart = addrs[sections[1]?.name] ?? textEnd;
  seg(6, dataStart - base, dataStart, end - (dataStart - base));
  w(ehsz, ph.out());
  if (extra) w(ehsz + nph * phsz, extra);
  for (const s of sections) w(addrs[s.name] - base, s.data);
  if (!noSectionHeaders) {
    w(shstrOff, shstr.out());
    const sh = new Buf(le);
    sh.zero(shsz);
    for (const s of sections) {
      const flags = 2 | (s.exec ? 4 : 0) | (s.write ? 1 : 0);
      if (bits === 64) sh.u32(nameOff[s.name]).u32(1).u64(flags).u64(addrs[s.name]).u64(addrs[s.name] - base).u64(s.data.length).u32(0).u32(0).u64(16).u64(0);
      else sh.u32(nameOff[s.name]).u32(1).u32(flags).u32(addrs[s.name]).u32(addrs[s.name] - base).u32(s.data.length).u32(0).u32(0).u32(16).u32(0);
    }
    if (bits === 64) sh.u32(nameOff['.shstrtab']).u32(3).u64(0).u64(0).u64(shstrOff).u64(shstr.length).u32(0).u32(0).u64(1).u64(0);
    else sh.u32(nameOff['.shstrtab']).u32(3).u32(0).u32(0).u32(shstrOff).u32(shstr.length).u32(0).u32(0).u32(1).u32(0);
    w(shoff, sh.out());
  }
  return { bytes: out, addrs };
}

const PE_MACHINE = { amd64: 0x8664, '386': 0x14c, arm64: 0xaa64 };
function pe({ bits, arch, sections, base }) {
  const plus = bits === 64;
  const optSize = plus ? 240 : 224;
  const hdrEnd = 0x80 + 4 + 20 + optSize + sections.length * 40;
  const fileAlign = 0x200;
  let off = Math.ceil(hdrEnd / fileAlign) * fileAlign;
  const addrs = layout(sections, base);
  const raw = sections.map((s) => { const o = off; off += Math.ceil(Math.max(1, s.data.length) / fileAlign) * fileAlign; return o; });
  const out = new Uint8Array(off);
  out[0] = 0x4d; out[1] = 0x5a;
  new DataView(out.buffer).setUint32(0x3c, 0x80, true);
  const h = new Buf(true);
  h.bytes([0x50, 0x45, 0, 0]).u16(PE_MACHINE[arch] ?? 0x8664).u16(sections.length).u32(0).u32(0).u32(0).u16(optSize).u16(plus ? 0x22 : 0x102);
  h.u16(plus ? 0x20b : 0x10b).u8(0).u8(0).u32(0).u32(0).u32(0).u32(addrs[sections[0].name] - base).u32(0x1000);
  if (!plus) h.u32(0);
  h.ptr(base, plus ? 8 : 4).u32(0x1000).u32(fileAlign).u16(6).u16(0).u16(0).u16(0).u16(6).u16(0).u32(0);
  const imageSize = Math.ceil((Math.max(...sections.map((s) => addrs[s.name] + s.data.length)) - base) / 0x1000) * 0x1000;
  h.u32(imageSize).u32(Math.ceil(hdrEnd / fileAlign) * fileAlign).u32(0).u16(3).u16(0x8160);
  for (let i = 0; i < 4; i++) h.ptr(0x100000, plus ? 8 : 4);
  h.u32(0).u32(16).zero(16 * 8);
  for (const [i, s] of sections.entries()) {
    const name = enc.encode(s.name).slice(0, 8);
    h.bytes(name).zero(8 - name.length).u32(s.data.length).u32(addrs[s.name] - base).u32(Math.ceil(Math.max(1, s.data.length) / fileAlign) * fileAlign).u32(raw[i]).u32(0).u32(0).u16(0).u16(0);
    h.u32(s.exec ? 0x60000020 : s.write ? 0xc0000040 : 0x40000040);
  }
  out.set(h.out(), 0x80);
  sections.forEach((s, i) => out.set(s.data, raw[i]));
  return { bytes: out, addrs };
}

function macho({ arch, sections, base }) {
  const cpu = arch === 'arm64' ? 0x0100000c : 0x01000007;
  const addrs = layout(sections, base);
  const text = sections.filter((s) => s.exec || !s.write);
  const data = sections.filter((s) => !s.exec && s.write);
  const segCmd = (name, secs) => {
    const b = new Buf(true);
    const lo = secs.length ? Math.min(...secs.map((s) => addrs[s.name])) : base;
    const hi = secs.length ? Math.max(...secs.map((s) => addrs[s.name] + s.data.length)) : base;
    const nm = enc.encode(name);
    b.u32(0x19).u32(72 + 80 * secs.length).bytes(nm).zero(16 - nm.length);
    b.u64(lo).u64(Math.ceil((hi - lo) / 0x1000) * 0x1000).u64(lo - base).u64(hi - lo).u32(secs.some((s) => s.exec) ? 5 : 3).u32(secs.some((s) => s.exec) ? 5 : 3).u32(secs.length).u32(0);
    for (const s of secs) {
      const sn = enc.encode(s.name).slice(0, 16);
      b.bytes(sn).zero(16 - sn.length).bytes(nm).zero(16 - nm.length).u64(addrs[s.name]).u64(s.data.length).u32(addrs[s.name] - base).u32(4).u32(0).u32(0).u32(s.exec ? 0x80000400 : 0).u32(0).u32(0).u32(0);
    }
    return b.out();
  };
  const cmds = [segCmd('__TEXT', text), ...(data.length ? [segCmd('__DATA', data)] : [])];
  const sizeofcmds = cmds.reduce((n, c) => n + c.length, 0);
  const end = Math.max(...sections.map((s) => addrs[s.name] - base + s.data.length));
  const out = new Uint8Array(end);
  const h = new Buf(true);
  h.u32(0xfeedfacf).u32(cpu).u32(3).u32(2).u32(cmds.length).u32(sizeofcmds).u32(0x200085).u32(0);
  out.set(h.out(), 0);
  let o = 32;
  for (const c of cmds) { out.set(c, o); o += c.length; }
  for (const s of sections) out.set(s.data, addrs[s.name] - base);
  return { bytes: out, addrs };
}

/**
 * Tam bir sentetik Go ikilisi: fonksiyon gövdeleri (code verilmezse RET + INT3 dolgusu), pclntab, buildinfo, rodata.
 * @param {{ format?, bits?, le?, arch?, pclntab?: '1.2'|'1.16'|'1.18'|'1.20', funcs: Array<{ name, file?, line?, code?: (addrs, ctx) => Uint8Array, size? }>,
 *           rodata?: Uint8Array, buildinfo?: { version, modinfo?, inline? } | null, pclntabSection?: boolean, extraSections?: [] }} o
 */
export function buildGoBinary(o) {
  const { format = 'elf', bits = 64, le = true, arch = 'amd64', pclntab: version = '1.20', funcs, rodata = new Uint8Array(16), buildinfo = null, pclntabSection = true, extraSections = [] } = o;
  const P = bits === 64 ? 8 : 4;
  const base = o.base ?? (format === 'elf' ? (bits === 64 ? 0x400000 : 0x8048000) : format === 'pe' ? (bits === 64 ? 0x140000000 : 0x400000) : 0x100000000);
  const quantum = arch === 'arm64' || arch === 'arm' ? 4 : 1;
  // iki aşama: önce boyutlar (adresler kod üreticisine verilir), sonra gerçek baytlar
  const sizeOf = (f) => Math.ceil((f.size ?? 16) / 16) * 16;
  const textAddr = base + 0x1000;
  let a = textAddr;
  const placed = funcs.map((f) => { const e = a; a += sizeOf(f); return { ...f, entry: e, size: sizeOf(f) }; });
  const fnAddr = Object.fromEntries(placed.map((f) => [f.name, f.entry]));
  const pcln = buildPclntab({ version, ptrSize: P, le, quantum, text: textAddr, funcs: placed });
  const names = { elf: ['.text', '.rodata', '.gopclntab', '.go.buildinfo', '.noptrdata'], pe: ['.text', '.rdata', '.pcln', '.data', '.bss'], macho: ['__text', '__rodata', '__gopclntab', '__go_buildinfo', '__noptrdata'] }[format];
  if (!pclntabSection) names[2] = format === 'elf' ? '.data.rel.ro' : format === 'pe' ? '.rdata2' : '__const';
  const sec = (i, data, extra = {}) => ({ name: names[i], data, ...extra });
  const draft = [sec(0, new Uint8Array(a - textAddr), { exec: true }), sec(1, rodata), sec(2, pcln), sec(3, new Uint8Array(512), { write: true }), sec(4, new Uint8Array(64), { write: true }), ...extraSections];
  const addrs = layout(draft, base);
  const ctx = { fn: fnAddr, addrs: { rodata: addrs[names[1]], text: textAddr } };
  const text = new Uint8Array(a - textAddr).fill(0xcc);
  for (const f of placed) {
    const code = f.code ? f.code(f.entry, ctx) : Uint8Array.of(0xc3);
    if (code.length > f.size) throw new Error(`${f.name}: kod ${code.length} > ${f.size}`);
    text.set(code, f.entry - textAddr);
  }
  const bi = buildinfo ? buildBuildinfo({ ...buildinfo, P, le, base: addrs[names[3]] }) : new Uint8Array(32);
  const sections = [sec(0, text, { exec: true }), sec(1, rodata), sec(2, pcln), sec(3, bi, { write: true }), sec(4, new Uint8Array(64), { write: true }), ...extraSections];
  const built = buildContainer({ format, bits, le, arch, sections, base });
  return { ...built, funcs: placed, text: textAddr };
}

// ── elle derlenmiş amd64 parçaları ──
const le32 = (v) => [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
const rel32 = (from, to) => le32((to - from) | 0);

/**
 * garble "simple" ailesi biçiminde çözme gövdesi: veri ve anahtar yığına yazılır, xor döngüsü, slicebytetostring.
 * @param {string} plain gizlenecek dizge (en çok 48 bayt)
 */
export function xorLiteralFunc(plain, keySeed = 0x5a) {
  const p = enc.encode(plain);
  if (p.length > 48) throw new Error('en çok 48 bayt');
  const key = [...p].map((_, i) => (keySeed * (i + 7) + 0x3d) & 0xff);
  const data = [...p].map((b, i) => b ^ key[i]);
  return (entry, ctx) => {
    const c = [0x48, 0x83, 0xec, 0x78];
    // veri [rsp+0x08..0x37], anahtar [rsp+0x40..0x6f]
    data.forEach((b, i) => c.push(0xc6, 0x44, 0x24, 0x08 + i, b));
    key.forEach((b, i) => c.push(0xc6, 0x44, 0x24, 0x40 + i, b));
    c.push(0x31, 0xc0);
    const loop = c.length;
    c.push(0x0f, 0xb6, 0x4c, 0x04, 0x40, 0x0f, 0xb6, 0x54, 0x04, 0x08, 0x31, 0xca, 0x88, 0x54, 0x04, 0x08, 0x48, 0xff, 0xc0, 0x48, 0x83, 0xf8, p.length);
    c.push(0x7c, (loop - (c.length + 2)) & 0xff);
    c.push(0x31, 0xc0, 0x48, 0x8d, 0x5c, 0x24, 0x08, 0xb9, ...le32(p.length));
    c.push(0xe8, ...rel32(entry + c.length + 5, ctx.fn['runtime.slicebytetostring']));
    c.push(0x48, 0x83, 0xc4, 0x78, 0xc3);
    return Uint8Array.from(c);
  };
}

/** Bir rodata dizgesini Go gibi yükleyip (LEA rax + MOV ebx, uzunluk) bir fonksiyona veren gövde */
export function stringCallFunc(rodataOff, len, callee, then = []) {
  return (entry, ctx) => {
    const c = [0x48, 0x83, 0xec, 0x18];
    const lea = entry + c.length;
    c.push(0x48, 0x8d, 0x05, ...rel32(lea + 7, ctx.addrs.rodata + rodataOff));
    c.push(0xbb, ...le32(len));
    c.push(0xe8, ...rel32(entry + c.length + 5, ctx.fn[callee]));
    for (const name of then) c.push(0xe8, ...rel32(entry + c.length + 5, ctx.fn[name]));
    c.push(0x48, 0x83, 0xc4, 0x18, 0xc3);
    return Uint8Array.from(c);
  };
}
