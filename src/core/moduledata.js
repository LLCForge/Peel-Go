// runtime.firstmoduledata: veri bölgelerinde pclntab adresini gösteren işaretçi aranır ve sürüme göre düzen
// doğrulanarak seçilir. Sonra typelinks (runtime._type adları) ve itablinks (arayüz ← somut tür eşleşmeleri) okunur.
import { reader } from './reader.js';

// alan konumları işaretçi boyutu biriminde (sözcük); dilimler 3 sözcük
const LAYOUTS = [
  { id: '1.26', min: 16, minpc: 20, maxpc: 21, text: 22, etext: 23, types: 37, etypes: 38, typelinks: 45, itablinks: 48 },
  { id: '1.20', min: 16, minpc: 20, maxpc: 21, text: 22, etext: 23, types: 37, etypes: 38, typelinks: 44, itablinks: 47 },
  { id: '1.18', min: 16, minpc: 20, maxpc: 21, text: 22, etext: 23, types: 35, etypes: 36, typelinks: 42, itablinks: 45 },
  { id: '1.16', min: 16, minpc: 20, maxpc: 21, text: 22, etext: 23, types: 35, etypes: 36, typelinks: 40, itablinks: 43 },
  { id: '1.7', min: 2, minpc: 10, maxpc: 11, text: 12, etext: 13, types: 25, etypes: 26, typelinks: 30, itablinks: 33 },
];
export const LIMITS = { maxTypes: 50_000, maxItabs: 50_000, maxCandidates: 256 };

const KINDS = ['invalid', 'bool', 'int', 'int8', 'int16', 'int32', 'int64', 'uint', 'uint8', 'uint16', 'uint32', 'uint64', 'uintptr',
  'float32', 'float64', 'complex64', 'complex128', 'array', 'chan', 'func', 'interface', 'map', 'ptr', 'slice', 'string', 'struct', 'unsafe.Pointer'];

/**
 * @param {object} img Image
 * @param {{ pclntabAddr: number, version: string, funcnameOff?: number, goMinor?: number }} o
 * @returns {null | { addr, layout, text, etext, minpc, maxpc, types, etypes, typelinks: number, itablinks: number, typeNames, itabs }}
 */
export function findModuledata(img, { pclntabAddr, version, funcnameOff = null, goMinor = null }) {
  if (pclntabAddr == null) return null;
  const P = img.ptrSize;
  const pat = new Uint8Array(P);
  const dv = new DataView(pat.buffer);
  if (P === 8) dv.setBigUint64(0, BigInt(pclntabAddr), img.le);
  else dv.setUint32(0, pclntabAddr, img.le);
  const dataRegions = img.regions.filter((r) => !r.exec && r.fileSize);
  let tried = 0;
  for (const reg of dataRegions) {
    const buf = img.bytes.subarray(reg.fileOff, reg.fileOff + reg.fileSize);
    for (let i = buf.indexOf(pat[0]); i >= 0 && tried < LIMITS.maxCandidates; i = buf.indexOf(pat[0], i + 1)) {
      if (i % P) continue;
      let ok = true;
      for (let j = 1; j < P; j++) if (buf[i + j] !== pat[j]) { ok = false; break; }
      if (!ok) continue;
      tried++;
      const md = tryLayouts(img, reg.addr + i, { version, pclntabAddr, funcnameOff, goMinor });
      if (md) return md;
    }
  }
  return null;
}

function tryLayouts(img, addr, { version, pclntabAddr, funcnameOff, goMinor }) {
  const P = img.ptrSize;
  const words = img.read(addr, 52 * P);
  if (!words) return null;
  const r = reader(words, img.le);
  const w = (i) => r.ptr(i * P, P);
  const candidates = version === '1.2' ? LAYOUTS.filter((l) => l.id === '1.7')
    : version === '1.16' ? LAYOUTS.filter((l) => l.id === '1.16')
      : version === '1.18' ? LAYOUTS.filter((l) => l.id === '1.18')
        : (goMinor != null && goMinor < 26 ? ['1.20', '1.26'] : ['1.26', '1.20']).map((id) => LAYOUTS.find((l) => l.id === id));
  for (const L of candidates) {
    try {
      if (version !== '1.2' && funcnameOff != null && w(1) !== pclntabAddr + funcnameOff) continue;
      const minpc = w(L.minpc);
      const maxpc = w(L.maxpc);
      const text = w(L.text);
      const etext = w(L.etext);
      const types = w(L.types);
      const etypes = w(L.etypes);
      if (!(text <= minpc && minpc < maxpc && maxpc <= etext + 64 && types < etypes)) continue;
      const tl = [w(L.typelinks), w(L.typelinks + 1), w(L.typelinks + 2)];
      const il = [w(L.itablinks), w(L.itablinks + 1), w(L.itablinks + 2)];
      if (tl[1] !== tl[2] || il[1] !== il[2] || tl[1] > LIMITS.maxTypes * 4 || il[1] > LIMITS.maxItabs * 4) continue;
      if (tl[1] && !img.regionOf(tl[0])) continue;
      if (il[1] && !img.regionOf(il[0])) continue;
      return { addr, layout: L.id, text, etext, minpc, maxpc, types, etypes, typelinksAddr: tl[0], typelinks: tl[1], itablinksAddr: il[0], itablinks: il[1] };
    } catch { /* sonraki düzen */ }
  }
  return null;
}

/** runtime.name: 1.17+ uvarint uzunluk, öncesi 2 bayt büyük sonlu uzunluk */
function readName(img, addr, varint) {
  const head = img.read(addr, 3);
  if (!head) return null;
  let len;
  let skip;
  if (varint) {
    const r = reader(img.read(addr, Math.min(11, 1 + 10)) ?? head, true);
    const [n, k] = r.uvarint(1);
    len = n;
    skip = 1 + k;
  } else {
    len = (head[1] << 8) | head[2];
    skip = 3;
  }
  if (len > 4096) return null;
  const b = img.read(addr + skip, len);
  if (!b) return null;
  let s = '';
  for (const c of b) { if (c < 0x20 && c !== 9) return null; s += String.fromCharCode(c); }
  return s;
}

/** Bir runtime._type'ın adı ve türü */
export function typeAt(img, md, addr, varint) {
  const P = img.ptrSize;
  const b = img.read(addr, 4 * P + 16);
  if (!b) return null;
  const r = reader(b, img.le);
  const tflag = r.u8(2 * P + 4);
  const kind = r.u8(2 * P + 7) & 0x1f;
  const str = r.i32(4 * P + 8);
  let name = readName(img, md.types + str, varint);
  if (name == null) return null;
  if (tflag & 2 && name.startsWith('*')) name = name.slice(1);
  // işaretçi, dilim, dizi ve kanal türlerinde öğe türü _type'tan hemen sonradır (adlı türler çoğu zaman yalnızca böyle görünür)
  const elem = ['ptr', 'slice', 'array', 'chan'].includes(KINDS[kind]) ? img.read(addr + 4 * P + 16, P) : null;
  return { addr, name, kind: KINDS[kind] ?? `kind${kind}`, size: r.ptr(0, P), elem: elem ? reader(elem, img.le).ptr(0, P) : null };
}

/** typelinks + itablinks → adlar (sınırlı) */
export function readTypes(img, md, { goMinor = null } = {}) {
  const P = img.ptrSize;
  const types = [];
  const itabs = [];
  const seen = new Set();
  if (!md) return { types, itabs };
  // ad kodlaması 1.17'de değişti; sürüm bilinmiyorsa ilk türde iki biçim de denenir
  let varint = goMinor == null ? null : goMinor >= 17;
  const tl = md.typelinks ? img.read(md.typelinksAddr, Math.min(md.typelinks, LIMITS.maxTypes) * 4) : null;
  if (tl) {
    const r = reader(tl, img.le);
    for (let i = 0; i < tl.length / 4; i++) {
      const addr = md.types + r.i32(i * 4);
      if (varint == null) varint = typeAt(img, md, addr, true) != null;
      const t = typeAt(img, md, addr, varint);
      if (!t || seen.has(t.addr)) continue;
      seen.add(t.addr);
      types.push(t);
      // öğe türleri bir düzey izlenir (ör. *main.Config → main.Config)
      const e = t.elem ? typeAt(img, md, t.elem, varint) : null;
      if (e && !seen.has(e.addr)) { seen.add(e.addr); types.push(e); }
    }
  }
  const il = md.itablinks ? img.read(md.itablinksAddr, Math.min(md.itablinks, LIMITS.maxItabs) * P) : null;
  if (il) {
    const r = reader(il, img.le);
    for (let i = 0; i < il.length / P; i++) {
      const itab = img.read(r.ptr(i * P, P), 2 * P);
      if (!itab) continue;
      const ir = reader(itab, img.le);
      const inter = typeAt(img, md, ir.ptr(0, P), varint ?? true);
      const concrete = typeAt(img, md, ir.ptr(P, P), varint ?? true);
      if (!inter || !concrete) continue;
      itabs.push({ iface: inter.name, type: concrete.name });
      // itab türleri (ve işaretçi öğeleri) de tür listesine girer: adlı kullanıcı türleri çoğu zaman yalnızca burada görünür
      for (const x of [inter, concrete, concrete.elem ? typeAt(img, md, concrete.elem, varint ?? true) : null]) {
        if (x && !seen.has(x.addr)) { seen.add(x.addr); types.push(x); }
      }
    }
  }
  return { types, itabs };
}
