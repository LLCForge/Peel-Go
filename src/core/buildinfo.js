// runtime.buildinfo: "\xff Go buildinf:" başlığı (32 bayt). 1.18+ dizgeler satır içi (uvarint uzunluk + bayt),
// öncesinde başlıkta sürüm ve modinfo Go dizgelerine işaretçiler bulunur. modinfo metni çerçeve dizgeleri arasında:
//   path <ana paket>   mod <yol> <sürüm> <toplam>   dep <yol> <sürüm> <toplam>   => <yerine geçen> <sürüm> <toplam>
//   build <anahtar>=<değer>   (-ldflags, GOOS, GOARCH, CGO_ENABLED, vcs, vcs.revision, vcs.time, vcs.modified …)
import { ascii, findAll, reader, decode } from './reader.js';

const MAGIC = ascii('\xff Go buildinf:');
const MAX_STR = 1 << 20;

function readGoString(img, addr, le, P) {
  const hdr = img.read(addr, 2 * P);
  if (!hdr) return null;
  const r = reader(hdr, le);
  const p = r.ptr(0, P);
  const n = r.ptr(P, P);
  if (n === 0) return '';
  if (n > MAX_STR) return null;
  const b = img.read(p, n);
  return b ? decode(b) : null;
}

/** @returns {null | { version, modinfo, raw: string, at: number, inline: boolean }} */
export function readBuildInfo(img) {
  const sec = img.section('.go.buildinfo', '__go_buildinfo');
  const hits = sec?.fileSize ? findAll(img.bytes.subarray(sec.offset, sec.offset + sec.fileSize), MAGIC, 1).map((o) => o + sec.offset) : [];
  if (!hits.length) hits.push(...findAll(img.bytes, MAGIC, 8));
  for (const off of hits) {
    // başlık 16 bayt hizalıdır; bozuk adaylar atlanır
    if (off + 32 > img.bytes.length) continue;
    const b = img.bytes;
    const P = b[off + 14];
    const flags = b[off + 15];
    let version = null;
    let mod = null;
    let inline = false;
    if (flags & 2) {
      inline = true;
      const r = reader(b, true);
      try {
        let p = off + 32;
        const [vl, n1] = r.uvarint(p);
        if (vl > MAX_STR) continue;
        p += n1;
        version = decode(r.slice(p, vl));
        p += vl;
        const [ml, n2] = r.uvarint(p);
        if (ml > MAX_STR) continue;
        p += n2;
        mod = decode(r.slice(p, ml));
      } catch { continue; }
    } else {
      if (P !== 4 && P !== 8) continue;
      const le = (flags & 1) === 0;
      const r = reader(b, le);
      try {
        version = readGoString(img, r.ptr(off + 16, P), le, P);
        mod = readGoString(img, r.ptr(off + 16 + P, P), le, P);
      } catch { continue; }
    }
    if (version == null) continue;
    // çerçeve: 16 bayt başlangıç + 16 bayt bitiş dizgesi (sondan 17. karakter '\n')
    let modinfo = '';
    if (mod && mod.length >= 33 && mod[mod.length - 17] === '\n') modinfo = mod.slice(16, -16);
    return { version, modinfo, at: off, inline, ...parseModinfo(modinfo) };
  }
  return null;
}

/** modinfo metni → { path, main, deps, settings } */
export function parseModinfo(text) {
  const out = { path: null, main: null, deps: [], settings: {} };
  let last = null;
  for (const line of String(text).split('\n').slice(0, 20000)) {
    const f = line.split('\t');
    if (f[0] === 'path') out.path = f[1] ?? null;
    else if (f[0] === 'mod') { out.main = { path: f[1] ?? '', version: f[2] ?? '', sum: f[3] ?? '' }; last = out.main; }
    else if (f[0] === 'dep') { last = { path: f[1] ?? '', version: f[2] ?? '', sum: f[3] ?? '' }; out.deps.push(last); }
    else if (f[0] === '=>' && last) last.replace = { path: f[1] ?? '', version: f[2] ?? '', sum: f[3] ?? '' };
    else if (f[0] === 'build') {
      const kv = f.slice(1).join('\t');
      const i = kv.indexOf('=');
      if (i > 0) out.settings[kv.slice(0, i)] = unquote(kv.slice(i + 1));
    }
  }
  return out;
}

const unquote = (v) => {
  if (!/^".*"$/.test(v)) return v;
  try { return JSON.parse(v); } catch { return v.slice(1, -1); }
};

/** "go1.21.3" → [1, 21, 3]; tanınmazsa null */
export function goVersion(v) {
  const m = /^go(\d+)\.(\d+)(?:\.(\d+))?/.exec(String(v ?? ''));
  return m ? [Number(m[1]), Number(m[2]), Number(m[3] ?? 0)] : null;
}
