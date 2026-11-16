// Soyma geçişleri. Her geçiş ctx üzerinde çalışır ve sonucunu ctx'e yazar; hata yalnızca o geçişi düşürür.
// Sıra: kapsayıcı → buildinfo → pclntab → moduledata/türler → dizgeler → gizli dizgeler (amd64 öykünme).
// required: --only ile kapatılamaz (sonrakiler onlara dayanır).
import { openImage } from '../core/container.js';
import { detectUpx } from '../core/upx.js';
import { readBuildInfo, goVersion } from '../core/buildinfo.js';
import { findPclntab, parsePclntab } from '../core/pclntab.js';
import { findModuledata, readTypes } from '../core/moduledata.js';
import { extractStrings } from '../core/strings.js';
import { recoverLiterals } from '../core/literals.js';
import { packageOf, isStdPackage } from '../core/gonames.js';
import { ascii, findAll } from '../core/reader.js';

export const container = {
  id: 'container',
  required: true,
  run(ctx) {
    ctx.img = openImage(ctx.bytes);
    ctx.upx = detectUpx(ctx.img);
    const i = ctx.img;
    ctx.log(`${i.format} ${i.bits}-bit ${i.arch} · ${i.sections.length} bölüm · ${i.symbols.length} sembol · ${i.imports.length} içe aktarma`);
    if (ctx.upx) ctx.log(`UPX işaretleri: ${ctx.upx.markers.join(', ')}`, 'warn');
    return true;
  },
};

// buildinfo yoksa (Go < 1.13 ya da silinmiş) runtime.buildVersion dizgesi aranır
const VERSION_RE = /go1\.\d{1,2}(?:\.\d{1,2})?(?:(?:beta|rc)\d)?/;
function versionString(bytes) {
  for (const at of findAll(bytes, ascii('go1.'), 64)) {
    if (at > 0 && bytes[at - 1] >= 0x21 && bytes[at - 1] < 0x7f) continue;
    const m = VERSION_RE.exec(String.fromCharCode(...bytes.subarray(at, at + 16)));
    if (m && !/[\w.]/.test(String.fromCharCode(bytes[at + m[0].length] ?? 0))) return m[0];
  }
  return null;
}

export const buildinfo = {
  id: 'buildinfo',
  run(ctx) {
    const bi = readBuildInfo(ctx.img);
    ctx.buildinfo = bi;
    ctx.go.version = bi?.version || null;
    ctx.go.versionSource = bi?.version ? 'buildinfo' : null;
    if (!ctx.go.version) {
      const v = versionString(ctx.bytes);
      if (v) { ctx.go.version = v; ctx.go.versionSource = 'string'; }
    }
    if (bi) ctx.log(`buildinfo: ${bi.version}${bi.path ? ` · ${bi.path}` : ''} · ${bi.deps.length} bağımlılık${bi.modinfo ? '' : ' · modinfo boş'}`);
    return Boolean(ctx.go.version);
  },
};

export const pclntab = {
  id: 'pclntab',
  required: true,
  run(ctx) {
    const found = findPclntab(ctx.img);
    if (!found || found.error) {
      ctx.log(`pclntab bulunamadı${found?.error ? `: ${found.error}` : ''}`, 'warn');
      return false;
    }
    ctx.tab = found.tab;
    ctx.pclntab = { version: found.tab.version, how: found.cand.how, addr: found.cand.addr, fileOff: found.cand.fileOff, nfunc: found.tab.nfunc, nfiles: found.tab.nfiles };
    ctx.log(`pclntab ${found.tab.version} (${found.cand.how}) · ${found.tab.nfunc} fonksiyon`);
    buildFunctions(ctx);
    return true;
  },
};

/** pclntab fonksiyonları → zengin liste, paketler, dosyalar */
export function buildFunctions(ctx) {
  const syms = new Map();
  for (const s of ctx.img.symbols) if (s.func || !s.undef) syms.set(s.addr, s.name);
  const fns = [];
  const pkgs = new Map();
  for (const f of ctx.tab.funcs) {
    const d = ctx.tab.details(f);
    const pkg = packageOf(f.name);
    const std = isStdPackage(pkg);
    fns.push({ entry: f.entry, end: f.end, size: f.end - f.entry, name: f.name, pkg, std, file: d.file, startLine: d.startLine, endLine: d.endLine, symbol: syms.get(f.entry) ?? null });
    const p = pkgs.get(pkg) ?? { path: pkg, std, functions: 0, files: new Set() };
    p.functions++;
    if (d.file) p.files.add(d.file);
    pkgs.set(pkg, p);
  }
  ctx.functions = fns;
  ctx.packages = [...pkgs.values()].map((p) => ({ ...p, files: [...p.files].sort() }));
  ctx.files = [...new Set(fns.map((f) => f.file).filter(Boolean))].sort();
}

export const moduledata = {
  id: 'moduledata',
  run(ctx) {
    if (!ctx.tab) return false;
    const minor = goVersion(ctx.go.version)?.[1] ?? null;
    const funcnameOff = ctx.tab.version === '1.2' ? null : readFuncnameOff(ctx);
    const md = findModuledata(ctx.img, { pclntabAddr: ctx.pclntab.addr, version: ctx.tab.version, funcnameOff, goMinor: minor });
    if (!md) { ctx.log('moduledata bulunamadı (türler okunmadı)', 'info'); return false; }
    ctx.moduledata = { addr: md.addr, layout: md.layout, text: md.text, etext: md.etext, types: md.types, etypes: md.etypes, typelinks: md.typelinks, itablinks: md.itablinks };
    // 1.18+: functab taban adresi moduledata.text'tir; tahmin edilen tabandan farklıysa yeniden ayrıştır
    if ((ctx.tab.version === '1.18' || ctx.tab.version === '1.20') && md.text !== ctx.tab.textStart) {
      ctx.tab = parsePclntab(ctx.bytes, ctx.pclntab.fileOff, { textStart: md.text });
      buildFunctions(ctx);
      ctx.log(`functab tabanı moduledata.text ile düzeltildi (0x${md.text.toString(16)})`, 'info');
    }
    const { types, itabs } = readTypes(ctx.img, md, { goMinor: minor });
    ctx.types = types.map((x) => ({ name: x.name, kind: x.kind }));
    ctx.itabs = itabs;
    ctx.log(`moduledata ${md.layout} · ${types.length} tür · ${itabs.length} itab`);
    return true;
  },
};

function readFuncnameOff(ctx) {
  const P = ctx.tab.ptrSize;
  const b = ctx.bytes;
  const o = ctx.pclntab.fileOff + 8 + 2 * P + (ctx.tab.version === '1.16' ? 0 : P);
  let v = 0;
  for (let i = P - 1; i >= 0; i--) v = v * 256 + b[o + (ctx.tab.le ? i : P - 1 - i)];
  return v;
}

export const strings = {
  id: 'strings',
  run(ctx) {
    if (!ctx.img) return false;
    const s = extractStrings(ctx.img, ctx.tab ? ctx.tab.funcs : []);
    ctx.strings = s.strings.map(({ addr, value }) => ({ addr, value }));
    ctx.funcStrings = [...s.byFunc];
    ctx.log(`${s.strings.length} dizge (${s.method === 'code' ? 'kod referanslarından' : 'yazdırılabilir diziler'})`);
    return s.strings.length > 0;
  },
};

export const literals = {
  id: 'literals',
  run(ctx) {
    if (!ctx.tab) return false;
    const r = recoverLiterals(ctx.img, ctx.tab.funcs, { signal: ctx.signal });
    const owner = (a) => ctx.functions.find((f) => a >= f.entry && a < f.end)?.entry ?? null;
    ctx.literals = {
      recovered: r.literals.map((l) => ({ ...l, funcEntry: owner(l.site) })),
      unresolved: r.unresolved.map((u) => ({ ...u, funcEntry: owner(u.site) })),
      roots: r.roots, steps: r.steps, ms: r.ms, skipped: r.skipped ?? null, truncated: Boolean(r.truncated),
    };
    if (r.skipped === 'arch') ctx.log(`gizli dizge öykünmesi yalnızca amd64'te (bu ikili ${ctx.img.arch})`, 'info');
    else ctx.log(`gizli dizge: ${r.roots} kök, ${r.literals.length} çözüldü, ${r.unresolved.length} çözülemedi · ${r.steps} komut · ${r.ms} ms${r.truncated ? ' (sınıra takıldı)' : ''}`, r.unresolved.length ? 'warn' : 'info');
    return r.literals.length > 0;
  },
};

export const PASSES = [container, buildinfo, pclntab, moduledata, strings, literals];
