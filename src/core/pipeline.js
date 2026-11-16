// Soyma hattı: girdi baytları → geçişler (src/passes) → olgular → rapor, listeleme ve ham görünüm.
// Hedef ikili hiçbir zaman çalıştırılmaz. Her geçiş kendi süresi ve sonucuyla olay olarak kaydedilir; listeleme
// anlık görüntüleri zaman çizelgesini besler.
import { PASSES } from '../passes/index.js';
import { analyze } from './analyze.js';
import { listing, rawView } from '../report/listing.js';
import { ParseError } from './reader.js';
import { cryptoConstants } from '../report/crypto.js';

export const MAX_INPUT = 256 * 1024 * 1024;

/**
 * @param {Uint8Array} bytes
 * @param {{ name?, lang?, only?: string[], onLog?, onPass?, onSnapshot?, signal? }} o
 */
export async function peelBinary(bytes, { name = '', lang = 'tr', only = null, onLog = () => {}, onPass = () => {}, onSnapshot = () => {}, signal = null } = {}) {
  const t0 = Date.now();
  if (!(bytes instanceof Uint8Array)) throw new TypeError('girdi Uint8Array olmalı');
  if (bytes.length > MAX_INPUT) return { error: `Girdi çok büyük (${bytes.length} bayt, en çok ${MAX_INPUT})`, events: [], stats: {} };
  const events = [];
  const stats = {};
  const ctx = {
    bytes, signal, go: {}, functions: [], packages: [], files: [], types: [], itabs: [], strings: [], funcStrings: [],
    literals: { recovered: [], unresolved: [], roots: 0, steps: 0, ms: 0, skipped: null, truncated: false },
    log: (m, level = 'info') => onLog(m, level),
  };
  const snap = (id) => {
    if (!ctx.tab) return;
    const r = result(ctx, name, null);
    onSnapshot({ id, round: 1, code: listing(r, name) });
  };
  for (const p of PASSES) {
    if (signal?.aborted) throw new Error('Durduruldu');
    if (only && !p.required && !only.includes(p.id)) { events.push({ id: p.id, round: 1, state: 'skip', ms: 0 }); onPass(p.id, 'skip'); continue; }
    const t = Date.now();
    onPass(p.id, 'run');
    let ok;
    try {
      ok = await p.run(ctx);
    } catch (e) {
      if (!(e instanceof ParseError) && !(e instanceof RangeError)) throw e;
      const msg = String(e?.message ?? e).split('\n')[0];
      events.push({ id: p.id, round: 1, state: 'fail', reason: msg, ms: Date.now() - t });
      onPass(p.id, 'fail');
      if (p.id === 'container') return { error: `İkili okunamadı: ${msg}`, events, stats };
      onLog(`${p.id}: ${msg}`, 'warn');
      continue;
    }
    events.push({ id: p.id, round: 1, state: ok ? 'ok' : 'skip', ms: Date.now() - t });
    onPass(p.id, ok ? 'ok' : 'skip');
    if (ok && ['pclntab', 'strings', 'literals'].includes(p.id)) snap(p.id);
  }
  stats.functions = ctx.functions.length;
  stats.packages = ctx.packages.length;
  stats.types = ctx.types.length;
  stats.strings = ctx.strings.length;
  stats.literals = ctx.literals.recovered.length;
  const r = result(ctx, name, lang);
  r.events = events;
  r.stats = stats;
  r.ms = Date.now() - t0;
  return r;
}

function result(ctx, name, lang) {
  const img = ctx.img;
  const allExec = ctx.functions.length > 0 && ctx.functions.every((f) => img.regionOf(f.entry)?.exec);
  const r = {
    name,
    size: ctx.bytes.length,
    binary: {
      format: img.format, bits: img.bits, le: img.le, arch: img.arch, os: ctx.buildinfo?.settings?.GOOS ?? img.os, kind: img.kind, entry: img.entry,
      fat: img.fat ?? null,
      sections: img.sections.map((s) => ({ name: s.name, addr: s.addr, size: s.size, exec: Boolean(s.exec), write: Boolean(s.write) })),
      symbols: img.symbols.length, goSymbols: img.symbols.filter((s) => s.name === 'main.main' || s.name.startsWith('runtime.')).length,
      imports: img.imports.slice(0, 5000), libs: img.libs, dwarf: img.hasDwarf, noSections: Boolean(img.noSections),
    },
    upx: ctx.upx ?? null,
    go: { version: ctx.go.version ?? null, versionSource: ctx.go.versionSource ?? null },
    pclntab: ctx.pclntab ?? null,
    buildinfo: ctx.buildinfo ? { at: ctx.buildinfo.at, inline: ctx.buildinfo.inline, modinfo: Boolean(ctx.buildinfo.modinfo), path: ctx.buildinfo.path, main: ctx.buildinfo.main, deps: ctx.buildinfo.deps, settings: ctx.buildinfo.settings } : null,
    moduledata: ctx.moduledata ?? null,
    functions: ctx.functions,
    packages: ctx.packages,
    files: ctx.files,
    types: ctx.types,
    itabs: ctx.itabs,
    strings: ctx.strings,
    funcStrings: ctx.funcStrings,
    literals: ctx.literals,
    // çapraz denetim: her fonksiyon girişi yürütülebilir bölgede ve (varsa) moduledata metin aralığında
    verified: allExec && (!ctx.moduledata || ctx.functions.every((f) => f.entry >= ctx.moduledata.text && f.entry <= ctx.moduledata.etext + 64)),
  };
  if (lang) {
    ctx.crypto ??= cryptoConstants(img);
    r.crypto = ctx.crypto;
    r.report = analyze(r, lang);
    r.listing = listing(r, name);
    r.rawView = rawView(r, name);
  }
  return r;
}
