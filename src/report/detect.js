// Tespit: Go araç zinciri, garble (karma adlar, boşaltılmış buildinfo, -literals, -tiny), gobfuscate (rastgele küçük
// harfli paket adları + maske xor dizgeleri), UPX paketleme ve silinmiş semboller. Her tespit güven ve kanıt taşır.
import { t, pick, hex } from './text.js';
import { hashScore, randomLowerScore, tokens } from '../core/gonames.js';

const L = (lang, tr, en) => pick(t(tr, en), lang);
const pctOf = (x) => Math.round(x * 100);

/** Kullanıcı fonksiyonlarının adlarına göre karma/rastgele oranları */
export function nameStats(functions) {
  const user = functions.filter((f) => !f.std && !/^main\.(?:main|init)(?:\.|$)/.test(f.name) && !/^(?:type|go):/.test(f.name));
  let hashed = 0;
  const pkgs = new Map();
  for (const f of user) {
    const toks = tokens(f.name);
    if (toks.some((x) => hashScore(x) >= 0.6)) hashed++;
    if (f.pkg && !pkgs.has(f.pkg)) pkgs.set(f.pkg, f.pkg.split('/').some((x) => randomLowerScore(x) >= 0.5));
  }
  const randomPkgs = [...pkgs.values()].filter(Boolean).length;
  const samples = user.filter((f) => tokens(f.name).some((x) => hashScore(x) >= 0.6)).slice(0, 3).map((f) => f.name);
  return { user: user.length, hashed, ratio: user.length ? hashed / user.length : 0, packages: pkgs.size, randomPkgs, samples, randomSamples: [...pkgs].filter(([, v]) => v).slice(0, 3).map(([k]) => k) };
}

/**
 * @param {object} f olgular (pipeline: facts)
 * @param {'tr'|'en'} lang
 */
export function detect(f, lang = 'tr') {
  const out = [];
  const go = f.go ?? {};
  // ── araç zinciri ──
  const tcEv = [];
  if (f.pclntab) tcEv.push(`pclntab ${f.pclntab.version} (${f.pclntab.how} @${hex(f.pclntab.addr ?? 0)})`);
  if (f.buildinfo) tcEv.push(`buildinfo @${hex(f.buildinfo.at)}${go.version ? `: ${go.version}` : ''}`);
  if (f.runtimeFuncs) tcEv.push(L(lang, `${f.runtimeFuncs} runtime fonksiyonu`, `${f.runtimeFuncs} runtime functions`));
  if (tcEv.length) out.push({ id: 'go', name: 'Go (gc)', version: go.version ?? null, kind: 'toolchain', confidence: f.pclntab ? 0.99 : 0.8, evidence: tcEv });

  // ── paketleyici ──
  if (f.upx) {
    out.push({ id: 'upx', name: 'UPX', version: f.upx.version, kind: 'packer', confidence: f.pclntab ? 0.6 : 0.95, decodable: false, evidence: f.upx.markers });
  }

  // ── garble ──
  const ns = f.names ?? nameStats(f.functions ?? []);
  const obfLits = (f.literals ?? []).filter((x) => x.family !== 'plain');
  const fams = [...new Set(obfLits.map((x) => x.family))];
  const g = [];
  let score = 0;
  // az kullanıcı fonksiyonu olan küçük ikililerde ad kanıtı tek başına yetmez (diğer izlerle birlikte sayılır)
  if (ns.hashed >= 1 && ns.ratio >= 0.5) {
    score += ns.user >= 3 ? 0.55 : 0.35;
    g.push(L(lang, `karma görünümlü adlar: kullanıcı fonksiyonlarının %${pctOf(ns.ratio)}'i (ör. ${ns.samples.join(', ')})`, `hashed-looking names: ${pctOf(ns.ratio)}% of user functions (e.g. ${ns.samples.join(', ')})`));
  }
  const bi = f.buildinfo;
  if (bi && go.version && !bi.modinfo) {
    score += 0.2;
    g.push(L(lang, 'buildinfo boşaltılmış: Go sürümü var, modül bilgisi yok', 'build info stripped: Go version present, module info empty'));
  }
  if (obfLits.length) {
    score += 0.25;
    g.push(L(lang, `-literals: ${obfLits.length} gizli dizge çözüldü (${fams.join(', ')})`, `-literals: ${obfLits.length} hidden string(s) recovered (${fams.join(', ')})`));
  }
  if (f.tiny) {
    score += 0.15;
    g.push(L(lang, '-tiny: kullanıcı fonksiyonlarında dosya adı ve satır bilgisi yok', '-tiny: no file names or line numbers on user functions'));
  }
  if (g.length && score >= 0.5) {
    g.push(L(lang, '-seed: tek ikiliden belirlenemez (karma tuzu ikiliye yazılmaz)', '-seed: not determinable from a single binary (the hash salt is not stored)'));
    out.push({ id: 'garble', name: 'garble', version: null, kind: 'obfuscator', confidence: Math.min(0.99, Number(score.toFixed(2))), evidence: g, traits: { hashedNames: ns.ratio >= 0.5, buildinfoStripped: Boolean(bi && go.version && !bi.modinfo), literals: obfLits.length, tiny: Boolean(f.tiny) } });
  }

  // ── gobfuscate ──
  if (ns.packages && ns.randomPkgs / ns.packages >= 0.5 && !out.some((d) => d.id === 'garble')) {
    const ev = [L(lang, `rastgele küçük harfli paket yolları: ${ns.randomPkgs}/${ns.packages} (ör. ${ns.randomSamples.join(', ')})`, `random lowercase package paths: ${ns.randomPkgs}/${ns.packages} (e.g. ${ns.randomSamples.join(', ')})`)];
    if (obfLits.length) ev.push(L(lang, `maske xor dizgeleri: ${obfLits.length} çözüldü`, `mask-xor strings: ${obfLits.length} recovered`));
    out.push({ id: 'gobfuscate', name: 'gobfuscate', version: null, kind: 'obfuscator', confidence: obfLits.length ? 0.85 : 0.6, evidence: ev });
  } else if (obfLits.length && !out.some((d) => d.id === 'garble')) {
    // yalnızca dizge gizleme izi
    out.push({ id: 'literals', name: L(lang, 'Gizlenmiş dizge sabitleri', 'Obfuscated string literals'), kind: 'technique', confidence: 0.7, evidence: [L(lang, `${obfLits.length} dizge çalışma anında çözülüyor (${fams.join(', ')})`, `${obfLits.length} string(s) decoded at run time (${fams.join(', ')})`)] });
  }

  // ── silinmiş semboller ──
  if (f.pclntab && !f.symbols?.go) {
    const ev = [L(lang, 'sembol tablosu yok (-ldflags=-s)', 'no symbol table (-ldflags=-s)')];
    if (!f.symbols?.dwarf) ev.push(L(lang, 'DWARF yok (-w)', 'no DWARF (-w)'));
    ev.push(L(lang, `adlar pclntab'tan geri kazanıldı (${f.functionCount} fonksiyon)`, `names recovered from pclntab (${f.functionCount} functions)`));
    out.push({ id: 'stripped', name: L(lang, 'Sembolleri silinmiş', 'Stripped symbols'), kind: 'technique', confidence: 0.9, evidence: ev });
  }
  return out;
}

/** UPX: korunan gövde çözülmez, yalnızca açıklanır */
export function protection(f, lang = 'tr') {
  if (!f.upx) return null;
  return {
    product: 'UPX',
    version: f.upx.version,
    decodable: false,
    notes: [
      L(lang, 'Kod ve pclntab sıkıştırılmış; bu hâliyle fonksiyon adları, dosyalar ve dizgeler okunamaz.', 'Code and pclntab are compressed; function names, files and strings cannot be read as is.'),
      L(lang, 'Tarayıcıda açma yapılmaz. Güvenli bir ortamda `upx -d dosya` ile açıp çıkan dosyayı yeniden yükleyin.', 'Unpacking is not done in the browser. Unpack with `upx -d file` in a safe environment and load the result again.'),
      ...(f.pclntab ? [L(lang, 'Yine de bir pclntab okunabildi: yalnızca kısmen paketlenmiş ya da UPX işaretleri yanıltıcı olabilir.', 'A pclntab was still readable: the file may be only partly packed or the UPX markers may be misleading.')] : []),
    ],
  };
}
