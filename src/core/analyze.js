// Analiz raporu. Arayüz, CLI ve kütüphane bu biçimi kullanır; alanlar eklenebilir, var olanlar değişmez.
//
// Report = {
//   detection:  [{ id, name, version?, kind: 'toolchain'|'obfuscator'|'packer'|'technique', confidence (0-1), evidence: string[], decodable?, traits? }]
//   protection: null | { product, version, decodable: false, notes: string[] }   paketleyici: yalnızca tanınır
//   threat:     { score (0-100), level: 'none'|'low'|'medium'|'high'|'critical', classes: [{ id, title, weight, evidence }] }
//   behaviour:  { network, commands, files, other: [{ api, target }], loads, stdout, calls, static: true }
//               ikiliye BAĞLANMIŞ fonksiyonlar (statik; hiçbir şey çalıştırılmadı)
//   iocs:       { urls, domains, ips, emails, discordWebhooks, telegram, downloads, pools, wallets, benign: string[] }
//   literals:   [{ site, func, value, family, length }]   çözülen gizli dizgeler (öykünmeyle, tahmin yok)
//   unresolved: [{ site, func, reason }]                  çözülemeyenler
//   crypto:     [{ name, at, region }]                     bilinen kripto sabitleri
//   notable:    [{ package, functions, why }]              dikkat çeken içe aktarılan paketler
//   go:         { version, module, goos, goarch, cgo, vcs }
//   metrics:    { format, arch, inBytes, outBytes, functions, userFunctions, packages, files, types, strings, literals, unresolved,
//                 pclntab, layers, rounds, rollbacks, toolchain, verified }
//   layers:     []        (Go ikililerinde gömülü katman çıkarılmaz; alan uyumluluk için)
//   summary:    string
//   lang:       'tr'|'en'
// }
import { detect, protection as findProtection, nameStats } from '../report/detect.js';
import { threat as assessThreat, capabilities, notablePackages } from '../report/threat.js';
import { iocs as findIocs } from '../report/iocs.js';
import { summarize } from '../report/summary.js';

/** -tiny izi: kullanıcı fonksiyonlarının neredeyse hiçbirinde dosya/satır yok */
const tinyTrait = (fns) => {
  const user = fns.filter((f) => !f.std && f.name !== 'main.main');
  if (user.length < 2) return false;
  const bare = user.filter((f) => !f.file || f.file === '?' || f.file === '??' || f.startLine <= 1).length;
  return bare / user.length >= 0.9;
};

/**
 * @param {object} r pipeline sonucu (peelBinary)
 * @param {'tr'|'en'} lang
 */
export function analyze(r, lang = 'tr') {
  lang = lang === 'en' ? 'en' : 'tr';
  const fns = r.functions ?? [];
  const lits = r.literals?.recovered ?? [];
  const facts = {
    go: r.go,
    pclntab: r.pclntab,
    buildinfo: r.buildinfo,
    upx: r.upx,
    functions: fns,
    functionCount: fns.length,
    runtimeFuncs: fns.filter((f) => f.name.startsWith('runtime.')).length,
    names: nameStats(fns),
    literals: lits,
    tiny: tinyTrait(fns),
    symbols: { go: (r.binary?.goSymbols ?? 0) > 0, dwarf: Boolean(r.binary?.dwarf) },
  };
  const detection = detect(facts, lang);
  const behaviour = capabilities(fns);
  const texts = [...(r.strings ?? []).map((s) => s.value), ...lits.map((l) => l.value)];
  const iocs = findIocs(texts);
  const bi = r.buildinfo;
  const report = {
    detection,
    protection: findProtection(facts, lang),
    threat: assessThreat({ functions: fns, strings: texts, iocs, detection, behaviour, imports: r.binary?.imports ?? [] }, lang),
    behaviour,
    iocs,
    literals: lits.map(({ site, func, value, family, length }) => ({ site, func, value, family, length })),
    unresolved: (r.literals?.unresolved ?? []).map(({ site, func, reason }) => ({ site, func, reason })),
    crypto: r.crypto ?? [],
    notable: notablePackages(r.packages ?? [], lang),
    go: {
      version: r.go?.version ?? null,
      module: bi?.main?.path ?? bi?.path ?? null,
      goos: bi?.settings?.GOOS ?? null,
      goarch: bi?.settings?.GOARCH ?? r.binary?.arch ?? null,
      cgo: bi?.settings?.CGO_ENABLED === '1',
      vcs: bi?.settings?.['vcs.revision'] ? { system: bi.settings.vcs ?? 'git', revision: bi.settings['vcs.revision'], time: bi.settings['vcs.time'] ?? null, modified: bi.settings['vcs.modified'] === 'true' } : null,
    },
    metrics: {
      format: r.binary?.format ?? null,
      arch: r.binary?.arch ?? null,
      inBytes: r.size ?? 0,
      outBytes: r.size ?? 0,
      functions: fns.length,
      userFunctions: fns.filter((f) => !f.std).length,
      packages: (r.packages ?? []).length,
      files: (r.files ?? []).length,
      types: (r.types ?? []).length,
      strings: (r.strings ?? []).length,
      literals: lits.length,
      unresolved: (r.literals?.unresolved ?? []).length,
      pclntab: r.pclntab?.version ?? null,
      layers: 0,
      rounds: 1,
      rollbacks: 0,
      toolchain: detection.find((d) => d.kind === 'toolchain')?.name ?? null,
      verified: Boolean(r.verified),
    },
    layers: [],
    lang,
    summary: '',
  };
  report.summary = summarize(report, lang);
  return report;
}
