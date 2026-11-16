// Rapor modüllerinin ortak yardımcıları: kanıt kesitleri, dil seçimi, düz metin rapor. Tarayıcıda da çalışır.

export const t = (tr, en = tr) => ({ tr, en });
export const pick = (o, lang) => (lang === 'en' ? o.en : o.tr);

/** Antivirüs imzalarına takılmasın diye şüpheli dizgeler kaynakta parçalı yazılır: rx(['Virtual', 'AllocEx']) */
export const rx = (parts, flags = '') => new RegExp(parts.join(''), flags);

/** Kanıt için tek satırlık, kısaltılmış kesit */
export function snippet(s, max = 120) {
  const one = String(s).replace(/\s+/g, ' ').trim();
  return one.length > max ? `${one.slice(0, max - 1)}…` : one;
}

export const hex = (n) => `0x${Number(n).toString(16)}`;

const LEVEL = {
  tr: { none: 'yok', low: 'düşük', medium: 'orta', high: 'yüksek', critical: 'kritik' },
  en: { none: 'none', low: 'low', medium: 'medium', high: 'high', critical: 'critical' },
};
export const levelName = (lv, lang) => LEVEL[lang === 'en' ? 'en' : 'tr'][lv] ?? lv;

/** CLI için okunabilir düz metin rapor */
export function reportText(r, lang = r?.lang ?? 'tr') {
  const en = lang === 'en';
  const L = (tr, e) => (en ? e : tr);
  const pct = (c) => (en ? `${Math.round(c * 100)}%` : `%${Math.round(c * 100)}`);
  const lines = [];
  lines.push(`${L('Özet', 'Summary')}: ${r.summary}`);
  const g = r.go ?? {};
  if (g.version || g.module) lines.push(`Go: ${[g.version, g.module, g.goos && g.goarch ? `${g.goos}/${g.goarch}` : ''].filter(Boolean).join(' · ')}`);
  lines.push(`${L('Tehdit', 'Threat')}: ${levelName(r.threat.level, lang)} (${r.threat.score}/100)`);
  for (const c of r.threat.classes) {
    lines.push(`  - ${c.title}`);
    for (const e of c.evidence) lines.push(`      ${e}`);
  }
  if (r.protection) {
    const p = r.protection;
    lines.push(`${L('Koruma', 'Protection')}: ${p.product}${p.version ? ` ${p.version}` : ''} (${L('çözülmez', 'not decoded')})`);
    for (const n of p.notes) lines.push(`  - ${n}`);
  }
  if (r.detection.length) {
    lines.push(`${L('Tespitler', 'Detections')}:`);
    for (const d of r.detection) {
      lines.push(`  - ${d.name}${d.version ? ` ${d.version}` : ''} [${d.kind}] ${pct(d.confidence)}`);
      for (const e of d.evidence) lines.push(`      ${e}`);
    }
  }
  if (r.literals?.length) {
    lines.push(`${L('Çözülen gizli dizgeler', 'Recovered hidden strings')} (${r.literals.length}):`);
    for (const l of r.literals.slice(0, 60)) lines.push(`  ${hex(l.site)} [${l.family}] ${JSON.stringify(l.value)}`);
  }
  if (r.unresolved?.length) {
    lines.push(`${L('Çözülemeyen (tahmin edilmedi)', 'Not recovered (not guessed)')} (${r.unresolved.length}):`);
    for (const u of r.unresolved.slice(0, 20)) lines.push(`  ${hex(u.site)} ${u.func} ${u.reason}`);
  }
  const b = r.behaviour;
  const acts = [...b.network, ...b.commands, ...b.files, ...b.other];
  if (acts.length) {
    lines.push(`${L('Yetenekler (bağlı fonksiyonlar; statik, hiçbir şey çalıştırılmadı)', 'Capabilities (linked functions; static, nothing was executed)')}:`);
    for (const a of acts.slice(0, 40)) lines.push(`  - ${snippet(a.api, 160)}`);
  }
  if (r.crypto?.length) lines.push(`${L('Kripto sabitleri', 'Crypto constants')}: ${r.crypto.map((c) => c.name).join(', ')}`);
  if (r.notable?.length) lines.push(`${L('Dikkat çeken paketler', 'Notable packages')}: ${r.notable.map((n) => n.package).join(', ')}`);
  const io = r.iocs;
  const keys = ['urls', 'domains', 'ips', 'emails', 'discordWebhooks', 'telegram', 'downloads', 'pools', 'wallets', 'benign'];
  if (keys.some((k) => io[k]?.length)) {
    lines.push('IOC:');
    for (const k of keys) if (io[k]?.length) lines.push(`  ${k}: ${io[k].join(', ')}`);
  }
  const m = r.metrics;
  lines.push(`${L('Ölçüler', 'Metrics')}: ${m.inBytes} ${L('bayt', 'bytes')}, ${L('fonksiyon', 'functions')} ${m.functions} (${L('kullanıcı', 'user')} ${m.userFunctions}), ${L('paket', 'packages')} ${m.packages}, ${L('dosya', 'files')} ${m.files}, ${L('tür', 'types')} ${m.types}, ${L('dizge', 'strings')} ${m.strings}, ${L('çözülen dizge', 'recovered literals')} ${m.literals}`);
  return `${lines.join('\n')}\n`;
}
