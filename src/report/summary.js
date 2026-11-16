// Raporun tek paragraflık özeti (tr | en); yalnızca bulunan bulgulara dayanır.
import { levelName } from './text.js';

const list = (xs, en) => (xs.length <= 1 ? xs.join('') : `${xs.slice(0, -1).join(', ')} ${en ? 'and' : 've'} ${xs.at(-1)}`);
const FORMAT = { elf: 'ELF', pe: 'PE', macho: 'Mach-O' };

export function summarize(r, lang = 'tr') {
  const en = lang === 'en';
  const parts = [];
  const pct = (c) => (en ? `${Math.round(c * 100)}%` : `%${Math.round(c * 100)}`);
  const of = (kind) => r.detection.filter((d) => d.kind === kind);
  const m = r.metrics;
  const g = r.go ?? {};
  const fmt = `${FORMAT[m.format] ?? m.format ?? '?'} ${m.arch ?? ''}`.trim();
  if (m.functions) {
    parts.push(en
      ? `Input: ${fmt} Go binary${g.version ? ` built with ${g.version}` : ''}${g.module ? ` (module ${g.module})` : ''}; ${m.functions} function(s) recovered from pclntab ${m.pclntab}, ${m.userFunctions} outside the standard library, in ${m.packages} package(s).`
      : `Girdi: ${fmt} Go ikilisi${g.version ? `, ${g.version} ile derlenmiş` : ''}${g.module ? ` (modül ${g.module})` : ''}; pclntab ${m.pclntab} üzerinden ${m.functions} fonksiyon geri kazanıldı, ${m.userFunctions} tanesi standart kitaplık dışında, ${m.packages} pakette.`);
  } else {
    parts.push(en ? `Input: ${fmt}; no readable Go pclntab was found.` : `Girdi: ${fmt}; okunabilir bir Go pclntab bulunamadı.`);
  }
  if (r.protection) {
    parts.push(en ? `${r.protection.product}${r.protection.version ? ` ${r.protection.version}` : ''} packing was detected; the packed body is not decoded.` : `${r.protection.product}${r.protection.version ? ` ${r.protection.version}` : ''} paketlemesi tespit edildi; paketli gövde çözülmez.`);
  }
  const obf = of('obfuscator');
  if (obf.length) parts.push(en ? `Obfuscator: ${list(obf.map((d) => `${d.name} (${pct(d.confidence)})`), en)}.` : `Gizleyici: ${list(obf.map((d) => `${d.name} (${pct(d.confidence)})`), en)}.`);
  const tech = of('technique');
  if (tech.length) parts.push(en ? `Techniques: ${list(tech.map((d) => d.name), en)}.` : `Teknikler: ${list(tech.map((d) => d.name), en)}.`);
  if (m.literals) parts.push(en ? `${m.literals} hidden string(s) were recovered by emulating their decoders${m.unresolved ? `; ${m.unresolved} could not be and are listed, not guessed` : ''}.` : `${m.literals} gizli dizge çözücüleri öykünülerek geri kazanıldı${m.unresolved ? `; ${m.unresolved} tanesi çözülemedi ve tahmin edilmeden listelendi` : ''}.`);
  else if (m.unresolved) parts.push(en ? `${m.unresolved} obfuscated string(s) could not be recovered; they are listed, not guessed.` : `${m.unresolved} gizli dizge çözülemedi; tahmin edilmeden listelendi.`);
  const th = r.threat;
  const lv = levelName(th.level, lang);
  if (th.classes.length) {
    parts.push(en ? `Threat level ${lv} (${th.score}/100): ${list(th.classes.slice(0, 5).map((c) => c.title), en)}.` : `Tehdit düzeyi ${lv} (${th.score}/100): ${list(th.classes.slice(0, 5).map((c) => c.title), en)}.`);
  } else {
    parts.push(en ? 'No dangerous capability was found (threat level none).' : 'Tehlikeli bir yetenek bulunmadı (tehdit düzeyi yok).');
  }
  const io = r.iocs;
  const counts = [[io.urls, 'URL', 'URL(s)'], [io.domains, 'alan adı', 'domain(s)'], [io.ips, 'IP', 'IP(s)'], [io.emails, 'e-posta', 'e-mail(s)'],
    [io.discordWebhooks, 'Discord webhook', 'Discord webhook(s)'], [io.telegram, 'Telegram', 'Telegram']]
    .filter(([xs]) => xs?.length).map(([xs, tr, e]) => `${xs.length} ${en ? e : tr}`);
  if (counts.length) parts.push(en ? `IOCs: ${list(counts, en)}.` : `IOC: ${list(counts, en)}.`);
  return parts.join(' ');
}
