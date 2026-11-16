// Metin görünümleri:
//   rawView  ikilinin "soyulmadan" hâli: başlık, bölümler, sembol tablosunun gördüğü (yoksa sub_XXXX) fonksiyonlar
//   listing  soyulmuş hâli: Go sürümü, modüller, paket ağacı; her fonksiyon adı, kaynak dosya:satır, dizgeleri ve
//            çözülen gizli dizgeleriyle. Fark görünümü bu ikisini karşılaştırır.
// İkiliden gelen her dizge JSON kaçışıyla basılır (görünmez karakter ve satır sonu listeyi bozamaz).

export const LIMITS = { maxLines: 80_000, stringsPerFunc: 4 };
const hx = (n, w = 8) => `0x${Number(n).toString(16).padStart(w, '0')}`;
const q = (s) => JSON.stringify(String(s));
const FORMAT = { elf: 'ELF', pe: 'PE', macho: 'Mach-O' };
const base = (p) => String(p ?? '').split('/').pop();

function header(r) {
  const b = r.binary;
  const out = [`; ${FORMAT[b.format] ?? b.format} ${b.bits}-bit ${b.le ? 'LE' : 'BE'} · ${b.arch} · ${b.os} · ${b.kind} · entry ${hx(b.entry)}${b.fat ? ` · fat: ${b.fat.join(', ')}` : ''}`];
  return out;
}

export function rawView(r, name = '') {
  const b = r.binary;
  const lines = [`; ${name ? `${name} · ` : ''}${r.size.toLocaleString('en-US')} bytes`, ...header(r)];
  lines.push(`; sections (${b.sections.filter((x) => x.name).length}):`);
  for (const s of b.sections.filter((x) => x.name).slice(0, 64)) lines.push(`;   ${s.name.padEnd(18)} ${hx(s.addr)}  ${String(s.size).padStart(9)}  ${s.exec ? 'r-x' : s.write ? 'rw-' : 'r--'}`);
  lines.push(`; symbols: ${b.symbols}${b.symbols ? '' : ' (stripped)'} · imports: ${b.imports.length}${b.libs.length ? ` · libs: ${b.libs.join(', ')}` : ''}`);
  if (r.upx) lines.push(`; packer markers: ${r.upx.markers.join(' · ')}`);
  lines.push(';', '; functions as a disassembler sees them without pclntab:');
  let n = 0;
  for (const f of r.functions) {
    if (++n > LIMITS.maxLines) { lines.push(`; … ${r.functions.length - LIMITS.maxLines} more`); break; }
    lines.push(`${hx(f.entry)}  ${f.symbol ?? `sub_${f.entry.toString(16)}`}`);
  }
  return `${lines.join('\n')}\n`;
}

export function listing(r, name = '') {
  const lines = [`; Peel-Go${name ? ` · ${name}` : ''}`, ...header(r)];
  const g = r.go;
  if (g.version || r.pclntab) lines.push(`; Go ${g.version ?? '?'}${r.pclntab ? ` · pclntab ${r.pclntab.version} (${r.pclntab.how} @${hx(r.pclntab.addr ?? 0)}) · ${r.functions.length} functions · ${r.files.length} files` : ''}`);
  const bi = r.buildinfo;
  if (bi) {
    if (bi.main) lines.push(`; module ${bi.main.path} ${bi.main.version}${bi.main.sum ? ` ${bi.main.sum}` : ''}`);
    else if (bi.path) lines.push(`; path ${bi.path}`);
    if (!bi.modinfo) lines.push('; build info: module info stripped');
    for (const d of bi.deps.slice(0, 500)) lines.push(`;   dep ${d.path} ${d.version}${d.replace ? ` => ${d.replace.path} ${d.replace.version}` : ''}${d.sum ? ` ${d.sum}` : ''}`);
    const s = Object.entries(bi.settings);
    if (s.length) lines.push(`;   build ${s.map(([k, v]) => `${k}=${/\s/.test(v) ? q(v) : v}`).join(' ')}`);
  }
  if (r.moduledata) lines.push(`; moduledata @${hx(r.moduledata.addr)} (layout ${r.moduledata.layout}) · ${r.types.length} types · ${r.itabs.length} itabs`);
  const obf = r.report?.detection?.filter((d) => d.kind === 'obfuscator' || d.kind === 'packer') ?? [];
  for (const d of obf) lines.push(`; ${d.kind}: ${d.name}${d.version ? ` ${d.version}` : ''} ${Math.round(d.confidence * 100)}% — ${d.evidence.join(' · ')}`);
  if (r.literals.unresolved.length) lines.push(`; ${r.literals.unresolved.length} obfuscated string(s) not recovered (listed below, not guessed)`);

  const lits = new Map();
  for (const l of r.literals.recovered) { const k = l.funcEntry; lits.set(k, [...(lits.get(k) ?? []), l]); }
  const unres = new Map();
  for (const u of r.literals.unresolved) { const k = u.funcEntry; unres.set(k, [...(unres.get(k) ?? []), u]); }
  const strs = new Map(r.funcStrings ?? []);
  // paket ağacı: önce kullanıcı paketleri, sonra standart kitaplık
  const pkgs = [...r.packages].sort((a, b) => (a.std - b.std) || a.path.localeCompare(b.path));
  const byPkg = new Map();
  for (const f of r.functions) byPkg.set(f.pkg, [...(byPkg.get(f.pkg) ?? []), f]);
  let count = lines.length;
  outer: for (const p of pkgs) {
    const fs = byPkg.get(p.path) ?? [];
    lines.push(';', `; ── package ${p.path || '(none)'}${p.std ? ' [std]' : ''} · ${fs.length} function(s)${p.files.length ? ` · ${p.files.slice(0, 4).map(base).join(', ')}${p.files.length > 4 ? ', …' : ''}` : ''}`);
    for (const f of fs) {
      if (++count > LIMITS.maxLines) { lines.push(`; … listing truncated at ${LIMITS.maxLines} lines (JSON export has everything)`); break outer; }
      const src = f.file ? `${base(f.file)}:${f.startLine}${f.endLine > f.startLine ? `-${f.endLine}` : ''}` : '';
      lines.push(`${hx(f.entry)}  ${f.name.padEnd(48)} ${src.padEnd(24)} ${f.size} B`);
      if (!f.std) for (const s of (strs.get(f.entry) ?? []).slice(0, LIMITS.stringsPerFunc)) lines.push(`            ; ${q(s)}`);
      for (const l of lits.get(f.entry) ?? []) lines.push(`            ; literal ${hx(l.site, 0)} [${l.family}] ${q(l.value)}`);
      for (const u of unres.get(f.entry) ?? []) lines.push(`            ; literal ${hx(u.site, 0)} NOT RECOVERED (${u.reason})`);
    }
  }
  return `${lines.join('\n')}\n`;
}
