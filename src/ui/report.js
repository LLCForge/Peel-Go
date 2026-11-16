import { t } from '../i18n.js';
import { h } from './dom.js';

// Analiz raporu görünümü (biçim: src/core/analyze.js). Rapordaki tüm dizgeler incelenen ikiliden gelir ve güvenilmezdir:
// yalnızca textContent ile basılır. Boş bölümler gösterilmez.

const MAX_ROWS = 80;
const kb = (n) => `${((Number(n) || 0) / 1024).toFixed(1)} KB`;
const arr = (v) => (Array.isArray(v) ? v : []);
const str = (v) => (v == null ? '' : String(v));
const hx = (n) => (Number.isFinite(Number(n)) ? `0x${Number(n).toString(16)}` : '');
const section = (title, ...body) => h('section', { class: 'rep-section' }, h('h3', {}, title), ...body);
const LEVELS = ['none', 'low', 'medium', 'high', 'critical'];

function table(headers, rows, classes = []) {
  return h('div', { class: 'table-wrap' }, h('table', { class: 'rep-table' },
    h('thead', {}, h('tr', {}, ...headers.map((x) => h('th', { scope: 'col' }, x)))),
    h('tbody', {}, ...rows.slice(0, MAX_ROWS).map((r) => h('tr', {}, ...r.map((c, i) => h('td', { class: classes[i] ?? '' }, str(c))))))),
  rows.length > MAX_ROWS ? h('p', { class: 'rep-muted small' }, t('report.more', { n: rows.length - MAX_ROWS })) : null);
}

function protection(p) {
  if (!p || typeof p !== 'object') return null;
  return h('section', { class: 'rep-section rep-protect', role: 'note' },
    h('h3', {}, t('report.protection')),
    h('p', { class: 'protect-title' }, [str(p.product), str(p.version)].filter(Boolean).join(' ')),
    h('p', {}, t('report.protection.body')),
    arr(p.notes).length ? h('ul', { class: 'rep-list' }, ...arr(p.notes).map((n) => h('li', {}, str(n)))) : null);
}

function threat(th) {
  if (!th || typeof th !== 'object') return null;
  const classes = arr(th.classes);
  const level = LEVELS.includes(th.level) ? th.level : 'none';
  return section(t('report.threat'),
    h('div', { class: `risk risk-${level}` }, h('b', {}, str(Number(th.score) || 0)), h('span', {}, t(`report.risk.${level}`))),
    classes.length ? table([t('report.threat.class'), t('report.threat.evidence')], classes.map((c) => [str(c.title || c.id), arr(c.evidence).map(str).join(' · ')]), ['', 'rep-muted mono']) : null);
}

const KINDS = ['toolchain', 'obfuscator', 'packer', 'technique'];
function detection(list) {
  const items = arr(list).filter((x) => x && typeof x === 'object');
  if (!items.length) return null;
  return section(t('report.detect'), h('div', { class: 'detect' }, ...items.map((f) => h('div', { class: 'detect-row' },
    h('span', { class: 'detect-name' }, [str(f.name), str(f.version)].filter(Boolean).join(' '),
      KINDS.includes(f.kind) ? h('small', {}, t(`report.detect.kind.${f.kind}`)) : null,
      h('small', {}, `${Math.round((Number(f.confidence) || 0) * 100)}%`),
      f.decodable === false ? h('small', { class: 'detect-only' }, t('report.detect.reportOnly')) : null),
    h('span', { class: 'detect-ev' }, arr(f.evidence).map(str).join(' · '))))));
}

function goInfo(r, extra) {
  const g = r.go;
  if (!g || typeof g !== 'object') return null;
  const m = r.metrics ?? {};
  const dl = h('dl', { class: 'kv' });
  const row = (label, value) => { if (value !== '' && value != null) dl.append(h('dt', {}, label), h('dd', {}, str(value))); };
  row(t('report.go.version'), g.version);
  row(t('report.go.module'), g.module);
  row(t('report.go.target'), [g.goos, g.goarch].filter(Boolean).join('/') || m.arch);
  row(t('report.go.format'), [str(m.format).toUpperCase(), m.arch].filter(Boolean).join(' · '));
  row('pclntab', m.pclntab);
  row(t('report.go.cgo'), g.cgo ? t('ui.on') : '');
  if (g.vcs) row('VCS', `${str(g.vcs.system)} ${str(g.vcs.revision).slice(0, 12)}${g.vcs.modified ? ' (modified)' : ''}${g.vcs.time ? ` · ${str(g.vcs.time)}` : ''}`);
  const deps = arr(extra.deps);
  return section(t('report.go'), dl,
    deps.length ? h('div', { class: 'ioc-group' }, h('h4', {}, `${t('report.go.deps')} (${deps.length})`),
      table([t('report.go.path'), t('report.go.ver'), 'sum'], deps.map((d) => [`${str(d.path)}${d.replace ? ` => ${str(d.replace.path)}` : ''}`, d.replace?.version || d.version, d.sum || d.replace?.sum || '']), ['mono', 'mono', 'mono rep-muted'])) : null);
}

function literals(list, unresolved) {
  const items = arr(list);
  const un = arr(unresolved);
  if (!items.length && !un.length) return null;
  return section(t('report.literals'),
    h('p', { class: 'rep-note' }, t('report.literals.note')),
    items.length ? table([t('report.literals.at'), t('report.literals.family'), t('report.literals.value'), t('report.literals.func')],
      items.map((l) => [hx(l.site), l.family, JSON.stringify(str(l.value)), l.func]), ['mono nowrap', '', 'mono', 'mono rep-muted']) : null,
    un.length ? h('div', { class: 'ioc-group' }, h('h4', {}, `${t('report.literals.unresolved')} (${un.length})`),
      table([t('report.literals.at'), t('report.literals.func'), t('report.literals.reason')], un.map((u) => [hx(u.site), u.func, u.reason]), ['mono nowrap', 'mono', 'rep-muted'])) : null);
}

function behaviour(b) {
  if (!b || typeof b !== 'object') return null;
  const groups = ['network', 'commands', 'files', 'other'].filter((k) => arr(b[k]).length);
  if (!groups.length) return null;
  return section(t('report.behaviour'),
    h('p', { class: 'rep-note' }, t('report.behaviour.note')),
    ...groups.map((k) => h('div', { class: 'ioc-group' },
      h('h4', {}, `${t(`report.behaviour.${k}`)} (${arr(b[k]).length})`),
      h('ul', { class: 'ioc-list' }, ...arr(b[k]).slice(0, MAX_ROWS).map((x) => h('li', {}, str(x.api)))))));
}

function notable(list, crypto) {
  const n = arr(list);
  const c = arr(crypto);
  if (!n.length && !c.length) return null;
  return section(t('report.notable'),
    n.length ? table([t('report.notable.package'), t('report.notable.functions'), t('report.notable.why')], n.map((x) => [x.package, x.functions, x.why]), ['mono', '', 'rep-muted']) : null,
    c.length ? h('div', { class: 'ioc-group' }, h('h4', {}, `${t('report.crypto')} (${c.length})`),
      h('p', { class: 'rep-note' }, t('report.crypto.note')),
      table([t('report.crypto.name'), t('report.literals.at')], c.map((x) => [x.name, `${hx(x.at)} ${str(x.region)}`]), ['', 'mono nowrap'])) : null);
}

function iocs(data) {
  if (!data || typeof data !== 'object') return null;
  const groups = ['urls', 'domains', 'ips', 'emails', 'discordWebhooks', 'telegram', 'downloads'].filter((k) => arr(data[k]).length);
  if (!groups.length) return null;
  return section(t('report.iocs'), ...groups.map((k) => h('div', { class: 'ioc-group' },
    h('h4', {}, `${t(`report.ioc.${k}`)} (${data[k].length})`),
    h('ul', { class: 'ioc-list' }, ...data[k].slice(0, MAX_ROWS).map((v) => h('li', {}, str(v)))))));
}

function metrics(m, extra) {
  const dl = h('dl', { class: 'kv' });
  const row = (label, value) => dl.append(h('dt', {}, label), h('dd', {}, value));
  if (m) {
    row(t('report.metric.size'), kb(m.inBytes));
    row(t('report.metric.functions'), `${str(m.functions)} (${t('report.metric.user')} ${str(m.userFunctions)})`);
    row(t('report.metric.packages'), str(m.packages));
    row(t('report.metric.files'), str(m.files));
    row(t('report.metric.types'), str(m.types));
    row(t('report.metric.strings'), str(m.strings));
    row(t('report.metric.literals'), `${str(m.literals)}${m.unresolved ? ` (${t('report.literals.unresolved')}: ${str(m.unresolved)})` : ''}`);
  }
  if (extra.verified != null) row(t('report.metric.verified'), t(extra.verified ? 'report.verified.yes' : 'report.verified.no'));
  if (extra.ms != null) row(t('report.metric.time'), `${(extra.ms / 1000).toFixed(2)} s`);
  return section(t('report.metrics'), dl);
}

function passTimes(events) {
  const by = new Map();
  for (const e of arr(events)) {
    const p = by.get(e.id) ?? { id: e.id, ms: 0, ok: 0, fail: 0 };
    p.ms += Number(e.ms) || 0;
    if (e.state === 'ok') p.ok++;
    if (e.state === 'fail') p.fail++;
    by.set(e.id, p);
  }
  const list = [...by.values()].sort((a, b) => b.ms - a.ms);
  if (!list.length) return null;
  const max = Math.max(1, ...list.map((p) => p.ms));
  return section(t('report.passes'), h('div', { class: 'bars' }, ...list.map((p) => {
    const bar = h('i');
    bar.style.width = `${Math.max(2, (p.ms / max) * 100)}%`;
    return h('div', { class: 'bar' },
      h('span', {}, p.id),
      h('span', {}, bar),
      h('span', {}, `${p.ms} ms`),
      h('span', { class: p.fail ? 'bar-fail' : 'bar-ok' }, p.fail ? t('report.pass.failed') : p.ok ? t('report.pass.ok') : '–'));
  })));
}

/**
 * @param {HTMLElement} el
 * @param {object|null} report
 * @param {{ verified?: boolean, ms?: number, events?: object[], deps?: object[], onExport?: () => void }} [extra]
 */
export function renderReport(el, report, extra = {}) {
  el.textContent = '';
  if (!report) {
    el.append(h('p', { class: 'placeholder' }, t('report.empty')));
    return;
  }
  const rep = h('div', { class: 'rep' });
  if (report.summary) rep.append(h('p', { class: 'rep-summary' }, str(report.summary)));
  for (const node of [
    protection(report.protection),
    threat(report.threat),
    detection(report.detection),
    goInfo(report, extra),
    literals(report.literals, report.unresolved),
    behaviour(report.behaviour),
    notable(report.notable, report.crypto),
    iocs(report.iocs),
    metrics(report.metrics, extra),
    passTimes(extra.events),
  ]) if (node) rep.append(node);
  if (extra.onExport) rep.append(h('button', { type: 'button', class: 'ghost small rep-export', onclick: extra.onExport }, t('action.export')));
  el.append(rep);
}
