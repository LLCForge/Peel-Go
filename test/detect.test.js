// Tespit: garble (karma adlar, boşaltılmış buildinfo, -literals, -tiny), gobfuscate, UPX (PE bölümleri ve bölümsüz
// ELF), silinmiş semboller; ad puanlamasının yanlış pozitif oranı ve tehdit sınıfları.
import assert from 'node:assert/strict';
import { peel } from '../src/index.js';
import { hashScore, randomLowerScore, packageOf, isStdFunc } from '../src/core/gonames.js';
import { buildContainer } from '../src/core/synth.js';
import { openImage } from '../src/core/container.js';
import { findPclntab } from '../src/core/pclntab.js';
import { fixture, synthetic } from './helpers.js';

// ad yardımcıları
assert.equal(packageOf('github.com/a/b.(*T).M'), 'github.com/a/b');
assert.equal(packageOf('gopkg.in/yaml.v3.(*decoder).unmarshal'), 'gopkg.in/yaml.v3');
assert.equal(packageOf('main.main.func1'), 'main');
assert.equal(packageOf('type:.eq.main.T'), 'type:');
assert.equal(packageOf('example.com/m.Map[...].Get'), 'example.com/m');
assert.ok(isStdFunc('runtime.main') && isStdFunc('internal/abi.(*Type).Kind') && isStdFunc('__x86.get_pc_thunk.ax'));
assert.ok(!isStdFunc('main.main') && !isStdFunc('github.com/x/y.F') && !isStdFunc('Wq8eZtLp/kQ8wZr3T.F'));
for (const h of ['Zx3kP9qL', 'kQ8wZr3T', 'Yt5Kc0Vd', 'Hx3kL2pm', 'Wq8eZtLp', 'aZ3_xQ9w']) assert.ok(hashScore(h) >= 0.6, `karma: ${h}`);
for (const w of ['ServeHTTP', 'getPCThunk', 'get_pc_thunk', 'Unmarshal', 'newRequest', 'WriteString', 'x509', 'parseHTTPHeader', 'gcBgMarkWorker']) assert.ok(hashScore(w) < 0.6, `sözcük: ${w}`);
assert.ok(randomLowerScore('kzqvtrwxbnmplhgd') >= 0.5 && randomLowerScore('3f9a0c7e1b2d4f6a') >= 0.5);
for (const w of ['netpollblockcommit', 'printcomplex128', 'stringslite', 'kubernetes']) assert.ok(randomLowerScore(w) < 0.5, `sözcük: ${w}`);

// gerçek std adlarında karma yanlış pozitif oranı
const tab = findPclntab(openImage(fixture('basic.linux-amd64.gz'))).tab;
const fp = tab.funcs.filter((f) => f.name.split(/[./()*]+/).some((x) => hashScore(x) >= 0.6)).length / tab.funcs.length;
assert.ok(fp < 0.02, `std yanlış pozitif %${(fp * 100).toFixed(1)}`);

const ids = (r) => new Set(r.report.detection.map((d) => d.id));

// garble: karma adlar + boşaltılmış modinfo + gizli dizge
const garbled = await peel(synthetic({ names: { lit: 'Wq8eZtLp/kQ8wZr3T.Yt5Kc0Vd', main: 'main.main' }, buildinfo: { version: 'go1.22.1', modinfo: '' } }).bytes, { lang: 'en' });
const g = garbled.report.detection.find((d) => d.id === 'garble');
assert.ok(g, [...ids(garbled)].join(','));
assert.ok(g.traits.hashedNames && g.traits.buildinfoStripped && g.traits.literals === 1);
assert.ok(g.evidence.some((e) => /-seed/.test(e)));

// -tiny: karma adlar, dosya/satır yok
const tiny = await peel(synthetic({ names: { lit: 'Wq8eZtLp.Yt5Kc0Vd', main: 'Wq8eZtLp.Fx3qLm9P' }, files: false, buildinfo: { version: 'go1.22.1', modinfo: '' } }).bytes, { lang: 'en' });
assert.equal(tiny.report.detection.find((d) => d.id === 'garble')?.traits.tiny, true);

// gobfuscate: rastgele küçük harfli paket
const gobf = await peel(synthetic({ names: { lit: 'kzqvtrwxbnmplhgd/jxwvqrlsugzbkhfn.Vqzrtkxwlpmnbhgf', main: 'main.main' } }).bytes, { lang: 'en' });
assert.ok(ids(gobf).has('gobfuscate') && !ids(gobf).has('garble'), [...ids(gobf)].join(','));

// yalnızca gizli dizge (adlar normal): teknik olarak raporlanır, gizleyici adı verilmez
const litOnly = await peel(synthetic().bytes, { lang: 'en' });
assert.ok(ids(litOnly).has('literals') && !ids(litOnly).has('garble'), [...ids(litOnly)].join(','));
assert.ok(ids(litOnly).has('stripped'));

// UPX: PE (UPX0/UPX1 + UPX! + $Info), pclntab yok → paketleyici + koruma notları
const enc = new TextEncoder();
const upxBody = new Uint8Array(512);
upxBody.set(enc.encode('$Info: This file is packed with the UPX executable packer http://upx.sf.net $\n$Id: UPX 4.24 Copyright'), 16);
upxBody.set(enc.encode('UPX!'), 200);
const upxPe = buildContainer({ format: 'pe', sections: [{ name: 'UPX0', data: new Uint8Array(64), exec: true }, { name: 'UPX1', data: upxBody, exec: true }, { name: '.rsrc', data: new Uint8Array(32) }] });
const up = await peel(upxPe.bytes, { lang: 'en' });
assert.ok(!up.error, up.error);
const u = up.report.detection.find((d) => d.id === 'upx');
assert.ok(u && u.version === '4.24' && u.decodable === false && u.confidence >= 0.9);
assert.equal(up.report.protection.product, 'UPX');
assert.ok(up.report.threat.classes.some((c) => c.id === 'packed'));
assert.equal(up.pclntab, null);
// ELF: bölüm tablosu yok + UPX! üst bilgisi
const upxElf = buildContainer({ format: 'elf', sections: [{ name: '.text', data: new Uint8Array(64), exec: true }, { name: '.data', data: upxBody, write: true }], noSectionHeaders: true, extra: enc.encode('UPX!') });
const ue = await peel(upxElf.bytes, { lang: 'en' });
assert.ok(ue.report.detection.find((d) => d.id === 'upx').evidence.some((e) => /no section headers/.test(e)));

// tehdit: dizgelerden kalıcılık (şüpheli dizgeler kaynakta parçalı), enjeksiyon, Discord webhook (sızdırma)
const bad = [
  'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  ['Virtual', 'AllocEx'].join(''),
  ['https://discord.com/api/', 'webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz'].join(''),
].join('\0');
const evil = await peel(synthetic({ rodata: enc.encode(`\0${bad}\0`), literal: null }).bytes, { lang: 'en' });
const cls = new Set(evil.report.threat.classes.map((c) => c.id));
assert.ok(cls.has('persistence') && cls.has('injection') && cls.has('exfiltration'), [...cls].join(','));
assert.ok(['high', 'critical'].includes(evil.report.threat.level), evil.report.threat.level);
assert.ok(evil.report.iocs.discordWebhooks.length === 1);

// temiz gerçek ikili: tehdit yok, gizleyici yok
const clean = await peel(fixture('basic.windows-amd64.gz'), { lang: 'tr' });
assert.equal(clean.report.threat.level, 'none');
assert.ok(!ids(clean).has('garble') && !ids(clean).has('gobfuscate'));
assert.match(clean.report.summary, /Tehlikeli bir yetenek bulunmadı/);
console.log(`detect: garble (-literals, -tiny, buildinfo), gobfuscate, UPX (PE/ELF), stripped, tehdit sınıfları; std karma yanlış pozitif %${(fp * 100).toFixed(2)}`);
