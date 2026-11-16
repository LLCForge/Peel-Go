// Fixture testleri: test/fixtures/*.gz gerçek Go ikilileri (scripts/make-fixtures.js, go build) tam hattan geçer.
//   node test/run.js              hepsi
//   node test/run.js garble       adında "garble" geçenler, log ve listeleme başıyla
// Beklentiler manifest'ten (hedef GOOS/GOARCH, program, gizli dizgeler) ve aşağıdaki program kurallarından gelir.
import { peel } from '../src/index.js';
import { manifest, fixture } from './helpers.js';

const filter = process.argv[2];
const FORMAT = { linux: 'elf', windows: 'pe', darwin: 'macho' };
const list = manifest.fixtures.filter((f) => !filter || f.file.includes(filter));

let pass = 0;
const t0 = Date.now();
for (const fx of list) {
  const bytes = fixture(fx.file);
  const logs = [];
  const r = await peel(bytes, { name: fx.file, lang: 'en', onLog: (m, l) => logs.push(`[${l}] ${m}`) });
  const fails = [];
  const check = (ok, msg) => { if (!ok) fails.push(msg); };
  check(!r.error, `hata: ${r.error}`);
  if (!r.error) {
    const rep = r.report;
    const ids = new Set(rep.detection.map((d) => d.id));
    // ortak: kapsayıcı, pclntab, buildinfo, moduledata, çapraz denetim
    check(r.binary.format === FORMAT[fx.goos], `biçim ${r.binary.format}`);
    check(r.binary.arch === fx.goarch, `mimari ${r.binary.arch}`);
    check(r.go.version === manifest.go, `Go sürümü ${r.go.version} ≠ ${manifest.go}`);
    check(r.pclntab?.version === '1.20', `pclntab ${r.pclntab?.version}`);
    check(r.functions.length > 1500, `fonksiyon ${r.functions.length}`);
    check(r.functions.some((f) => f.name === 'main.main' && f.file?.endsWith('main.go') && f.startLine > 0), 'main.main dosya/satır yok');
    check(r.functions.some((f) => f.name === 'runtime.main' && f.file === 'runtime/proc.go'), 'runtime.main / runtime/proc.go yok');
    check(r.verified, 'çapraz denetim başarısız');
    check(r.moduledata && r.types.length > 300 && r.itabs.length > 5, `moduledata/türler: ${r.types.length} tür, ${r.itabs.length} itab`);
    check(ids.has('go'), 'Go araç zinciri tespit edilmedi');
    check(fx.symbols ? !ids.has('stripped') : ids.has('stripped'), `stripped tespiti yanlış (${fx.symbols ? 'semboller var' : 'semboller yok'})`);
    check(!r.events.some((e) => e.state === 'fail'), `başarısız geçiş: ${r.events.filter((e) => e.state === 'fail').map((e) => e.id)}`);
    if (fx.program === 'basic') {
      const bi = r.buildinfo;
      check(bi?.main?.path === 'example.com/peelfixture', `ana modül ${bi?.main?.path}`);
      check(bi?.deps.some((d) => d.path === 'example.com/peelutil' && d.replace?.path === './peelutil'), 'replace bağımlılığı yok');
      check(bi?.settings.GOOS === fx.goos && bi?.settings.GOARCH === fx.goarch && bi?.settings['-trimpath'] === 'true', 'build ayarları');
      check(!ids.has('garble') && !ids.has('gobfuscate') && !ids.has('literals'), `yanlış pozitif: ${[...ids].join(', ')}`);
      check(rep.iocs.urls.includes('https://cdn.peel-fixture.test/v1/check'), 'URL IOC yok');
      check(rep.iocs.ips.includes('198.51.100.7'), 'IP IOC yok');
      check(rep.threat.level === 'none', `tehdit ${rep.threat.level}`);
      check(rep.notable.some((n) => n.package === 'os/exec'), 'os/exec dikkat çeken paket değil');
      check(r.types.some((t) => t.name === 'main.Config'), 'main.Config türü yok');
      check(r.itabs.some((i) => i.type === '*main.Config' && i.iface === 'main.Checker'), 'itab *main.Config → main.Checker yok');
    }
    if (fx.program === 'garblelike') {
      const g = rep.detection.find((d) => d.id === 'garble');
      check(g && g.confidence >= 0.9 && g.traits.hashedNames && g.traits.buildinfoStripped, 'garble tespiti/izleri');
      for (const { family, value } of manifest.literals.garble) {
        check(r.literals.recovered.some((l) => l.value === value && l.family === family), `gizli dizge yok: [${family}] ${value}`);
      }
      check(r.literals.unresolved.length === 0, `çözülemeyen: ${r.literals.unresolved.map((u) => u.reason).join(', ')}`);
      check(rep.iocs.urls.includes('https://cdn.peel-fixture.test/v2/config.json'), 'çözülen URL IOC değil');
      check(rep.iocs.ips.includes('198.51.100.23'), 'çözülen IP IOC değil');
    }
    if (fx.program === 'gobflike') {
      check(ids.has('gobfuscate') && !ids.has('garble'), `gobfuscate tespiti: ${[...ids].join(', ')}`);
      for (const value of manifest.literals.gobf) check(r.literals.recovered.some((l) => l.value === value), `maske xor dizgesi yok: ${value}`);
    }
  }
  if (!fails.length) pass++;
  console.log(`${fails.length ? 'FAIL' : 'ok  '} ${fx.file} (${r.ms ?? 0} ms, ${r.functions?.length ?? 0} fonksiyon, ${r.literals?.recovered.length ?? 0} gizli dizge)${fails.length ? `\n     ${fails.join('\n     ')}` : ''}`);
  if (filter) {
    console.log(logs.join('\n'));
    console.log(r.listing?.split('\n').slice(0, 40).join('\n'));
    console.log(r.report?.summary);
  }
}
console.log(`\ntoplam ${Date.now() - t0}ms | ${pass}/${list.length}`);
if (pass !== list.length) process.exitCode = 1;
