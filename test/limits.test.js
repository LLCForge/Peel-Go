// Sınırlar: girdi boyutu, pclntab/tür/dizge/öykünme bütçeleri, bozuk ve rastgele girdiler (çökme yok, süre sınırlı).
import assert from 'node:assert/strict';
import { peelBinary, MAX_INPUT } from '../src/core/pipeline.js';
import { LIMITS as PCLN } from '../src/core/pclntab.js';
import { LIMITS as LIT } from '../src/core/literals.js';
import { LIMITS as STR } from '../src/core/strings.js';
import { LIMITS as MD } from '../src/core/moduledata.js';
import { LIMITS as LST } from '../src/report/listing.js';
import { reader, ParseError } from '../src/core/reader.js';
import { synthetic, fixture } from './helpers.js';

// tavanlar tanımlı ve akla yatkın
assert.equal(MAX_INPUT, 256 * 1024 * 1024);
assert.ok(PCLN.maxFuncs <= 400_000 && PCLN.maxPcValueSteps <= 200_000);
assert.ok(LIT.totalSteps <= 10_000_000 && LIT.timeMs <= 15_000 && LIT.maxDepth <= 4 && LIT.pathsPerRoot <= 64);
assert.ok(STR.maxStrings <= 100_000 && STR.maxLen <= 4096);
assert.ok(MD.maxTypes <= 50_000 && MD.maxItabs <= 50_000);
assert.ok(LST.maxLines <= 100_000);

// büyük girdi: işlenmeden reddedilir (tampon ayrılmadan: uzunluk vekili)
const huge = new Uint8Array(16);
Object.defineProperty(huge, 'length', { value: MAX_INPUT + 1 });
const big = await peelBinary(huge, {});
assert.match(big.error, /çok büyük/);

// okuyucu: sınır dışı ve taşan uvarint
const r = reader(Uint8Array.of(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
assert.throws(() => r.u32(9), ParseError);
assert.throws(() => r.uvarint(0), ParseError);
assert.throws(() => reader(Uint8Array.of(0x41, 0x42)).cstr(0), ParseError);

// bozuk ikililer: rastgele bayt değiştirme, kesme; her durumda sonuç ya da {error}, istisna yok
const base = synthetic().bytes;
let seed = 11;
const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed; };
const t0 = Date.now();
let errors = 0;
for (let i = 0; i < 120; i++) {
  const x = base.slice(0, i % 7 === 0 ? 64 + (rnd() % base.length) : base.length);
  for (let k = 0; k < 24; k++) x[rnd() % x.length] = rnd() & 0xff;
  const res = await peelBinary(x, { lang: 'en' });
  if (res.error) errors++;
  else assert.ok(res.report && typeof res.report.summary === 'string');
}
assert.ok(Date.now() - t0 < 60_000, 'bozuk girdiler zaman sınırını aştı');

// Go olmayan / boş / yalnızca sihirli bayt
for (const b of [new Uint8Array(0), Uint8Array.of(0x7f, 0x45, 0x4c, 0x46), new TextEncoder().encode('MZ' + 'x'.repeat(200))]) {
  const res = await peelBinary(b, { lang: 'en' });
  assert.ok(res.error || res.report);
}

// gerçek ikili zaman bütçesi
const t1 = Date.now();
const real = await peelBinary(fixture('garblelike.windows-amd64.gz'), { lang: 'en' });
assert.ok(!real.error && Date.now() - t1 < 15_000);
console.log(`limits: tavanlar, büyük girdi reddi, 120 bozuk ikili (${errors} okunamadı, 0 istisna), ${Date.now() - t1} ms gerçek ikili`);
