// Sandbox: Node worker_threads iş parçacığında soyma, aynı süreçteki sonuçla birebir; ilerleme iletileri; bekçinin
// süre sınırı ve Durdur (kill); kuyruktaki iş yeni iş parçacığında devam eder.
import assert from 'node:assert/strict';
import { createNodeSandbox } from '../src/sandbox/node-host.js';
import { peel } from '../src/index.js';
import { fixture, synthetic } from './helpers.js';

const sb = createNodeSandbox();
try {
  const bytes = fixture('garblelike.linux-amd64.gz');
  const logs = [];
  const passes = [];
  const snaps = [];
  const a = await peel(bytes, { sandbox: sb, lang: 'en', onLog: (m) => logs.push(m), onPass: (id, s) => passes.push(`${id}:${s}`), onSnapshot: (s) => snaps.push(s.id) });
  const b = await peel(bytes, { lang: 'en' });
  assert.ok(!a.error, a.error);
  assert.equal(a.listing, b.listing, 'worker ve aynı süreç listelemesi farklı');
  assert.deepEqual(a.literals.recovered.map((l) => l.value), b.literals.recovered.map((l) => l.value));
  assert.ok(logs.some((m) => /pclntab 1\.20/.test(m)));
  assert.ok(passes.includes('literals:ok') && passes.includes('container:run'));
  assert.deepEqual(snaps, ['pclntab', 'strings', 'literals']);
  assert.equal(bytes.length > 0, true, 'çağıranın tamponu aktarılıp boşaltılmamalı');

  // süre sınırı: iş parçacığı öldürülür, hata döner, sonraki iş yenisinde çalışır
  const slow = await peel(bytes, { sandbox: sb, deadlineMs: 1 });
  assert.equal(slow.timedOut, true);
  assert.match(slow.error, /zaman aşımı/);
  const after = await peel(synthetic().bytes, { sandbox: sb, lang: 'tr' });
  assert.equal(after.literals.recovered.length, 1);
  assert.ok(sb.watchdogStats.restarts >= 1 && sb.watchdogStats.timeouts >= 1);

  // Durdur: uçuştaki ve kuyruktaki işler hata alır
  const p1 = peel(bytes, { sandbox: sb });
  const p2 = peel(bytes, { sandbox: sb });
  sb.kill('Durduruldu');
  const [k1, k2] = await Promise.all([p1, p2]);
  assert.equal(k1.error, 'Durduruldu');
  assert.equal(k2.error, 'Durduruldu');
  const again = await peel(synthetic().bytes, { sandbox: sb });
  assert.ok(!again.error);
  console.log(`sandbox: worker = aynı süreç, ilerleme iletileri, zaman aşımı, Durdur (${sb.watchdogStats.restarts} yeniden başlatma)`);
} finally {
  sb.close();
}
