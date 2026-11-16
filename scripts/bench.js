#!/usr/bin/env node
// Ölçüm: her fixture tam hattan N kez geçer (aynı süreç), ortanca süre ve geçiş başına süreler yazılır.
//   node scripts/bench.js [tekrar=5]
import { peelBinary } from '../src/core/pipeline.js';
import { manifest, fixture } from '../test/helpers.js';

const N = Math.max(1, Number(process.argv[2]) || 5);
const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
const rows = [];
for (const fx of manifest.fixtures) {
  const bytes = fixture(fx.file);
  const times = [];
  const passes = {};
  let r;
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    r = await peelBinary(bytes, { lang: 'en' });
    times.push(performance.now() - t0);
    for (const e of r.events) (passes[e.id] ??= []).push(e.ms);
  }
  rows.push({
    file: fx.file.replace(/\.gz$/, ''),
    mb: (bytes.length / 1048576).toFixed(2),
    ms: Math.round(median(times)),
    functions: r.functions.length,
    strings: r.strings.length,
    literals: r.literals.recovered.length,
    emuSteps: r.literals.steps,
    pclntab: median(passes.pclntab),
    strings_ms: median(passes.strings),
    literals_ms: median(passes.literals),
  });
}
console.table(rows);
const total = rows.reduce((s, x) => s + x.ms, 0);
console.log(`${rows.length} ikili, ortanca toplam ${total} ms (${N} tekrar, Node ${process.versions.node})`);
