// Peel-Go kütüphane API'si. Saf JavaScript; yerel bağımlılık yok, hedef ikili hiçbir zaman çalıştırılmaz.
//   import { peel, exportAs } from 'peel-go';
//   const r = await peel(readFileSync('app'), { lang: 'en' });
//   r.report, r.functions, r.listing, exportAs(r, 'ghidra')
import { peelBinary } from './core/pipeline.js';
import { analyze as runAnalyze } from './core/analyze.js';
import { PASSES } from './passes/index.js';

export { exportAs, FORMATS, EXT } from './report/exports.js';
export { reportText } from './report/text.js';

const toBytes = (input) => {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  throw new TypeError('girdi Uint8Array ya da ArrayBuffer olmalı (Go ikilisi baytları)');
};

/**
 * Soyma + rapor. Dönüş: { binary, go, pclntab, buildinfo, moduledata, functions, packages, files, types, itabs, strings,
 * literals, report, listing, rawView, events, stats, verified, ms } ya da { error }
 */
export async function peel(input, { sandbox = null, ...options } = {}) {
  const bytes = toBytes(input);
  // tarayıcıda (ya da isteğe bağlı) yalıtılmış worker; yoksa aynı süreçte (sınırlı bütçelerle)
  if (sandbox) return sandbox.peel(bytes, options);
  return peelBinary(bytes, options).catch((e) => ({ error: String(e?.message ?? e), events: [], stats: {} }));
}

/** Yalnızca rapor (var olan bir sonuç için, örn. dil değiştirirken) */
export const analyze = runAnalyze;
export const passes = () => PASSES.map(({ id, required }) => ({ id, required: Boolean(required) }));
