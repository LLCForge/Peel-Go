// Worker tarafı ortak işleyici (tarayıcı Web Worker'ı ve Node worker_threads): soyma hattını çalıştırır, ilerlemeyi
// ayrı 'progress' iletileriyle bildirir. Hedef ikili burada da çalıştırılmaz; yalnızca baytları okunur ve öykünülür.
import { peelBinary } from '../core/pipeline.js';

/**
 * @param {{ id, type: 'peel', bytes: Uint8Array, name?, lang?, only? }} msg
 * @param {(m: object) => void} post
 */
export async function handle(msg, post) {
  if (msg?.type !== 'peel') return { ok: false, error: `bilinmeyen istek: ${String(msg?.type)}` };
  if (!(msg.bytes instanceof Uint8Array)) return { ok: false, error: 'bytes Uint8Array olmalı' };
  const progress = (kind, data) => post({ id: msg.id, type: 'progress', kind, ...data });
  const r = await peelBinary(msg.bytes, {
    name: typeof msg.name === 'string' ? msg.name.slice(0, 200) : '',
    lang: msg.lang === 'en' ? 'en' : 'tr',
    only: Array.isArray(msg.only) ? msg.only.filter((x) => typeof x === 'string') : null,
    onLog: (m, level) => progress('log', { m, level }),
    onPass: (pass, state) => progress('pass', { pass, state }),
    onSnapshot: (s) => progress('snapshot', { snap: s }),
  });
  return { ok: !r.error, result: r };
}
