// Web Worker tarafı: soyma hattı (ayrıştırıcılar + x86-64 öykünücüsü) burada çalışır; uzun süren ya da takılan iş ana
// thread'deki bekçi tarafından worker sonlandırılarak kesilir.
//
// Yalıtım worker düzeyindedir:
//  1. CSP: worker betiğinin yanıt başlığı (dev/preview: vite.config.js ara katmanı, üretim: public/_headers)
//     default-src 'none'; script-src 'self'; connect-src 'self'
//  2. JS kilidi: ilk iletiden önce ağ API'leri, eval/Function kurucuları, dizge zamanlayıcıları ve iç içe worker
//     kaldırılır. Başlık veremeyen barındırmada tek JS katmanı budur; durum ana thread'e 'env' iletisiyle bildirilir.
//  3. İncelenen ikili hiçbir zaman çalıştırılmaz: komutları JavaScript'te yorumlanır, sistem çağrısı yoktur.
import { handle } from './handler.js';

// CSP sınaması: bu betiğin kendi yanıtı yeniden (aynı köken) okunur ve başlıkta connect-src 'self' aranır
const cspProbe = fetch(self.location.href, { method: 'HEAD', cache: 'no-store' })
  .then((r) => /(^|;)\s*connect-src 'self'\s*(;|$)/.test(r.headers.get('content-security-policy') ?? ''), () => false);

// Kaldırılan genel adlar: ağ, kod üretme, iç içe worker, kalıcı depolama
const BLOCKED = [
  'fetch', 'fetchLater', 'XMLHttpRequest', 'WebSocket', 'WebSocketStream', 'EventSource', 'WebTransport',
  'importScripts', 'Worker', 'SharedWorker', 'caches', 'BroadcastChannel', 'indexedDB',
];
const denied = () => { throw new EvalError('Peel sandbox: kod üretimi kapalı'); };

function lockdown() {
  const ctorProtos = [
    Function.prototype,
    Object.getPrototypeOf(async function () {}),
    Object.getPrototypeOf(function* () {}),
    Object.getPrototypeOf(async function* () {}),
  ];
  for (const name of BLOCKED) {
    for (let o = self; o; o = Object.getPrototypeOf(o)) {
      if (Object.prototype.hasOwnProperty.call(o, name)) {
        Object.defineProperty(o, name, { value: undefined, writable: false, configurable: false });
      }
    }
  }
  const BlockedFunction = function Function() { denied(); };
  BlockedFunction.prototype = Function.prototype;
  const freeze = (o, k, value) => Object.defineProperty(o, k, { value, writable: false, configurable: false });
  freeze(self, 'eval', denied);
  freeze(self, 'Function', BlockedFunction);
  for (const proto of ctorProtos) freeze(proto, 'constructor', BlockedFunction);
  for (const name of ['setTimeout', 'setInterval']) {
    const real = self[name];
    Object.defineProperty(self, name, {
      value: (fn, ...rest) => (typeof fn === 'function' ? real(fn, ...rest) : 0),
      writable: false,
      configurable: false,
    });
  }
}

// kilit, CSP sınaması bitince ve ilk işten önce kurulur
const ready = cspProbe.then((csp) => {
  lockdown();
  self.postMessage({ type: 'env', csp, locked: true });
});

self.addEventListener('message', async ({ data }) => {
  await ready;
  const { id, ...msg } = data ?? {};
  let result;
  try {
    result = await handle({ id, ...msg }, (m) => self.postMessage(m));
  } catch (err) {
    result = { ok: false, error: String(err?.message ?? err).split('\n').filter(Boolean).slice(-3).join(' | ') };
  }
  self.postMessage({ id, ...result });
});
