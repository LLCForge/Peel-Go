// Node (CLI ve testler) için bekçili sandbox: soyma hattı ayrı bir worker_threads iş parçacığında çalışır; son tarihi
// aşan iş parçacığı sonlandırılır (sert zaman sınırı), sıradaki istek yenisinde başlar. Bellek de sınırlıdır.
import { Worker } from 'node:worker_threads';
import { createWatchdog } from './watchdog.js';
import { sandboxApi } from './api.js';

const WORKER = new URL('./node-worker.js', import.meta.url);

export function createNodeSandbox({ maxHeapMb = 2048 } = {}) {
  let progress = () => {};
  const dog = createWatchdog({
    spawn() {
      const w = new Worker(WORKER, { resourceLimits: { maxOldGenerationSizeMb: maxHeapMb } });
      let onErr = () => {};
      let onMsg = () => {};
      w.on('message', (data) => {
        if (data?.type === 'progress') { progress(data); return; }
        onMsg(data);
      });
      w.on('error', (e) => onErr(e?.message ?? String(e)));
      w.on('exit', (code) => { if (code !== 0) onErr(`sandbox iş parçacığı çıktı (${code})`); });
      return {
        post: (m) => w.postMessage(m),
        onMessage: (cb) => { onMsg = cb; },
        onError: (cb) => { onErr = cb; },
        terminate: () => { onErr = () => {}; w.terminate(); },
        ref: () => w.ref(),
        unref: () => w.unref(),
      };
    },
  });
  return { ...sandboxApi(dog.send, (fn) => { progress = fn; }), watchdogStats: dog.stats, kill: (reason) => dog.kill(reason), close: () => dog.terminate() };
}
