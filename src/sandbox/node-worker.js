// Node worker_threads tarafı: tarayıcıdaki web-worker.js ile aynı işleyici.
import { parentPort } from 'node:worker_threads';
import { handle } from './handler.js';

parentPort.on('message', async (data) => {
  const { id, ...msg } = data ?? {};
  let result;
  try {
    result = await handle({ id, ...msg }, (m) => parentPort.postMessage(m));
  } catch (err) {
    result = { ok: false, error: String(err?.message ?? err).split('\n').filter(Boolean).slice(-3).join(' | ') };
  }
  parentPort.postMessage({ id, ...result });
});
