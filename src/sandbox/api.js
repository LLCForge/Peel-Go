// Sandbox istemci API'si (tarayıcı ve Node ortak): peel(bytes, seçenekler) → pipeline sonucu.
// İlerleme (log, geçiş durumu, anlık görüntü) worker'dan ayrı iletilerle gelir ve çağıranın geri çağrılarına dağıtılır.

export const DEADLINE_MS = 90_000;

/**
 * @param {(msg) => Promise<object>} send bekçinin send'i
 * @param {(fn) => void} setProgress ilerleme dinleyicisini kurar
 */
export function sandboxApi(send, setProgress) {
  return {
    async peel(bytes, { name = '', lang = 'tr', only = null, onLog = () => {}, onPass = () => {}, onSnapshot = () => {}, deadlineMs = DEADLINE_MS } = {}) {
      setProgress((p) => {
        if (p.kind === 'log') onLog(p.m, p.level);
        else if (p.kind === 'pass') onPass(p.pass, p.state);
        else if (p.kind === 'snapshot') onSnapshot(p.snap);
      });
      try {
        // kopya gönderilir: çağıranın tamponu aktarılıp boşaltılmasın
        const r = await send({ type: 'peel', bytes: bytes.slice(), name, lang, only, deadlineMs });
        if (r.result) return r.result;
        return { error: r.error ?? 'sandbox hatası', timedOut: Boolean(r.timedOut), events: [], stats: {} };
      } finally {
        setProgress(() => {});
      }
    },
  };
}
