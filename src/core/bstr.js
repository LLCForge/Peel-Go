// İkili dosya arayüzde ve oturum kaydında "bayt dizisi" (bstr) olarak tutulur: her karakter bir bayttır (0-255).
// Böylece IndexedDB/JSON oturumuna olduğu gibi yazılır ve geçersiz UTF-8 ikili veriyi bozmaz. Metne çevirme yalnızca
// girdi/çıktı sınırındadır.

/** Uint8Array → bstr */
export function fromBytes(bytes) {
  let s = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  return s;
}

/** bstr → Uint8Array */
export function toBytes(bstr) {
  const out = new Uint8Array(bstr.length);
  for (let i = 0; i < bstr.length; i++) out[i] = bstr.charCodeAt(i) & 0xff;
  return out;
}

