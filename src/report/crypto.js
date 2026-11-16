// Kripto sabitleri: rodata/veri bölgelerinde bilinen tablo ve başlangıç değerleri (küçük sonlu). Go'nun kendi crypto
// paketleri de bu sabitleri taşır; bulgu bilgi amaçlıdır, tehdit puanına girmez.
import { findAll } from '../core/reader.js';

const le32 = (...ws) => ws.flatMap((w) => [w & 0xff, (w >>> 8) & 0xff, (w >>> 16) & 0xff, w >>> 24]);
const SIGS = [
  ['AES S-box', [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]],
  ['AES T-table (Te0)', le32(0xa56363c6, 0x847c7cf8, 0x997777ee)],
  ['SHA-256 K', le32(0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5)],
  ['SHA-256 IV', le32(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a)],
  ['SHA-512 K', le32(0xd728ae22, 0x428a2f98, 0x23ef65cd, 0x71374491)],
  ['MD5 T', le32(0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee)],
  ['SHA-1 K', le32(0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6)],
  ['ChaCha20/Salsa20 sigma', [...'expand 32-byte k'].map((c) => c.charCodeAt(0))],
  ['CRC-32 table', le32(0x00000000, 0x77073096, 0xee0e612c, 0x990951ba)],
  ['Blowfish P-array', le32(0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344)],
  ['RC2/Pi table', [0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79]],
];

/** @returns {Array<{ name, at, region }>} */
export function cryptoConstants(img) {
  const out = [];
  for (const [name, pat] of SIGS) {
    for (const r of img.regions) {
      if (!r.fileSize) continue;
      const b = img.bytes.subarray(r.fileOff, r.fileOff + r.fileSize);
      const hit = findAll(b, pat, 1)[0];
      if (hit != null) { out.push({ name, at: r.addr + hit, region: r.name }); break; }
    }
  }
  return out;
}
