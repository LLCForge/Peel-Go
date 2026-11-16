// Bayt okuma yardımcıları: sınır denetimli tamsayı okuma (LE/BE), C dizgesi, uvarint. Tüm ayrıştırıcılar buradan okur;
// dosya dışına taşan her okuma ParseError fırlatır (bozuk ya da kasıtlı olarak kırpılmış ikililer çökmeye yol açmaz).

export class ParseError extends Error {}

export const MAX_CSTR = 4096;
const latin1 = new TextDecoder('latin1');

/** Uint8Array → okuyucu. le: küçük sonlu mu */
export function reader(bytes, le = true) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const n = bytes.length;
  const need = (off, size) => {
    if (!Number.isInteger(off) || off < 0 || off + size > n) throw new ParseError(`okuma sınır dışı: 0x${Number(off).toString(16)}+${size}`);
  };
  const r = {
    bytes,
    le,
    length: n,
    u8: (o) => { need(o, 1); return bytes[o]; },
    u16: (o) => { need(o, 2); return dv.getUint16(o, le); },
    u32: (o) => { need(o, 4); return dv.getUint32(o, le); },
    i32: (o) => { need(o, 4); return dv.getInt32(o, le); },
    i16: (o) => { need(o, 2); return dv.getInt16(o, le); },
    // 64 bit adresler Number'a sığar (2^53 altı); daha büyükse hata (geçerli bir Go ikilisinde olmaz)
    u64: (o) => {
      need(o, 8);
      const v = dv.getBigUint64(o, le);
      if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new ParseError(`64 bit değer çok büyük @0x${o.toString(16)}`);
      return Number(v);
    },
    ptr: (o, size) => (size === 8 ? r.u64(o) : r.u32(o)),
    slice: (o, len) => { need(o, len); return bytes.subarray(o, o + len); },
    /** NUL ile biten dizge (en çok max bayt); sonu yoksa ParseError */
    cstr: (o, max = MAX_CSTR) => {
      need(o, 1);
      const end = Math.min(n, o + max);
      let i = o;
      while (i < end && bytes[i] !== 0) i++;
      if (i === end && (end === n || bytes[i] !== 0)) throw new ParseError(`dizge sonu yok @0x${o.toString(16)}`);
      return decode(bytes.subarray(o, i));
    },
    /** uvarint (Go encoding/binary); dönüş [değer, bayt sayısı] */
    uvarint: (o) => {
      let v = 0;
      let shift = 0;
      for (let i = 0; i < 10; i++) {
        const b = r.u8(o + i);
        v += (b & 0x7f) * 2 ** shift;
        if (b < 0x80) return [v, i + 1];
        shift += 7;
        if (shift > 49) throw new ParseError('uvarint taşması');
      }
      throw new ParseError('uvarint çok uzun');
    },
  };
  return r;
}

/** UTF-8 ise UTF-8, değilse Latin-1 (Go adları normalde ASCII/UTF-8) */
export function decode(b) {
  for (let i = 0; i < b.length; i++) {
    if (b[i] >= 0x80) {
      try { return new TextDecoder('utf-8', { fatal: true }).decode(b); } catch { return latin1.decode(b); }
    }
  }
  return latin1.decode(b);
}


/** bytes içinde needle'ın tüm konumları (en çok max) */
export function findAll(bytes, needle, max = 64, from = 0) {
  const out = [];
  const first = needle[0];
  outer: for (let i = bytes.indexOf(first, from); i >= 0 && i + needle.length <= bytes.length; i = bytes.indexOf(first, i + 1)) {
    for (let j = 1; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
    out.push(i);
    if (out.length >= max) break;
  }
  return out;
}

export const ascii = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff);
