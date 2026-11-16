// UPX tanıma: "UPX!" üst bilgisi, UPX0/UPX1 bölüm adları, "$Info:/$Id: UPX" dizgeleri, bölüm tablosu olmayan ELF.
// Açma yapılmaz: sıkıştırılmış gövdedeki pclntab okunamaz; rapor `upx -d` ile açıp yeniden yüklemeyi önerir.
import { ascii, findAll } from './reader.js';

const MAGIC = ascii('UPX!');
const INFO = ascii('$Info: This file is packed with the UPX');
const ID = ascii('$Id: UPX ');

/** @returns {null | { markers: string[], version: string|null }} */
export function detectUpx(img) {
  const b = img.bytes;
  const markers = [];
  const head = b.subarray(0, Math.min(b.length, 0x2000));
  const tail = b.subarray(Math.max(0, b.length - 0x2000));
  const hits = findAll(head, MAGIC, 4).length + findAll(tail, MAGIC, 4).length;
  if (hits) markers.push(`UPX! ×${hits}`);
  const upxSecs = img.sections.filter((s) => /^\.?UPX\d$/i.test(s.name)).map((s) => s.name);
  if (upxSecs.length) markers.push(`sections: ${upxSecs.join(', ')}`);
  if (findAll(b, INFO, 1).length) markers.push('$Info: … UPX executable packer');
  let version = null;
  const id = findAll(b, ID, 1)[0];
  if (id != null) {
    const m = /^\$Id: UPX (\d+\.\d+(?:\.\d+)?)/.exec(String.fromCharCode(...b.subarray(id, id + 24)));
    if (m) { version = m[1]; markers.push(`$Id: UPX ${version}`); }
  }
  if (img.format === 'elf' && img.noSections && markers.length) markers.push('ELF: no section headers');
  return markers.length ? { markers, version } : null;
}
