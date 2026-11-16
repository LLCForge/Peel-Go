// Dışa aktarma: Ghidra (Python, Jython ya da PyGhidra), IDA (IDAPython), radare2/rizin (.r2 komutları) ve JSON.
// Fonksiyon adları ve dizgeler ikiliden gelir, yani güvenilmezdir:
//   Python betikleri veriyi base64 kodlu JSON olarak taşır (adlar koda hiç girmez, kod enjeksiyonu yok);
//   r2 betiğinde adlar [A-Za-z0-9_.] kümesine indirgenir, yorumlar "CCu base64:" ile yazılır.

export const FORMATS = ['listing', 'ghidra', 'ida', 'r2', 'json'];
export const EXT = { listing: '.peel.txt', ghidra: '.ghidra.py', ida: '.ida.py', r2: '.r2', json: '.peel.json' };
const MAX_COMMENT = 1000;

const b64 = (s) => {
  const bytes = new TextEncoder().encode(s);
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
};
/** IDA/r2 için güvenli ad: Go adının okunur kalması için ayraçlar '_' olur */
export const safeName = (name) => {
  const s = String(name).replace(/[^A-Za-z0-9_.$]/g, '_').replace(/_{2,}/g, '_').slice(0, 480);
  return /^[A-Za-z_.$]/.test(s) ? s : `_${s}`;
};
const clip = (s) => (s.length > MAX_COMMENT ? `${s.slice(0, MAX_COMMENT - 1)}…` : s);

/** Ortak yük: fonksiyonlar + yorumlar */
export function payload(r) {
  const functions = r.functions.map((f) => ({
    entry: f.entry,
    end: f.end,
    name: f.name,
    safe: safeName(f.name),
    comment: f.file ? `${f.file}:${f.startLine}${f.endLine > f.startLine ? `-${f.endLine}` : ''}` : '',
  }));
  const comments = [
    ...r.literals.recovered.map((l) => ({ at: l.site, text: clip(`peel-go literal [${l.family}]: ${JSON.stringify(l.value)}`) })),
    ...r.literals.unresolved.map((u) => ({ at: u.site, text: `peel-go literal NOT RECOVERED (${u.reason})` })),
  ];
  return { tool: 'peel-go', format: r.binary.format, arch: r.binary.arch, go: r.go.version ?? null, functions, comments };
}

const PY_HEADER = (tool, how) => `# Peel-Go export for ${tool}: function names from the Go pclntab, comments for recovered strings.
# ${how}
# Data is embedded as base64 JSON and never evaluated as code.
`;

export function ghidraScript(r) {
  const data = b64(JSON.stringify(payload(r)));
  return `${PY_HEADER('Ghidra', 'Script Manager > New script (Python), paste, run on the same binary (Jython or PyGhidra).')}# @category Peel-Go
import base64
import json
from ghidra.program.model.symbol import SourceType

DATA = json.loads(base64.b64decode("${data}").decode("utf-8"))


def main():
    fm = currentProgram.getFunctionManager()
    named = 0
    for f in DATA["functions"]:
        addr = toAddr(f["entry"])
        fn = fm.getFunctionAt(addr)
        if fn is None:
            disassemble(addr)
            fn = createFunction(addr, None)
        if fn is None:
            continue
        try:
            fn.setName(f["name"].replace(" ", "_"), SourceType.USER_DEFINED)
            named += 1
        except Exception:
            fn.setName(f["safe"], SourceType.USER_DEFINED)
            named += 1
        if f["comment"]:
            setPlateComment(addr, f["comment"])
    for c in DATA["comments"]:
        setEOLComment(toAddr(c["at"]), c["text"])
    print("Peel-Go: %d functions named, %d comments" % (named, len(DATA["comments"])))


main()
`;
}

export function idaScript(r) {
  const data = b64(JSON.stringify(payload(r)));
  return `${PY_HEADER('IDA Pro', 'File > Script file… (IDAPython, IDA 7.4+).')}import base64
import json

import ida_funcs
import ida_name
import idc

DATA = json.loads(base64.b64decode("${data}").decode("utf-8"))


def main():
    named = 0
    for f in DATA["functions"]:
        ea = f["entry"]
        if ida_funcs.get_func(ea) is None:
            ida_funcs.add_func(ea)
        if ida_name.set_name(ea, f["safe"], ida_name.SN_NOWARN | ida_name.SN_FORCE):
            named += 1
        if f["comment"]:
            idc.set_func_cmt(ea, f["name"] + "  " + f["comment"], 1)
    for c in DATA["comments"]:
        idc.set_cmt(c["at"], c["text"], 0)
    print("Peel-Go: %d functions named, %d comments" % (named, len(DATA["comments"])))


main()
`;
}

export function r2Script(r) {
  const p = payload(r);
  const lines = [
    '# Peel-Go export for radare2 / rizin: function names from the Go pclntab, comments for recovered strings.',
    '# r2 -i peel.r2 <binary>     rizin -i peel.r2 <binary>',
    'fs+peelgo',
  ];
  for (const f of p.functions) {
    const at = `0x${f.entry.toString(16)}`;
    lines.push(`af @ ${at}`, `afn ${f.safe} @ ${at}`, `f go.${f.safe} ${Math.max(1, f.end - f.entry)} @ ${at}`);
    if (f.comment) lines.push(`CCu base64:${b64(`${f.name}  ${f.comment}`)} @ ${at}`);
  }
  for (const c of p.comments) lines.push(`CCu base64:${b64(c.text)} @ 0x${c.at.toString(16)}`);
  lines.push('fs-');
  return `${lines.join('\n')}\n`;
}

/** Tam JSON: rapor + fonksiyonlar + modüller + türler + dizgeler */
export function jsonExport(r) {
  return `${JSON.stringify({
    tool: 'peel-go',
    binary: r.binary,
    go: r.go,
    pclntab: r.pclntab,
    buildinfo: r.buildinfo,
    moduledata: r.moduledata,
    functions: r.functions.map(({ symbol, ...f }) => f),
    packages: r.packages,
    files: r.files,
    types: r.types,
    itabs: r.itabs,
    strings: r.strings,
    literals: r.literals,
    report: r.report,
  }, null, 2)}\n`;
}

export function exportAs(r, fmt) {
  switch (fmt) {
    case 'ghidra': return ghidraScript(r);
    case 'ida': return idaScript(r);
    case 'r2': return r2Script(r);
    case 'json': return jsonExport(r);
    default: return r.listing;
  }
}
