// Dışa aktarma betikleri: Ghidra (Python), IDA (IDAPython), radare2/rizin, JSON, listeleme. Python varsa betikler
// sahte Ghidra/IDA API'leriyle gerçekten çalıştırılır. Kötü niyetli fonksiyon adı (tırnak, satır sonu, r2 ayırıcıları)
// koda/komuta sızamaz.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { peel, exportAs, FORMATS, EXT } from '../src/index.js';
import { safeName } from '../src/report/exports.js';
import { fixture } from './helpers.js';

const r = await peel(fixture('garblelike.linux-amd64.gz'), { lang: 'en' });
assert.deepEqual(FORMATS, ['listing', 'ghidra', 'ida', 'r2', 'json']);
assert.ok(Object.values(EXT).every((e) => e.startsWith('.')));

// kötü niyetli ad: Python dizgesinden ve r2 komutundan kaçmaya çalışır
const EVIL = 'main.x"); import os; os.system("id") #\n; !rm -rf / @ 0 | `cat` ~ $(x)';
r.functions[0] = { ...r.functions[0], name: EVIL };
const decodeData = (py) => JSON.parse(Buffer.from(/b64decode\("([A-Za-z0-9+/=]+)"\)/.exec(py)[1], 'base64').toString('utf8'));

for (const fmt of ['ghidra', 'ida']) {
  const py = exportAs(r, fmt);
  assert.ok(!py.includes(EVIL) && !py.includes('os.system'), `${fmt}: ad koda girmemeli`);
  const data = decodeData(py);
  assert.equal(data.functions[0].name, EVIL);
  assert.match(data.functions[0].safe, /^[A-Za-z0-9_.$]+$/);
  assert.equal(data.functions.length, r.functions.length);
  assert.equal(data.comments.filter((c) => c.text.includes('peel-go literal')).length, 7);
}
const r2 = exportAs(r, 'r2');
for (const line of r2.split('\n').filter((l) => l && !l.startsWith('#'))) {
  assert.match(line, /^(?:fs[+-](?:peelgo)?|af @ 0x[0-9a-f]+|afn [A-Za-z0-9_.$]+ @ 0x[0-9a-f]+|f go\.[A-Za-z0-9_.$]+ \d+ @ 0x[0-9a-f]+|CCu base64:[A-Za-z0-9+/=]+ @ 0x[0-9a-f]+)$/, `r2 satırı: ${line.slice(0, 80)}`);
}
const ccs = [...r2.matchAll(/CCu base64:([A-Za-z0-9+/=]+)/g)].map((m) => Buffer.from(m[1], 'base64').toString('utf8'));
assert.ok(ccs.some((c) => c.includes('"198.51.100.23:8443"')), 'r2 yorumu çözülen dizgeyi taşımalı');
assert.equal(safeName('a b/c.(*T).M'), 'a_b_c._T_.M');
assert.match(safeName('9lives'), /^_9lives$/);

const json = JSON.parse(exportAs(r, 'json'));
assert.equal(json.tool, 'peel-go');
assert.equal(json.literals.recovered.length, 7);
assert.ok(json.report.detection.some((d) => d.id === 'garble'));
assert.ok(!('symbol' in json.functions[0]));
assert.match(exportAs(r, 'listing'), /; literal 0x[0-9a-f]+ \[seed\] "fixture-token-not-a-secret"/);

// Python ile gerçek çalıştırma (varsa): sahte Ghidra ve IDA API'leri
const python = ['python', 'python3', 'py'].find((p) => spawnSync(p, ['--version'], { encoding: 'utf8' }).status === 0);
let ran = 0;
if (python) {
  const dir = mkdtempSync(join(tmpdir(), 'peel-go-exp-'));
  try {
    const ghidraStub = `
import sys, types, json
calls = {"names": {}, "plate": {}, "eol": {}, "created": 0}
mod = types.ModuleType("ghidra.program.model.symbol")
class SourceType: USER_DEFINED = "user"
mod.SourceType = SourceType
for n in ["ghidra", "ghidra.program", "ghidra.program.model"]:
    sys.modules[n] = types.ModuleType(n)
sys.modules["ghidra.program.model.symbol"] = mod
class Fn:
    def __init__(self, a): self.a = a
    def setName(self, name, src): calls["names"][self.a] = name
class FM:
    def getFunctionAt(self, a): return None
class Prog:
    def getFunctionManager(self): return FM()
def createFunction(a, n):
    calls["created"] += 1
    return Fn(a)
g = {"currentProgram": Prog(), "toAddr": lambda x: x, "disassemble": lambda a: True, "createFunction": createFunction,
     "setPlateComment": lambda a, c: calls["plate"].__setitem__(a, c), "setEOLComment": lambda a, c: calls["eol"].__setitem__(a, c), "__name__": "__main__"}
exec(compile(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1], "exec"), g)
print(json.dumps({"names": len(calls["names"]), "eol": len(calls["eol"]), "evil": sorted(calls["names"].values())[0] if calls["names"] else ""}))
`;
    const idaStub = `
import sys, types, json
calls = {"names": {}, "cmts": {}, "funcs": 0}
f = types.ModuleType("ida_funcs"); f.get_func = lambda ea: None
def add_func(ea):
    calls["funcs"] += 1
    return True
f.add_func = add_func
n = types.ModuleType("ida_name"); n.SN_NOWARN = 1; n.SN_FORCE = 2
def set_name(ea, name, flags):
    calls["names"][ea] = name
    return True
n.set_name = set_name
i = types.ModuleType("idc"); i.set_func_cmt = lambda ea, c, r: True
i.set_cmt = lambda ea, c, r: calls["cmts"].__setitem__(ea, c)
sys.modules.update({"ida_funcs": f, "ida_name": n, "idc": i})
exec(compile(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1], "exec"), {"__name__": "__main__"})
print(json.dumps({"names": len(calls["names"]), "cmts": len(calls["cmts"]), "funcs": calls["funcs"]}))
`;
    for (const [fmt, stub] of [['ghidra', ghidraStub], ['ida', idaStub]]) {
      const script = join(dir, `export${EXT[fmt]}`);
      const harness = join(dir, `${fmt}-harness.py`);
      writeFileSync(script, exportAs(r, fmt));
      writeFileSync(harness, stub);
      const p = spawnSync(python, ['-I', harness, script], { encoding: 'utf8', timeout: 60_000 });
      assert.equal(p.status, 0, `${fmt}: ${p.stderr}`);
      const out = JSON.parse(p.stdout.trim().split('\n').pop());
      assert.equal(out.names, r.functions.length, `${fmt}: adlandırılan fonksiyon`);
      if (fmt === 'ghidra') { assert.equal(out.eol, 7); assert.ok(out.evil.length > 0); } else assert.equal(out.cmts, 7);
      ran++;
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
console.log(`exports: Ghidra / IDA / r2 / JSON / listeleme; enjeksiyon denemesi etkisiz${ran ? `; ${ran} betik Python'da sahte API ile çalıştırıldı` : ' (Python yok: çalıştırma atlandı)'}`);
