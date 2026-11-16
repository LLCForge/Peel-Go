#!/usr/bin/env node
// Test ikililerini gerçek Go araç zinciriyle derler: node scripts/make-fixtures.js
//
// Zararsız üç program, geçici bir dizinde yazılır ve derlenir; çıktılar gzip'lenip test/fixtures/ altına kopyalanır:
//   basic       os/exec + yerel bir bağımlılık (replace) içeren küçük bir "güncelleme denetleyici"; 8 hedef
//               (linux amd64/arm64/386, windows amd64/386, darwin amd64/arm64; biri sembol tablolu)
//   garblelike  garble'ın -literals şablonlarıyla (simple, swap, split, shuffle, seed) elle yazılmış dizgeler,
//               karma görünümlü paket/fonksiyon adları, boşaltılmış modinfo (-X runtime.modinfo=); linux + windows amd64
//   gobflike    gobfuscate tarzı rastgele küçük harfli paket adları ve maske-xor dizgeleri; linux amd64
// garble kuruluysa (PATH'te, bu betik hiçbir aracı kurmaz) ayrıca gerçek bir garble ikilisi derlenir.
//
// Kişisel bilgi sızmasın diye: -trimpath, -buildvcs=false, -buildid=, CGO kapalı, GOFLAGS/GOPATH etkisiz.
// Derleme sonrası her ikili kullanıcı dizini / ana bilgisayar adı kalıplarına karşı taranır; bulunursa betik durur.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, readdirSync, unlinkSync } from 'node:fs';
import { tmpdir, userInfo, hostname } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';

const OUT = new URL('../test/fixtures/', import.meta.url);
const go = spawnSync('go', ['version'], { encoding: 'utf8' });
if (go.status !== 0) {
  console.error('Go bulunamadı: gerçek fixture\'lar için Go kurulu olmalı (sentetik fixture\'lar testte üretilir).');
  process.exit(1);
}
const goVersion = go.stdout.trim().split(' ')[2];

// ── belirlenimci rastgelelik (aynı girdi → aynı kaynak) ──
let seed = 0x5eed1234;
const rnd = () => { seed ^= seed << 13; seed >>>= 0; seed ^= seed >>> 17; seed ^= seed << 5; seed >>>= 0; return seed; };
const rb = () => rnd() & 0xff;
const EXT = [];
const goBytes =(arr) => `"${arr.map((b) => `\\x${b.toString(16).padStart(2, '0')}`).join('')}"`;
const enc = (s) => [...Buffer.from(s, 'utf8')];

// ── garble -literals şablonları (garble/internal/literals obfuscator'larının ürettiği biçim) ──
const T = {
  simple(s, op = 'xor') {
    const p = enc(s);
    const key = p.map(rb);
    const data = p.map((b, i) => (op === 'xor' ? b ^ key[i] : op === 'add' ? (b - key[i]) & 0xff : (b + key[i]) & 0xff));
    const sym = { xor: '^', add: '+', sub: '-' }[op];
    return `func() string {
	key := []byte(${goBytes(key)})
	data := []byte(${goBytes(data)})
	for i, b := range key {
		data[i] = data[i] ${sym} b
	}
	return string(data)
}()`;
  },
  swap(s) {
    const data = enc(s);
    const n = data.length;
    const pairs = Math.max(1, Math.floor(n / 2) + 1);
    const pos = [];
    for (let i = 0; i < pairs * 2; i++) pos.push(rnd() % n);
    const shift = rb();
    // her takas kendi tersidir: kodlama, çözme adımlarının ters sırayla uygulanmasıdır
    for (let i = pos.length - 2; i >= 0; i -= 2) {
      const k = (i + (pos[i] ^ pos[i + 1]) + shift) & 0xff;
      const a = data[pos[i]];
      const b = data[pos[i + 1]];
      data[pos[i]] = b ^ k;
      data[pos[i + 1]] = a ^ k;
    }
    return `func() string {
	data := []byte(${goBytes(data)})
	positions := [...]byte{${pos.join(', ')}}
	for i := 0; i < ${pos.length}; i += 2 {
		localKey := byte(i) + byte(positions[i]^positions[i+1]) + ${shift}
		data[positions[i]], data[positions[i+1]] = data[positions[i+1]]^localKey, data[positions[i]]^localKey
	}
	return string(data)
}()`;
  },
  split(s) {
    const p = enc(s);
    const chunks = [];
    for (let i = 0; i < p.length;) { const n = 1 + (rnd() % 4); chunks.push(p.slice(i, i + n)); i += n; }
    const states = [];
    while (states.length < chunks.length + 1) { const v = 1 + (rnd() % 900); if (!states.includes(v)) states.push(v); }
    let key = rnd() % 256;
    const start = key;
    // durum makinesini çalıştır: son anahtar
    for (let c = 0, i = 0; i < chunks.length; c++, i++) key ^= states[i] * c;
    const flat = chunks.flat();
    const encd = flat.map((b, y) => b ^ ((key ^ y) & 0xff));
    let off = 0;
    const cases = chunks.map((ch, i) => {
      const part = encd.slice(off, off + ch.length);
      off += ch.length;
      return `		case ${states[i]}:
			i = ${states[i + 1]}
			data = append(data, ${goBytes(part)}...)`;
    });
    // case sırası karıştırılır (garble da karıştırır)
    for (let i = cases.length - 1; i > 0; i--) { const j = rnd() % (i + 1); [cases[i], cases[j]] = [cases[j], cases[i]]; }
    return `func() string {
	data := make([]byte, 0, ${p.length})
	i := ${states[0]}
	decryptKey := ${start}
	for counter := 0; i != ${states[chunks.length]}; counter++ {
		decryptKey ^= i * counter
		switch i {
${cases.join('\n')}
		}
	}
	for y := range data {
		data[y] = data[y] ^ byte(decryptKey^y)
	}
	return string(data)
}()`;
  },
  // yeni garble sürümleri gibi paket düzeyinde bir "dış anahtar" kullanır: değişken global olduğu için derleyici
  // fullData[a]^fullData[b] ifadesini sabite katlayamaz
  shuffle(s) {
    const p = enc(s);
    const keys = p.map(rb);
    const name = `Kx${EXT.length}Qz7`;
    const g = (BigInt(rnd()) << 32n) | BigInt(rnd());
    const sh = 8 * (rnd() % 8);
    const ext = Number((g >> BigInt(sh)) & 0xffn);
    EXT.push(`var ${name} uint64 = 0x${g.toString(16)}`);
    const vals = [...p.map((b, i) => b ^ keys[i] ^ ext), ...keys];
    const order = vals.map((_, i) => i);
    for (let i = order.length - 1; i > 0; i--) { const j = rnd() % (i + 1); [order[i], order[j]] = [order[j], order[i]]; }
    const full = order.map((i) => vals[i]);
    const at = (orig) => order.indexOf(orig);
    const terms = p.map((_, i) => `fullData[${at(i)}]^fullData[${at(p.length + i)}]^byte(${name}>>${sh})`);
    return `func() string {
	fullData := []byte(${goBytes(full)})
	data := make([]byte, 0, ${p.length})
	data = append(data, ${terms.join(', ')})
	return string(data)
}()`;
  },
  seed(s) {
    const p = enc(s);
    const s0 = rb();
    let sd = s0;
    const e = p.map((b) => { const x = b ^ sd; sd = (sd + x) & 0xff; return x; });
    return `func() string {
	seed := byte(${s0})
	var data []byte
	type decFunc func(byte) decFunc
	var fnc decFunc
	fnc = func(x byte) decFunc {
		data = append(data, x^seed)
		seed += x
		return fnc
	}
	fnc${e.map((x) => `(${x})`).join('')}
	return string(data)
}()`;
  },
  // gobfuscate: maske ile maskelenmiş dizgenin xor'u
  gobf(s) {
    const p = enc(s);
    const mask = p.map(rb);
    const masked = p.map((b, i) => b ^ mask[i]);
    return `func() string {
	mask := []byte(${goBytes(mask)})
	maskedStr := []byte(${goBytes(masked)})
	res := make([]byte, ${p.length})
	for i, m := range mask {
		res[i] = m ^ maskedStr[i]
	}
	return string(res)
}()`;
  },
};

// Gizlenecek dizgeler (zararsız; .test alan adı ve RFC 5737 belge IP'leri). Testler bu değerleri bekler.
const GARBLE_LITERALS = [
  ['simple', 'https://cdn.peel-fixture.test/v2/config.json', 'xor'],
  ['simple', 'update.peel-fixture.test', 'add'],
  ['simple', 'harmless sample string', 'sub'],
  ['swap', '198.51.100.23:8443'],
  ['split', 'peel-fixture: split literal recovered'],
  ['shuffle', 'Software\\PeelFixture\\Settings'],
  ['seed', 'fixture-token-not-a-secret'],
];
const GOBF_LITERALS = ['http://198.51.100.99/status', 'peel gobfuscate-style fixture'];

const PROGRAMS = {
  basic: {
    module: 'example.com/peelfixture',
    files: {
      'go.mod': 'module example.com/peelfixture\n\ngo 1.21\n\nrequire example.com/peelutil v0.1.0\n\nreplace example.com/peelutil => ./peelutil\n',
      'peelutil/go.mod': 'module example.com/peelutil\n\ngo 1.21\n',
      'peelutil/util.go': `package peelutil

import "strings"

// Banner yalnızca bir başlık döndürür.
func Banner(name string) string { return "[" + strings.ToUpper(name) + "]" }
`,
      'main.go': `package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"

	"example.com/peelutil"
)

type Config struct {
	Endpoint string
	Mirror   string
	Retries  int
}

func (c *Config) String() string { return c.Endpoint + " via " + c.Mirror + " x" + strconv.Itoa(c.Retries) }

type Checker interface{ Check() bool }

func (c *Config) Check() bool { return strings.HasPrefix(c.Endpoint, "https://") }

// arayüz çağrısı satır içine alınmasın: itab (*main.Config → main.Checker) ikilide kalır
//go:noinline
func run(ck Checker) bool { return ck.Check() }

func main() {
	c := &Config{Endpoint: "https://cdn.peel-fixture.test/v1/check", Mirror: "198.51.100.7", Retries: 3}
	var ck Checker = c
	_, err := exec.LookPath("peel-fixture-tool-that-does-not-exist")
	os.Stdout.WriteString(peelutil.Banner("peel fixture") + " " + c.String() + " " + strconv.FormatBool(run(ck)) + " " + strconv.FormatBool(err != nil) + "\\n")
}
`,
    },
    targets: [
      ['linux', 'amd64', true], ['linux', 'amd64', false], ['linux', 'arm64', false], ['linux', '386', false],
      ['windows', 'amd64', false], ['windows', '386', false], ['darwin', 'amd64', false], ['darwin', 'arm64', false],
    ],
  },
  garblelike: {
    module: 'Wq8eZtLp',
    ldflags: '-X=runtime.modinfo=',
    files: {
      'go.mod': 'module Wq8eZtLp\n\ngo 1.21\n',
      'kQ8wZr3T/kQ8wZr3T.go': `package kQ8wZr3T

import "os"

type Hx3kL2pm struct{ Rv7Qz int }

func (h *Hx3kL2pm) Wn9qXb() int { return h.Rv7Qz * 2 }

func Fx3qLm9P(Zp2 string) { os.Stdout.WriteString(Zp2 + "\\n") }

func Yt5Kc0Vd() []string {
	return []string{
${GARBLE_LITERALS.map(([fam, s, op]) => `\t\t${T[fam](s, op).split('\n').join('\n\t\t')},`).join('\n')}
	}
}

${EXT.join('\n')}
`,
      'main.go': `package main

import "Wq8eZtLp/kQ8wZr3T"

func main() {
	h := &kQ8wZr3T.Hx3kL2pm{Rv7Qz: 21}
	for _, s := range kQ8wZr3T.Yt5Kc0Vd() {
		kQ8wZr3T.Fx3qLm9P(s)
	}
	if h.Wn9qXb() != 42 {
		kQ8wZr3T.Fx3qLm9P("?")
	}
}
`,
    },
    targets: [['linux', 'amd64', false], ['windows', 'amd64', false]],
  },
  gobflike: {
    module: 'kzqvtrwxbnmplhgd',
    files: {
      'go.mod': 'module kzqvtrwxbnmplhgd\n\ngo 1.21\n',
      'jxwvqrlsugzbkhfn/jxwvqrlsugzbkhfn.go': `package jxwvqrlsugzbkhfn

import "os"

func Vqzrtkxwlpmnbhgf(s string) { os.Stdout.WriteString(s + "\\n") }

func Wbkqzrtxplmnvcdf() (string, string) {
	return ${T.gobf(GOBF_LITERALS[0]).split('\n').join('\n\t')}, ${T.gobf(GOBF_LITERALS[1]).split('\n').join('\n\t')}
}
`,
      'main.go': `package main

import "kzqvtrwxbnmplhgd/jxwvqrlsugzbkhfn"

func main() {
	a, b := jxwvqrlsugzbkhfn.Wbkqzrtxplmnvcdf()
	jxwvqrlsugzbkhfn.Vqzrtkxwlpmnbhgf(a)
	jxwvqrlsugzbkhfn.Vqzrtkxwlpmnbhgf(b)
}
`,
    },
    targets: [['linux', 'amd64', false]],
  },
};

// derlenen ikilide olmaması gereken kalıplar (kullanıcı dizinleri, geçici dizin, ana bilgisayar)
function personal(buf, work) {
  const text = buf.toString('latin1');
  const hits = [];
  for (const re of [/[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/]/i, /\/(?:home|Users)\/[A-Za-z0-9._-]+\//, /AppData[\\/]/i]) {
    const m = re.exec(text);
    if (m) hits.push(m[0]);
  }
  for (const s of [work, userInfo().username, hostname()]) if (s && s.length >= 4 && text.includes(s)) hits.push('<yerel ad>');
  return hits;
}

function build(name, prog, work) {
  const dir = join(work, name);
  for (const [f, body] of Object.entries(prog.files)) {
    const p = join(dir, f);
    mkdirSync(join(p, '..'), { recursive: true });
    writeFileSync(p, body);
  }
  const outs = [];
  for (const [goos, goarch, symbols] of prog.targets) {
    const file = `${name}.${goos}-${goarch}${symbols ? '-syms' : ''}`;
    const out = join(work, file);
    const ld = [symbols ? '-w' : '-s -w', '-buildid=', prog.ldflags ?? ''].filter(Boolean).join(' ');
    execFileSync('go', ['build', '-trimpath', '-buildvcs=false', `-ldflags=${ld}`, '-o', out, '.'], {
      cwd: dir,
      stdio: ['ignore', 'inherit', 'inherit'],
      env: { ...process.env, GOOS: goos, GOARCH: goarch, CGO_ENABLED: '0', GOFLAGS: '', GOTOOLCHAIN: 'local', GOWORK: 'off', GO386: 'sse2', GOAMD64: 'v1', GOARM64: 'v8.0' },
    });
    outs.push({ file, out, goos, goarch, symbols, program: name, tool: 'go' });
  }
  return outs;
}

const work = mkdtempSync(join(tmpdir(), 'peel-go-fx-'));
try {
  const all = [];
  for (const [name, prog] of Object.entries(PROGRAMS)) all.push(...build(name, prog, work));
  const garble = spawnSync('garble', ['version'], { encoding: 'utf8' });
  if (garble.status === 0) {
    const dir = join(work, 'garblelike');
    const out = join(work, 'garble.linux-amd64');
    execFileSync('garble', ['-literals', '-tiny', '-seed=cGVlbC1maXh0dXJl', 'build', '-trimpath', '-o', out, '.'], {
      cwd: dir, stdio: 'inherit', env: { ...process.env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0', GOFLAGS: '-buildvcs=false' },
    });
    all.push({ file: 'garble.linux-amd64', out, goos: 'linux', goarch: 'amd64', symbols: false, program: 'garble', tool: 'garble' });
  } else console.log('garble kurulu değil: gerçek garble fixture\'ı atlandı (garble benzeri fixture\'lar derlendi)');

  mkdirSync(OUT, { recursive: true });
  for (const f of readdirSync(OUT)) if (f.endsWith('.gz') || f === 'manifest.json') unlinkSync(new URL(f, OUT));
  const manifest = { go: goVersion, garble: garble.status === 0, fixtures: [] };
  let total = 0;
  for (const x of all) {
    const buf = readFileSync(x.out);
    const bad = personal(buf, work);
    if (bad.length) throw new Error(`${x.file}: kişisel yol/ad kalıbı bulundu (${bad.join(', ')})`);
    const gz = gzipSync(buf, { level: 9 });
    writeFileSync(new URL(`${x.file}.gz`, OUT), gz);
    total += gz.length;
    manifest.fixtures.push({ file: `${x.file}.gz`, program: x.program, tool: x.tool, goos: x.goos, goarch: x.goarch, symbols: x.symbols, size: buf.length, sha256: createHash('sha256').update(buf).digest('hex') });
    console.log(`${x.file}: ${buf.length} B → ${gz.length} B gzip`);
  }
  manifest.literals = { garble: GARBLE_LITERALS.map(([family, value]) => ({ family, value })), gobf: GOBF_LITERALS };
  writeFileSync(new URL('manifest.json', OUT), `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`toplam ${(total / 1024 / 1024).toFixed(2)} MB (${all.length} ikili, ${goVersion})`);
  if (total > 15 * 1024 * 1024) throw new Error('fixture toplamı 15 MB sınırını aşıyor');
} finally {
  rmSync(work, { recursive: true, force: true });
}
