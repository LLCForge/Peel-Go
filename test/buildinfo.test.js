// runtime.buildinfo: satır içi (1.18+) ve işaretçili eski biçim (LE/BE, 32/64), modinfo ayrıştırma (dep, replace,
// build ayarları, tırnaklı değerler), boşaltılmış modinfo ve gerçek fixture'lar.
import assert from 'node:assert/strict';
import { openImage } from '../src/core/container.js';
import { readBuildInfo, parseModinfo, goVersion } from '../src/core/buildinfo.js';
import { peel } from '../src/index.js';
import { fixture, synthetic } from './helpers.js';

const MOD = [
  'path\texample.com/tool/cmd/tool',
  'mod\texample.com/tool\tv1.4.2\th1:abcdefabcdefabcdefabcdefabcdefabcdefabcdefa=',
  'dep\tgolang.org/x/sys\tv0.20.0\th1:0123456789012345678901234567890123456789012=',
  'dep\texample.com/fork\tv1.0.0',
  '=>\t../fork\t(devel)\t',
  'build\t-buildmode=exe',
  'build\t-ldflags="-s -w -X main.version=1.4.2"',
  'build\tCGO_ENABLED=1',
  'build\tGOOS=windows',
  'build\tGOARCH=amd64',
  'build\tvcs=git',
  'build\tvcs.revision=0123456789abcdef0123456789abcdef01234567',
  'build\tvcs.time=2026-01-02T03:04:05Z',
  'build\tvcs.modified=false',
  '',
].join('\n');

const m = parseModinfo(MOD);
assert.equal(m.path, 'example.com/tool/cmd/tool');
assert.deepEqual(m.main, { path: 'example.com/tool', version: 'v1.4.2', sum: 'h1:abcdefabcdefabcdefabcdefabcdefabcdefabcdefa=' });
assert.equal(m.deps.length, 2);
assert.deepEqual(m.deps[1].replace, { path: '../fork', version: '(devel)', sum: '' });
assert.equal(m.settings['-ldflags'], '-s -w -X main.version=1.4.2');
assert.equal(m.settings['vcs.revision'], '0123456789abcdef0123456789abcdef01234567');
assert.deepEqual(goVersion('go1.21.3'), [1, 21, 3]);
assert.deepEqual(goVersion('go1.22rc1'), [1, 22, 0]);
assert.equal(goVersion('devel'), null);

// sentetik: satır içi ve işaretçili, 32/64 bit, LE/BE
for (const [inline, bits, le, format] of [[true, 64, true, 'elf'], [true, 32, true, 'pe'], [false, 64, true, 'elf'], [false, 32, true, 'elf'], [false, 64, false, 'elf'], [true, 64, true, 'macho']]) {
  const b = synthetic({ format, bits, le, arch: le ? 'amd64' : 'ppc64', literal: null, buildinfo: { version: 'go1.16.15', modinfo: MOD, inline } });
  const bi = readBuildInfo(openImage(b.bytes));
  const tag = `${inline ? 'satır içi' : 'işaretçili'} ${format}${bits} ${le ? 'LE' : 'BE'}`;
  assert.equal(bi?.version, 'go1.16.15', tag);
  assert.equal(bi.inline, inline, tag);
  assert.equal(bi.main.path, 'example.com/tool', tag);
  assert.equal(bi.settings.GOOS, 'windows', tag);
}

// boşaltılmış modinfo (garble benzeri): sürüm var, modül yok → rapor izi
const stripped = await peel(synthetic({ buildinfo: { version: 'go1.21.4', modinfo: '' } }).bytes, { lang: 'en' });
assert.equal(stripped.go.version, 'go1.21.4');
assert.equal(stripped.buildinfo.modinfo, false);
// buildinfo yok: sürüm runtime.buildVersion dizgesinden
const nobi = await peel(synthetic({ buildinfo: null, rodata: new TextEncoder().encode('\0go1.12.17\0') }).bytes, { lang: 'en' });
assert.equal(nobi.go.version, 'go1.12.17');
assert.equal(nobi.go.versionSource, 'string');

// gerçek fixture: replace'li yerel bağımlılık ve -trimpath ayarları
const real = readBuildInfo(openImage(fixture('basic.windows-386.gz')));
assert.equal(real.version.startsWith('go1.'), true);
assert.equal(real.main.path, 'example.com/peelfixture');
assert.equal(real.deps[0].path, 'example.com/peelutil');
assert.equal(real.deps[0].replace.path, './peelutil');
assert.equal(real.settings.GOARCH, '386');
assert.equal(real.settings['-trimpath'], 'true');
const gl = readBuildInfo(openImage(fixture('garblelike.linux-amd64.gz')));
assert.equal(gl.modinfo, '');
console.log('buildinfo: modinfo, satır içi + işaretçili (LE/BE, 32/64), boşaltılmış, yalnızca sürüm dizgesi, gerçek');
