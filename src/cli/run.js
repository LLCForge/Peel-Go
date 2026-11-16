// peel-go komut satırı: tarayıcıdakiyle aynı motor. Soyma işi sert zaman sınırlı bir worker_threads iş parçacığında
// çalışır; incelenen ikili hiçbir zaman çalıştırılmaz.
import { readFile, writeFile, mkdir, readdir, stat, open } from 'node:fs/promises';
import { dirname, join, relative, resolve, basename } from 'node:path';
import { peel, passes, exportAs, FORMATS, EXT } from '../index.js';
import { createNodeSandbox } from '../sandbox/node-host.js';
import { reportText } from '../report/text.js';
import { detectFormat } from '../core/container.js';
import { MAX_INPUT } from '../core/pipeline.js';
import { parseArgs, UsageError } from './args.js';

export const EXIT = { OK: 0, ERROR: 1, USAGE: 2, THREAT: 4 };
const LEVELS = ['none', 'low', 'medium', 'high', 'critical'];
const MAX_DIR_FILES = 5000;

const SPEC = {
  out: { alias: 'o', type: 'string' },
  format: { alias: 'f', type: 'string' },
  listing: { type: 'string' },
  ghidra: { type: 'string' },
  ida: { type: 'string' },
  r2: { type: 'string' },
  'out-dir': { alias: 'd', type: 'string' },
  report: { alias: 'r', type: 'string' },
  json: { type: 'bool' },
  lang: { type: 'string' },
  only: { type: 'list' },
  'fail-on': { type: 'string' },
  timeout: { type: 'number' },
  quiet: { alias: 'q', type: 'bool' },
  help: { alias: 'h', type: 'bool' },
};

const optional = () => passes().filter((p) => !p.required).map((p) => p.id);
const HELP = {
  tr: () => `peel-go <dosya|dizin|-> [seçenekler]

Derlenmiş bir Go ikilisinin (ELF, PE, Mach-O; amd64/arm64/386) gizlemesini soyar: pclntab'tan fonksiyon adları,
kaynak dosyaları ve satırlar, runtime.buildinfo'dan Go sürümü ve modüller, moduledata'dan tür adları; garble,
gobfuscate, UPX ve silinmiş semboller tespit edilir, garble -literals dizgeleri amd64'te öykünülerek çözülür.
İkili hiçbir zaman çalıştırılmaz.

  -o, --out <dosya>        çıktıyı yaz (biçim uzantıdan: .txt listeleme | .py Ghidra (ya da -f ida) | .r2 | .json)
  -f, --format <biçim>     stdout ve -d için biçim: ${FORMATS.join(' | ')} (varsayılan listing)
      --listing <dosya>    listelemeyi de yaz
      --ghidra <dosya>     Ghidra Python betiğini de yaz
      --ida <dosya>        IDAPython betiğini de yaz
      --r2 <dosya>         radare2/rizin komut dosyasını da yaz
  -d, --out-dir <dizin>    çıktıları dizine yaz (<ad><uzantı>; dizin girdisinde yapı korunur)
  -r, --report <hedef>     rapor: json | text (stdout'a, çıktı yazılmaz) ya da dosya yolu (.txt ise metin, değilse JSON;
                           dizin girdisinde JSON dizi)
      --json               --report json ile aynı
      --only <geçiş,...>   yalnızca bu isteğe bağlı geçişler (${optional().join(', ')})
      --lang tr|en         rapor dili (varsayılan tr)
      --fail-on <düzey>    tehdit düzeyi bu eşiğe ulaşırsa çıkış kodu 4: low | medium | high | critical
      --timeout <sn>       dosya başına süre sınırı (varsayılan 90)
  -q, --quiet              ilerleme ve özet yazma
  -h, --help               bu yardım

Çıkış kodları: 0 tamam, 1 hata, 2 kullanım hatası, 4 --fail-on eşiğine ulaşıldı (hatadan önceliklidir).
UPX ile paketlenmiş ikililer tanınır ama açılmaz (önce upx -d).`,
  en: () => `peel-go <file|dir|-> [options]

Peels the obfuscation off a compiled Go binary (ELF, PE, Mach-O; amd64/arm64/386): function names, source files and
lines from pclntab, Go version and modules from runtime.buildinfo, type names from moduledata; detects garble,
gobfuscate, UPX and stripped symbols, and decodes garble -literals strings on amd64 by emulation.
The binary is never executed.

  -o, --out <file>         write the output (format from the extension: .txt listing | .py Ghidra (or -f ida) | .r2 | .json)
  -f, --format <fmt>       format for stdout and -d: ${FORMATS.join(' | ')} (default listing)
      --listing <file>     also write the listing
      --ghidra <file>      also write the Ghidra Python script
      --ida <file>         also write the IDAPython script
      --r2 <file>          also write the radare2/rizin command file
  -d, --out-dir <dir>      write outputs to a directory (<name><ext>; directory input keeps its structure)
  -r, --report <target>    report: json | text (to stdout, no output) or a file path (.txt gives text, anything else JSON;
                           a JSON array for directory input)
      --json               same as --report json
      --only <pass,...>    run only these optional passes (${optional().join(', ')})
      --lang tr|en         report language (default tr)
      --fail-on <level>    exit with code 4 when the threat level reaches: low | medium | high | critical
      --timeout <sec>      time limit per file (default 90)
  -q, --quiet              no progress or summary output
  -h, --help               this help

Exit codes: 0 ok, 1 error, 2 usage error, 4 --fail-on threshold reached (takes precedence over errors).
UPX-packed binaries are identified but not unpacked (run upx -d first).`,
};

async function readBytes(path) {
  if (path === '-') {
    const chunks = [];
    let n = 0;
    for await (const c of process.stdin) {
      n += c.length;
      if (n > MAX_INPUT) throw new Error('Girdi çok büyük');
      chunks.push(c);
    }
    return new Uint8Array(Buffer.concat(chunks));
  }
  const s = await stat(path);
  if (!s.isFile()) throw new Error(`Dosya değil: ${path}`);
  if (s.size > MAX_INPUT) throw new Error(`Dosya çok büyük: ${path}`);
  return new Uint8Array(await readFile(path));
}

/** Dosyanın ilk baytları ELF/PE/Mach-O mu */
async function isBinary(path) {
  const fh = await open(path, 'r');
  try {
    const buf = new Uint8Array(4096);
    const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
    return detectFormat(buf.subarray(0, bytesRead)) != null;
  } finally {
    await fh.close();
  }
}

/** Dizindeki ikililer (özyinelemeli, sembolik bağlar izlenmez), sıralı */
async function listInputs(root) {
  const out = [];
  const walkDir = async (dir) => {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (out.length >= MAX_DIR_FILES) return;
      const p = join(dir, e.name);
      if (e.isDirectory()) { if (e.name !== 'node_modules' && !e.name.startsWith('.')) await walkDir(p); } else if (e.isFile() && await isBinary(p).catch(() => false)) out.push(p);
    }
  };
  await walkDir(root);
  return out;
}

async function writeOut(path, data) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, data);
}

const formatOf = (path, fmt) => (/\.r2$/i.test(path) ? 'r2' : /\.json$/i.test(path) ? 'json' : /\.py$/i.test(path) ? (fmt === 'ida' ? 'ida' : 'ghidra') : 'listing');
const levelOf = (entry) => entry.report?.threat?.level ?? 'none';
const textOf = (entries, isDir, lang) => entries.map((e) => `${isDir ? `== ${e.file} ==\n` : ''}${e.error ? `${lang === 'en' ? 'Error' : 'Hata'}: ${e.error}\n` : ''}${e.report ? reportText(e.report, lang) : ''}`).join('\n');

export async function runCli(argv) {
  const { opts, positional } = parseArgs(argv, SPEC);
  const lang = opts.lang === undefined ? 'tr' : opts.lang;
  if (lang !== 'tr' && lang !== 'en') throw new UsageError(`--lang tr ya da en olmalı: ${lang}`);
  if (opts.help) { console.log(HELP[lang]()); return EXIT.OK; }
  if (positional.length !== 1) throw new UsageError(`${HELP[lang]()}\n\nTek bir girdi gerekli (dosya, dizin ya da -).`);
  if (opts['fail-on'] !== undefined && !LEVELS.slice(1).includes(opts['fail-on'])) throw new UsageError('--fail-on şunlardan biri olmalı: low, medium, high, critical');
  const format = opts.format ?? 'listing';
  if (!FORMATS.includes(format)) throw new UsageError(`--format şunlardan biri olmalı: ${FORMATS.join(', ')}`);
  if (opts.timeout !== undefined && !(opts.timeout > 0 && opts.timeout <= 3600)) throw new UsageError('--timeout 1 ile 3600 saniye arasında olmalı');
  const ids = optional();
  const only = opts.only.flatMap((x) => x.split(',')).map((x) => x.trim()).filter(Boolean);
  const unknown = only.filter((x) => !ids.includes(x));
  if (unknown.length) throw new UsageError(`Bilinmeyen geçiş: ${unknown.join(', ')} (geçerli: ${ids.join(', ')})`);
  const stdoutReport = opts.json ? 'json' : ['json', 'text'].includes(opts.report) ? opts.report : null;
  const reportFile = opts.report !== undefined && !['json', 'text'].includes(opts.report) ? opts.report : null;

  const target = positional[0];
  const isDir = target !== '-' && (await stat(target).catch(() => null))?.isDirectory();
  if (isDir && (opts.out || opts.listing || opts.ghidra || opts.ida || opts.r2)) throw new UsageError('Dizin girdisinde -o/--listing/--ghidra/--ida/--r2 yerine -d kullanın');
  const log = (m) => { if (!opts.quiet) process.stderr.write(`${m}\n`); };
  const options = { lang, deadlineMs: Math.round((opts.timeout ?? 90) * 1000), ...(only.length ? { only } : {}) };

  const sandbox = createNodeSandbox();
  const entries = [];
  try {
    const files = isDir ? await listInputs(target) : [target];
    if (isDir && !files.length) log(lang === 'en' ? 'No ELF, PE or Mach-O files found.' : 'ELF, PE ya da Mach-O dosyası bulunamadı.');
    for (const file of files) {
      const name = file === '-' ? '-' : isDir ? relative(target, file).split('\\').join('/') : file;
      const entry = { file: name, ok: false };
      entries.push(entry);
      let bytes;
      try {
        bytes = await readBytes(file);
      } catch (e) {
        entry.error = e.message;
        log(`${name}: ${e.message}`);
        continue;
      }
      const r = await peel(bytes, { sandbox, name: file === '-' ? 'stdin' : basename(file), ...options });
      Object.assign(entry, { ok: !r.error, error: r.error, verified: Boolean(r.verified), ms: r.ms ?? 0, stats: r.stats ?? {}, report: r.report ?? null });
      if (!r.error) {
        if (opts['out-dir']) {
          const rel = isDir ? relative(target, file) : file === '-' ? 'stdin' : basename(file);
          const dest = resolve(opts['out-dir'], `${rel}${EXT[format]}`);
          if (relative(resolve(opts['out-dir']), dest).startsWith('..')) throw new Error(`Çıktı dizini dışına yazma: ${rel}`);
          await writeOut(dest, exportAs(r, format));
        }
        if (opts.out) await writeOut(opts.out, exportAs(r, formatOf(opts.out, format)));
        for (const k of ['listing', 'ghidra', 'ida', 'r2']) if (opts[k]) await writeOut(opts[k], exportAs(r, k));
        if (!isDir && !opts.out && !opts['out-dir'] && !stdoutReport) process.stdout.write(exportAs(r, format));
      }
      if (r.report) {
        const th = r.report.threat;
        log(`${isDir ? `${name}: ` : ''}[${th.level} ${th.score}/100]${r.error ? ` ${r.error};` : ''} ${r.report.summary}`);
      } else log(`${name}: ${r.error}`);
    }
  } finally {
    sandbox.close();
  }

  const payload = isDir ? entries : entries[0];
  const json = `${JSON.stringify(payload, null, 2)}\n`;
  if (reportFile) await writeOut(reportFile, /\.txt$/i.test(reportFile) ? textOf(entries, isDir, lang) : json);
  if (stdoutReport === 'json') process.stdout.write(json);
  else if (stdoutReport === 'text') process.stdout.write(textOf(entries, isDir, lang));

  const failOn = opts['fail-on'];
  if (failOn && entries.some((e) => LEVELS.indexOf(levelOf(e)) >= LEVELS.indexOf(failOn))) return EXIT.THREAT;
  return entries.some((e) => !e.ok) ? EXIT.ERROR : EXIT.OK;
}
