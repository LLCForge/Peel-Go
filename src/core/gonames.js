// Go sembol adı yardımcıları: paket yolu, standart kitaplık ayrımı, karma (garble) ve rastgele küçük harf (gobfuscate)
// görünümlü tanımlayıcı puanı.

// Go standart kitaplığının üst düzey yolları (cmd/, test dizinleri hariç) ve derleyicinin ürettiği önekler
export const STD_ROOTS = new Set(['archive', 'arena', 'bufio', 'builtin', 'bytes', 'cmp', 'compress', 'container', 'context', 'crypto', 'database',
  'debug', 'embed', 'encoding', 'errors', 'expvar', 'flag', 'fmt', 'go', 'hash', 'html', 'image', 'index', 'internal', 'io', 'iter', 'log', 'maps',
  'math', 'mime', 'net', 'os', 'path', 'plugin', 'reflect', 'regexp', 'runtime', 'simd', 'slices', 'sort', 'strconv', 'strings', 'structs', 'sync',
  'syscall', 'testing', 'text', 'time', 'unicode', 'unique', 'unsafe', 'vendor', 'weak', 'type:', 'go:', 'gclocals', 'type']);

/** "github.com/a/b.(*T).M" → "github.com/a/b"; "main.main" → "main"; tanınmazsa "" */
export function packageOf(name) {
  let s = String(name);
  const br = s.indexOf('[');
  if (br > 0) s = s.slice(0, br);
  if (s.startsWith('type:') || s.startsWith('go:')) return s.slice(0, s.indexOf(':') + 1);
  const slash = s.lastIndexOf('/');
  const tail = s.slice(slash + 1);
  // gopkg.in/yaml.v3 gibi sürüm sonekli son bölüm
  const ver = /^[\w-]+\.v\d+(?=\.)/.exec(tail);
  const dot = ver ? ver[0].length : tail.indexOf('.');
  if (dot < 0) return slash >= 0 ? s : '';
  return s.slice(0, slash + 1 + dot);
}

export const rootOf = (pkg) => {
  const i = pkg.indexOf('/');
  return i < 0 ? pkg : pkg.slice(0, i);
};

/** Standart kitaplık (ya da derleyici/çalışma zamanı üretimi) mi? */
export function isStdPackage(pkg) {
  if (!pkg) return true;
  const root = rootOf(pkg);
  // bağlayıcı/derleyici yardımcıları (__x86.get_pc_thunk.ax, _rt0_amd64_linux)
  if (root.startsWith('_')) return true;
  return STD_ROOTS.has(root) && !root.includes('.');
}
export const isStdFunc = (name) => isStdPackage(packageOf(name));

const VOWEL = /[aeiouAEIOU]/g;

/** Tanımlayıcı parçasının "karma gibi" görünme puanı (0-1). Gerçek adlar sözcüklerden oluşur. */
export function hashScore(raw) {
  if (!/^[A-Za-z0-9_]{5,24}$/.test(raw)) return 0;
  // snake_case sözcükleri birleşir (get_pc_thunk sözcük, Zx3_kP9q karma kalır)
  const tok = raw.replace(/_/g, '');
  if (tok.length < 5) return 0;
  const segs = tok.match(/[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+|_/g) ?? [];
  const avg = tok.length / Math.max(1, segs.length);
  const letters = tok.replace(/[^A-Za-z]/g, '');
  const vowels = (letters.match(VOWEL) ?? []).length / Math.max(1, letters.length);
  const upper = (tok.match(/[A-Z]/g) ?? []).length;
  const lower = (tok.match(/[a-z]/g) ?? []).length;
  const digits = (tok.match(/\d/g) ?? []).length;
  let s = 0;
  if (segs.length >= 3 && avg < 2.6) s += 0.5;
  if (upper && lower && upper / (upper + lower) > 0.3) s += 0.2;
  if (vowels < 0.25 && letters.length >= 5) s += 0.25;
  if (digits && letters.length && !/^\D+\d+$/.test(tok)) s += 0.15;
  if (/[A-Z]{2,}/.test(tok) && /[a-z][A-Z][a-z]/.test(tok) && avg < 3) s += 0.1;
  return Math.min(1, s);
}

/** gobfuscate tarzı: yalnızca küçük harf/rakam, uzun, sözcük gibi olmayan */
export function randomLowerScore(tok) {
  if (!/^[a-z0-9]{10,64}$/.test(tok)) return 0;
  const letters = tok.replace(/\d/g, '');
  const vowels = (letters.match(VOWEL) ?? []).length / Math.max(1, letters.length);
  // sesli harf oranı İngilizce sözcüklerde ~%40, rastgele küçük harfte ~%19 (onaltılıkta a/e ile ~%30, ama rakam çok)
  // iki işaret gerekir (uzun bileşik sözcükler, ör. netpollblockcommit, tek başına yetmez); onaltılık karma tek başına yeter
  let s = 0;
  if (vowels < 0.22) s += 0.35;
  if (/[bcdfghjklmnpqrstvwxz]{5,}/.test(letters)) s += 0.3;
  if (/\d/.test(tok) && /[a-f]/.test(tok) && /^[0-9a-f]+$/.test(tok)) s += 0.5;
  return Math.min(1, s);
}

/** Bir sembol adının parçaları: paket yolu bölümleri ve tanımlayıcılar */
export function tokens(name) {
  return String(name).split(/[./()*[\]{},;: ]+/).filter((x) => x && x !== 'func1' && !/^func\d+$/.test(x) && !/^gowrap\d+$/.test(x));
}
