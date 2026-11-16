// Tehdit analizi (statik): ikiliye bağlanmış fonksiyonlar (Go bağlayıcısı kullanılmayan kodu atar; bir fonksiyonun
// varlığı onun çağrılabildiğini gösterir), dizge sabitleri + çözülen gizli dizgeler, IOC'ler ve paketleme.
// Hiçbir şey çalıştırılmaz. Şüpheli dizgeler kaynakta parçalı yazılır (antivirüs imzalarına takılmasın).
import { pick, rx, snippet, t } from './text.js';

export const CLASSES = {
  network: t('Ağ erişimi', 'Network access'),
  'command-exec': t('Komut / süreç çalıştırma', 'Command / process execution'),
  injection: t('Bellek enjeksiyonu / kabuk kodu yükleme', 'Memory injection / shellcode loading'),
  persistence: t('Kalıcılık (otomatik başlatma)', 'Persistence (autostart)'),
  'anti-analysis': t('Analiz karşıtı (hata ayıklayıcı denetimi)', 'Anti-analysis (debugger checks)'),
  'credential-access': t('Kimlik bilgisi / tarayıcı verisi erişimi', 'Credential / browser data access'),
  exfiltration: t('Veri sızdırma (Discord/Telegram)', 'Data exfiltration (Discord/Telegram)'),
  'dynamic-code': t('Dinamik kod yükleme (plugin / DLL)', 'Dynamic code loading (plugin / DLL)'),
  packed: t('Paketlenmiş yürütülebilir dosya', 'Packed executable'),
};

// fonksiyon adı kalıpları → yetenek grubu
const FN = {
  network: /^(?:net\.(?:Dial|DialTimeout|Listen|ListenPacket|\(\*Dialer\)\.DialContext|ResolveTCPAddr)$|net\/http\.(?:\(\*Client\)\.Do|Get|Post|PostForm|\(\*Transport\)\.roundTrip|ListenAndServe|\(\*Server\)\.Serve)$|crypto\/tls\.(?:Dial|DialWithDialer|\(\*Conn\)\.Handshake)$|net\/smtp\.SendMail$)/,
  commands: /^(?:os\/exec\.\(\*Cmd\)\.(?:Start|Run|Output|CombinedOutput)$|os\.StartProcess$|syscall\.(?:StartProcess|ForkExec|Exec)$|golang\.org\/x\/sys\/windows\.CreateProcess$)/,
  files: /^(?:os\.(?:OpenFile|WriteFile|Remove|RemoveAll|Rename|Chmod|ReadDir)$|path\/filepath\.(?:Walk|WalkDir)$|io\/ioutil\.WriteFile$)/,
  other: /^(?:golang\.org\/x\/sys\/windows\.(?:\(\*LazyProc\)\.Call|LoadLibrary|LoadLibraryEx|CreateRemoteThread|VirtualAllocEx|WriteProcessMemory)|plugin\.Open|os\/user\.Current|os\/signal\.Notify)$/,
};
// Go'nun Windows çalışma zamanı VirtualAlloc, CreateThread ve Get/SetThreadContext'i kendisi kullanır: listede yoklar
const INJECT = rx(['\\b(?:Virtual', 'AllocEx|WriteProcess', 'Memory|CreateRemote', 'Thread(?:Ex)?|NtUnmap', 'ViewOfSection|QueueUser', 'APC|RtlCreate', 'UserThread|NtCreate', 'ThreadEx)\\b']);
const PERSIST = rx(['(?:\\\\CurrentVersion\\\\Run(?:Once)?\\b|/etc/cron|crontab\\s+-|\\.config/autostart|systemctl\\s+enable|/Library/Launch', '(?:Agents|Daemons)|schtasks(?:\\.exe)?\\s+/create)'], 'i');
const ANTI = rx(['\\b(?:IsDebugger', 'Present|CheckRemote', 'DebuggerPresent|NtQuery', 'InformationProcess|TracerPid|PTRACE_TRACEME)\\b']);
const CREDS = rx(['(?:Login Data|Local State|Cookies\\b|wallet\\.dat|\\\\Google\\\\Chrome\\\\User Data|\\\\Mozilla\\\\Firefox\\\\Profiles|\\.ssh/id_', '(?:rsa|ed25519)|keychain-db)'], 'i');
const HOOK = rx(['discord(?:app)?\\.com/api/(?:v\\d+/)?', 'webhooks/'], 'i');
const TG = rx(['api\\.telegram\\.org/', 'bot'], 'i');
// syscall.LoadDLL / NewLazyDLL standart kitaplığın Windows tarafında her zaman bağlıdır: yalnızca eklenti ve x/sys yükleyicileri
const DLL = /^(?:golang\.org\/x\/sys\/windows\.(?:LoadLibrary|LoadLibraryEx|NewLazyDLL)|plugin\.Open)$/;

const NOTABLE = [
  ['os/exec', t('süreç çalıştırma', 'process execution')],
  ['net/http', t('HTTP istemci/sunucu', 'HTTP client/server')],
  ['net', t('ham soket', 'raw sockets')],
  ['crypto/tls', 'TLS'],
  ['syscall', t('doğrudan sistem çağrıları', 'direct system calls')],
  ['golang.org/x/sys/windows', t('Windows API', 'Windows API')],
  ['golang.org/x/sys/unix', t('Unix sistem çağrıları', 'Unix system calls')],
  ['plugin', t('dinamik eklenti yükleme', 'dynamic plugin loading')],
  ['os/user', t('kullanıcı bilgisi', 'user information')],
  ['os/signal', t('sinyal yakalama', 'signal handling')],
  ['crypto/aes', 'AES'],
  ['crypto/rsa', 'RSA'],
  ['crypto/cipher', t('akış/blok şifre kipleri', 'cipher modes')],
  ['encoding/base64', 'base64'],
  ['compress/gzip', 'gzip'],
  ['archive/zip', 'zip'],
  ['net/smtp', 'SMTP'],
  ['reflect', t('yansıma', 'reflection')],
  ['unsafe', t('güvensiz işaretçi', 'unsafe pointers')],
];

/** Bağlı fonksiyonlardan yetenek grupları (sandbox davranışı yerine statik karşılık) */
export function capabilities(functions) {
  const b = { network: [], commands: [], files: [], other: [], loads: 0, stdout: '', calls: [], static: true };
  for (const f of functions) {
    for (const k of ['network', 'commands', 'files', 'other']) {
      if (FN[k].test(f.name) && b[k].length < 40) { b[k].push({ api: f.name, target: f.pkg ?? '' }); break; }
    }
  }
  return b;
}

/** İkilide bulunan dikkat çekici paketler */
export function notablePackages(packages, lang) {
  const have = new Map(packages.map((p) => [p.path, p]));
  return NOTABLE.filter(([p]) => have.has(p)).map(([p, why]) => ({ package: p, functions: have.get(p).functions, why: typeof why === 'string' ? why : pick(why, lang) }));
}

/**
 * @param {{ functions, strings: string[], iocs, detection, behaviour, upx }} o
 */
export function threat({ functions = [], strings = [], iocs, detection = [], behaviour, imports = [] }, lang = 'tr') {
  const findings = [];
  const add = (cls, weight, ev) => findings.push({ cls, weight, ev });
  const fnLabel = pick(t('fonksiyon', 'function'), lang);
  const strLabel = pick(t('dizge', 'string'), lang);
  const impLabel = pick(t('içe aktarma', 'import'), lang);
  for (const n of behaviour.network.slice(0, 3)) add('network', 20, `${fnLabel}: ${n.api}`);
  for (const c of behaviour.commands.slice(0, 3)) add('command-exec', 35, `${fnLabel}: ${c.api}`);
  for (const f of functions) if (DLL.test(f.name)) { add('dynamic-code', 15, `${fnLabel}: ${f.name}`); break; }
  for (const i of imports.slice(0, 2000)) {
    if (INJECT.test(i.name)) add('injection', 45, `${impLabel}: ${i.lib ? `${i.lib}!` : ''}${i.name}`);
    if (ANTI.test(i.name)) add('anti-analysis', 20, `${impLabel}: ${i.name}`);
  }
  for (const s of strings.slice(0, 200_000)) {
    if (s.length > 2000) continue;
    if (INJECT.test(s)) add('injection', 45, `${strLabel}: ${snippet(s, 80)}`);
    else if (PERSIST.test(s)) add('persistence', 40, `${strLabel}: ${snippet(s, 80)}`);
    else if (ANTI.test(s)) add('anti-analysis', 20, `${strLabel}: ${snippet(s, 80)}`);
    else if (CREDS.test(s)) add('credential-access', 45, `${strLabel}: ${snippet(s, 80)}`);
    if (HOOK.test(s) || TG.test(s)) add('exfiltration', 55, `${strLabel}: ${snippet(s, 80)}`);
  }
  for (const u of (iocs?.discordWebhooks ?? []).slice(0, 2)) add('exfiltration', 60, `Discord: ${snippet(u, 80)}`);
  // ağ yeteneği + gömülü (ya da gizlenmiş) adres birlikteyse ağır
  if (behaviour.network.length && (iocs?.urls?.length || iocs?.ips?.length)) add('network', 35, `IOC: ${snippet([...(iocs.urls ?? []), ...(iocs.ips ?? [])].slice(0, 3).join(', '), 100)}`);
  const upx = detection.find((d) => d.id === 'upx');
  if (upx) add('packed', 15, `UPX${upx.version ? ` ${upx.version}` : ''}: ${upx.evidence.slice(0, 2).join(' · ')}`);

  const byClass = new Map();
  for (const f of findings) {
    const c = byClass.get(f.cls) ?? { id: f.cls, title: pick(CLASSES[f.cls], lang), weight: 0, evidence: [] };
    c.weight = Math.max(c.weight, f.weight);
    if (c.evidence.length < 6 && !c.evidence.includes(f.ev)) c.evidence.push(f.ev);
    byClass.set(f.cls, c);
  }
  const classes = [...byClass.values()].sort((a, b) => b.weight - a.weight);
  // en güçlü sınıf tam, diğerleri yarım ağırlıkla
  const score = Math.min(100, Math.round(classes.reduce((s, c, i) => s + (i === 0 ? c.weight : c.weight / 2), 0)));
  const level = score === 0 ? 'none' : score < 20 ? 'low' : score < 45 ? 'medium' : score < 70 ? 'high' : 'critical';
  return { score, level, classes };
}
