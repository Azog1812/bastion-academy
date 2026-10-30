import { createHash, createHmac } from 'node:crypto';

/**
 * Challenge artifacts: what a learner receives and has to analyse to recover
 * their flag. Each kind teaches one idea from the lessons. Artifacts are
 * deterministic per (user, challenge), derived from a seed, so reloading the
 * page shows the same puzzle, and nothing has to be stored.
 *
 * The set of kinds is closed: content/ can only pick one of these, never ship
 * code (ADR 0006).
 */

export const CHALLENGE_KINDS = [
  'base64-layers',
  'xor-single-byte',
  'http-headers',
  'jwt-claims',
  'weak-pin-hash',
  'blind-sqli-log',
  'jwt-weak-secret',
  'cleartext-capture',
  'linux-permissions',
  'firewall-flows',
  'powershell-encoded',
] as const;
export type ChallengeKind = (typeof CHALLENGE_KINDS)[number];

/** Free-form but typed: the front-end shows each field as text in a <pre>. */
export type Artifact = Record<string, string>;

const b64url = (v: Buffer | string) => Buffer.from(v).toString('base64url');

/** Deterministic integer in [0, n) for (label, i): the puzzle varies per learner, nothing is stored. */
function draw(seed: Buffer, label: string, i: number, n: number): number {
  return createHmac('sha256', seed).update(`${label}:${i}`).digest().readUInt32BE(0) % n;
}

/** Deterministic element of a non-empty list. */
function pick<T>(list: readonly T[], seed: Buffer, label: string, i: number): T {
  const item = list[draw(seed, label, i, list.length)];
  if (item === undefined) throw new Error(`empty list for ${label}`);
  return item;
}

/** Same shape as a real flag (BASTION{32 hex}), so decoys cannot be told apart by their format. */
function decoyFlag(seed: Buffer, k: number): string {
  return `BASTION{${createHmac('sha256', seed).update(`decoy:${k}`).digest('hex').slice(0, 32)}}`;
}

/** Cuts a flag into `n` slices of near-equal length. */
function slices(flag: string, n: number): string[] {
  const size = Math.ceil(flag.length / n);
  return Array.from({ length: n }, (_, i) => flag.slice(i * size, (i + 1) * size));
}

/**
 * A lock for puzzles whose answer is a recovered secret: flag XOR SHA-256(secret:0) ‖ SHA-256(secret:1).
 * Not a cipher to use anywhere else; it only has to be reversible with Python's standard library.
 */
function lock(secret: string, flag: string): string {
  const pad = Buffer.concat([0, 1].map((i) => createHash('sha256').update(`${secret}:${i}`).digest()));
  if (flag.length > pad.length) throw new Error('flag too long to lock');
  return Buffer.from(Buffer.from(flag).map((b, i) => b ^ (pad[i] ?? 0))).toString('hex');
}

/** "Encoding is not encryption": the flag, base64-encoded 2 to 4 times. */
function base64Layers(flag: string, seed: Buffer): Artifact {
  let data = flag;
  const layers = 2 + ((seed[0] ?? 0) % 3);
  for (let i = 0; i < layers; i++) data = Buffer.from(data).toString('base64');
  return { data };
}

/** Home-made crypto: single-byte XOR falls to a known-plaintext attack (every flag starts with "BASTION{"). */
function xorSingleByte(flag: string, seed: Buffer): Artifact {
  const key = 1 + ((seed[1] ?? 0) % 255);
  const ct = Buffer.from(flag).map((b) => b ^ key);
  return { ciphertextHex: Buffer.from(ct).toString('hex') };
}

/** Verbose servers: the flag leaks in a debug header among ordinary ones. */
function httpHeaders(flag: string, seed: Buffer): Artifact {
  const requestId = seed.subarray(2, 18).toString('hex');
  const response = [
    'HTTP/1.1 200 OK',
    'Content-Type: application/json; charset=utf-8',
    'Cache-Control: no-store',
    'Server: legacy-api/0.9.3',
    `X-Request-Id: ${requestId}`,
    `X-Debug-Session: ${flag}`,
    'Strict-Transport-Security: max-age=63072000',
    'Content-Length: 27',
    '',
    '{"status":"ok","items":[]}',
  ].join('\n');
  return { response };
}

/** "A JWT is signed, not encrypted": anyone holding the token can read its claims. */
function jwtClaims(flag: string, seed: Buffer): Artifact {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ sub: 'stagiaire-42', role: 'user', debug_note: flag, iat: 1_767_225_600 }));
  // Signed with a throwaway key derived from the seed: the signature is real but irrelevant to the puzzle.
  const signature = createHmac('sha256', seed).update(`${header}.${payload}`).digest('base64url');
  return { token: `${header}.${payload}.${signature}` };
}

/** Fast, unsalted hashes: a 4-digit PIN hashed with SHA-256 falls to 10,000 guesses. */
function weakPinHash(flag: string, seed: Buffer): Artifact {
  const pin = String(draw(seed, 'pin', 0, 10_000)).padStart(4, '0');
  return { storedHash: createHash('sha256').update(pin).digest('hex'), vault: lock(pin, flag) };
}

/**
 * Blind SQL injection, read from the defender's side: an access log where the attacker
 * extracted a secret one character at a time by binary search (`ASCII(SUBSTR(...)) > n`),
 * and the only signal is the response size (true: the product page, false: "no product").
 */
function blindSqliLog(flag: string, seed: Buffer): Artifact {
  const lines: string[] = [];
  let t = 3 * 3600 + 14 * 60 + draw(seed, 'start', 0, 600);
  const at = () => {
    t += 1 + draw(seed, 'gap', t, 2);
    const hh = String(Math.floor(t / 3600)).padStart(2, '0');
    const mm = String(Math.floor(t / 60) % 60).padStart(2, '0');
    return `[12/Jan/2026:${hh}:${mm}:${String(t % 60).padStart(2, '0')} +0100]`;
  };
  const visitor = `192.0.2.${10 + draw(seed, 'visitor', 0, 200)}`;
  const browsing = [['/', 8211], ['/produits?id=3', 5120], ['/produits?id=7', 5120], ['/panier', 2048]] as const;
  for (const [path, size] of browsing) {
    lines.push(`${visitor} - - ${at()} "GET ${path} HTTP/1.1" 200 ${size} "-" "Mozilla/5.0 (X11; Linux x86_64) Firefox/134.0"`);
  }
  const attacker = `10.13.37.${2 + draw(seed, 'attacker', 0, 250)}`;
  const probe = (query: string, truth: boolean) =>
    lines.push(
      `${attacker} - - ${at()} "GET /produits?id=${encodeURIComponent(query)} HTTP/1.1" 200 ${truth ? 5120 : 312} "-" "sqlmap/1.8.12#stable"`,
    );
  probe("3'", false);
  probe('3 AND 1=1', true);
  probe('3 AND 1=2', false);
  Buffer.from(flag).forEach((code, i) => {
    let lo = 32;
    let hi = 126;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      const truth = code > mid;
      probe(`3 AND ASCII(SUBSTR((SELECT valeur FROM secrets LIMIT 1),${i + 1},1))>${mid}`, truth);
      if (truth) lo = mid + 1;
      else hi = mid;
    }
  });
  return { accessLog: lines.join('\n') };
}

/** Common secrets: offline, each candidate is checked against the HS256 signature, no server involved. */
const WEAK_JWT_SECRETS = [
  'secret', 'password', 'changeme', 'azerty', '123456', 'admin', 'motdepasse', 'your-256-bit-secret',
  'supersecret', 'default', 'letmein', 'qwerty', 's3cr3t', 'jwt_secret', 'jwtsecret', 'mysecret',
  'secretkey', 'soleil', 'bonjour', 'marseille', 'paris2024', 'development', 'production', 'shhhhh',
  'token', 'private', 'test', 'dev', 'bastion', 'p@ssw0rd',
] as const;

/** A JWT signed with a guessable secret: crack the signature offline, then the secret opens the vault. */
function jwtWeakSecret(flag: string, seed: Buffer): Artifact {
  const secret = pick(WEAK_JWT_SECRETS, seed, 'jwt', 0);
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ sub: 'stagiaire-42', role: 'user', iat: 1_767_225_600 }));
  const signature = createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
  return { token: `${header}.${payload}.${signature}`, wordlist: WEAK_JWT_SECRETS.join('\n'), vault: lock(secret, flag) };
}

/** Internet checksum (RFC 1071), so the capture is a packet a real decoder would accept. */
function checksum(data: Buffer): number {
  let sum = 0;
  for (let i = 0; i < data.length; i += 2) sum += ((data[i] ?? 0) << 8) | (data[i + 1] ?? 0);
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return ~sum & 0xffff;
}

/** HTTP without TLS: Basic credentials cross the network in Base64, readable by anyone on the path. */
function cleartextCapture(flag: string, seed: Buffer): Artifact {
  const src = [10, 0, 1, 10 + draw(seed, 'src', 0, 200)];
  const dst = [10, 0, 2, 20];
  const sport = 49152 + draw(seed, 'sport', 0, 16000);
  const seq = draw(seed, 'seq', 0, 0xffffffff);
  const ack = draw(seed, 'ack', 0, 0xffffffff);
  const http = Buffer.from(
    'GET /admin/sauvegardes HTTP/1.1\r\nHost: intranet.bastion.test\r\n' +
      `Authorization: Basic ${Buffer.from(`admin:${flag}`).toString('base64')}\r\nUser-Agent: curl/8.11.1\r\n\r\n`,
  );
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(sport, 0);
  tcp.writeUInt16BE(80, 2);
  tcp.writeUInt32BE(seq, 4);
  tcp.writeUInt32BE(ack, 8);
  tcp.writeUInt8(0x50, 12); // header length: 5 x 32-bit words, no options
  tcp.writeUInt8(0x18, 13); // PSH + ACK
  tcp.writeUInt16BE(502, 14);
  const segment = tcp.length + http.length;
  const pseudo = Buffer.from([...src, ...dst, 0, 6, segment >> 8, segment & 0xff]);
  tcp.writeUInt16BE(checksum(Buffer.concat([pseudo, tcp, http])), 16);
  const ip = Buffer.alloc(20);
  ip.writeUInt8(0x45, 0); // IPv4, 20-byte header
  ip.writeUInt16BE(20 + segment, 2);
  ip.writeUInt16BE(draw(seed, 'ipid', 0, 0xffff), 4);
  ip.writeUInt16BE(0x4000, 6); // don't fragment
  ip.writeUInt8(64, 8);
  ip.writeUInt8(6, 9); // TCP
  Buffer.from([...src, ...dst]).copy(ip, 12);
  ip.writeUInt16BE(checksum(ip), 10);
  const packet = Buffer.concat([ip, tcp, http]);
  const usec = String(draw(seed, 'usec', 0, 1_000_000)).padStart(6, '0');
  const rows = [
    `09:41:07.${usec} IP ${src.join('.')}.${sport} > ${dst.join('.')}.80: Flags [P.], ` +
      `seq ${seq}:${seq + http.length}, ack ${ack}, win 502, length ${http.length}: HTTP: GET /admin/sauvegardes HTTP/1.1`,
  ];
  for (let off = 0; off < packet.length; off += 16) {
    const row = packet.subarray(off, off + 16);
    const hex = (row.toString('hex').match(/.{1,4}/g) ?? []).join(' ');
    const ascii = [...row].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('');
    rows.push(`\t0x${off.toString(16).padStart(4, '0')}:  ${hex.padEnd(39)}  ${ascii}`);
  }
  return { capture: rows.join('\n') };
}

type FileMode = { owner: string; group: string; mode: number };

/** For www-data (uid 33, groups www-data and adm). The kernel applies ONE class: owner, else group, else other. */
const READABLE: readonly FileMode[] = [
  { owner: 'root', group: 'root', mode: 0o644 },
  { owner: 'root', group: 'adm', mode: 0o640 },
  { owner: 'www-data', group: 'www-data', mode: 0o600 },
  { owner: 'root', group: 'adm', mode: 0o750 },
];
const UNREADABLE: readonly FileMode[] = [
  { owner: 'root', group: 'root', mode: 0o640 },
  { owner: 'root', group: 'shadow', mode: 0o640 },
  { owner: 'root', group: 'root', mode: 0o600 },
  { owner: 'www-data', group: 'www-data', mode: 0o044 }, // owner class applies: no read, despite "other" r
  { owner: 'root', group: 'adm', mode: 0o604 }, // group class applies: no read, despite "other" r
  { owner: 'syslog', group: 'adm', mode: 0o600 },
];

function modeString(mode: number): string {
  const rwx = (bits: number) => ['r', 'w', 'x'].map((c, i) => (bits & (4 >> i) ? c : '-')).join('');
  return `-${rwx(mode >> 6)}${rwx(mode >> 3)}${rwx(mode)}`;
}

/** Linux permissions: only the fragments www-data can actually read make up the flag. */
function linuxPermissions(flag: string, seed: Buffer): Artifact {
  const dirs = ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel', 'india', 'juliett', 'kilo', 'lima'];
  const offset = draw(seed, 'dir', 0, dirs.length);
  const files: { path: string; perm: FileMode; content: string }[] = [];
  slices(flag, 4).forEach((part, i) => {
    const winner = draw(seed, 'winner', i, 3);
    for (let j = 0; j < 3; j++) {
      const k = i * 3 + j;
      files.push({
        path: `/srv/coffre/${dirs[(k + offset) % dirs.length] ?? 'alpha'}/part-${i + 1}`,
        perm: j === winner ? pick(READABLE, seed, 'ok', i) : pick(UNREADABLE, seed, 'ko', k),
        content: j === winner ? part : (slices(decoyFlag(seed, k), 4)[i] ?? ''),
      });
    }
  });
  files.sort((a, b) => a.path.localeCompare(b.path));
  const line = (f: (typeof files)[number]) =>
    `${modeString(f.perm.mode)} 1 ${f.perm.owner.padEnd(8)} ${f.perm.group.padEnd(8)} ${String(f.content.length + 1).padStart(3)} janv. 12 10:00 ${f.path}`;
  return {
    id: 'uid=33(www-data) gid=33(www-data) groups=33(www-data),4(adm)',
    listing: files.map(line).join('\n'),
    contents: files.map((f) => `==> ${f.path} <==\n${f.content}`).join('\n\n'),
  };
}

export const FIREWALL_RULESET = [
  'table inet filtre {',
  '  chain entree {',
  '    type filter hook input priority 0; policy drop;',
  '    ct state established,related accept',
  '    ip saddr 10.66.0.0/16 drop',
  '    tcp dport 443 accept',
  '    ip saddr 10.0.9.0/24 tcp dport 22 accept',
  '    ip saddr 10.0.0.0/8 udp dport 53 accept',
  '  }',
  '}',
].join('\n');

type Flow = { proto: 'tcp' | 'udp'; src: string; port: number };

/** New connections, and the reason FIREWALL_RULESET decides them (first match wins, else policy drop). */
const ACCEPTED_FLOWS: readonly ((host: number) => Flow)[] = [
  (h) => ({ proto: 'tcp', src: `198.51.100.${h}`, port: 443 }),
  (h) => ({ proto: 'tcp', src: `10.0.3.${h}`, port: 443 }),
  (h) => ({ proto: 'tcp', src: `10.0.9.${h}`, port: 22 }),
  (h) => ({ proto: 'udp', src: `10.0.4.${h}`, port: 53 }),
];
const DROPPED_FLOWS: readonly ((host: number) => Flow)[] = [
  (h) => ({ proto: 'tcp', src: `10.66.1.${h}`, port: 443 }), // the quarantine rule comes before "443 accept"
  (h) => ({ proto: 'tcp', src: `10.0.8.${h}`, port: 22 }), // not the admin subnet
  (h) => ({ proto: 'udp', src: `203.0.113.${h}`, port: 53 }), // DNS only from 10.0.0.0/8
  (h) => ({ proto: 'tcp', src: `10.0.9.${h}`, port: 3306 }), // admin subnet, but only for SSH
  (h) => ({ proto: 'tcp', src: `198.51.100.${h}`, port: 80 }), // no rule: policy drop
  (h) => ({ proto: 'udp', src: `10.0.3.${h}`, port: 443 }), // 443 is allowed over TCP only
];

/** Default deny, first match wins: only accepted connections carry fragments of the flag. */
function firewallFlows(flag: string, seed: Buffer): Artifact {
  const rows = ['n°  heure     proto  source           port  données'];
  let k = 0;
  slices(flag, 6).forEach((part, i) => {
    const count = 2 + draw(seed, 'count', i, 2);
    const winner = draw(seed, 'winner', i, count);
    for (let j = 0; j < count; j++) {
      const host = 2 + draw(seed, 'host', k, 250);
      const flow = (j === winner ? pick(ACCEPTED_FLOWS, seed, 'accept', i) : pick(DROPPED_FLOWS, seed, 'drop', k))(host);
      const data = j === winner ? part : (slices(decoyFlag(seed, k), 6)[i] ?? '');
      k++;
      const time = `09:${String(10 + Math.floor(k / 60)).padStart(2, '0')}:${String(k % 60).padStart(2, '0')}`;
      rows.push(`${String(k).padStart(2, '0')}  ${time}  ${flow.proto.padEnd(5)}  ${flow.src.padEnd(15)}  ${String(flow.port).padEnd(4)}  ${data}`);
    }
  });
  return { ruleset: FIREWALL_RULESET, connections: rows.join('\n') };
}

/**
 * Windows logs after a password spray: 4625 failures for many accounts from one address, one
 * 4624 success, then a 4688 process creation whose PowerShell -EncodedCommand (Base64 of
 * UTF-16LE) creates a backdoor account. The flag is that account's password.
 */
function powershellEncoded(flag: string, seed: Buffer): Artifact {
  const accounts = ['a.martin', 'c.bernard', 'l.petit', 'm.durand', 's.leroy', 'j.moreau', 'n.simon', 'p.laurent', 'e.michel', 't.garcia', 'r.david', 'h.bertrand'];
  const victim = pick(accounts, seed, 'victim', 0);
  const attacker = `10.0.5.${2 + draw(seed, 'attacker', 0, 250)}`;
  const enc = (cmd: string) => Buffer.from(cmd, 'utf16le').toString('base64');
  let s = 0;
  const at = () => {
    s += 1 + draw(seed, 'gap', s, 3);
    return `2026-01-12T02:${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
  };
  const rows = ['TimeCreated;EventID;Compte;Source;Détail'];
  rows.push(`${at()};4688;adm-jdupont;SRV-FICHIERS;powershell.exe -NoProfile -EncodedCommand ${enc("Get-Service | Where-Object Status -eq 'Stopped'")}`);
  for (const account of accounts) {
    rows.push(
      account === victim
        ? `${at()};4624;${account};${attacker};LogonType=3 (réseau)`
        : `${at()};4625;${account};${attacker};LogonType=3 Status=0xC000006A (mot de passe incorrect)`,
    );
  }
  rows.push(`${at()};4688;adm-jdupont;SRV-FICHIERS;powershell.exe -NoProfile -EncodedCommand ${enc('Get-ChildItem D:\\Sauvegardes | Measure-Object -Property Length -Sum')}`);
  rows.push(
    `${at()};4688;${victim};SRV-FICHIERS;powershell.exe -NoP -W Hidden -EncodedCommand ` +
      enc(`net user svc_maint '${flag}' /add; net localgroup Administrateurs svc_maint /add`),
  );
  return { events: rows.join('\n') };
}

export function buildArtifact(kind: ChallengeKind, flag: string, seed: Buffer): Artifact {
  switch (kind) {
    case 'base64-layers':
      return base64Layers(flag, seed);
    case 'xor-single-byte':
      return xorSingleByte(flag, seed);
    case 'http-headers':
      return httpHeaders(flag, seed);
    case 'jwt-claims':
      return jwtClaims(flag, seed);
    case 'weak-pin-hash':
      return weakPinHash(flag, seed);
    case 'blind-sqli-log':
      return blindSqliLog(flag, seed);
    case 'jwt-weak-secret':
      return jwtWeakSecret(flag, seed);
    case 'cleartext-capture':
      return cleartextCapture(flag, seed);
    case 'linux-permissions':
      return linuxPermissions(flag, seed);
    case 'firewall-flows':
      return firewallFlows(flag, seed);
    case 'powershell-encoded':
      return powershellEncoded(flag, seed);
  }
}
