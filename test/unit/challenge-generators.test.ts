import { describe, expect, it } from 'vitest';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { buildArtifact, CHALLENGE_KINDS, FIREWALL_RULESET, type Artifact, type ChallengeKind } from '../../src/challenges/generators.js';

/**
 * Each solver works the way the brief tells the learner to: brute force, log analysis,
 * packet decoding, permission and firewall reasoning. None of them reads generator
 * internals, so a generator that hides the flag badly, or not at all, fails here.
 */

const newFlag = () => `BASTION{${randomBytes(16).toString('hex')}}`;

/** The learner's side of lock(): the snippet given in the briefs, in TypeScript. */
function unlock(secret: string, vaultHex: string): string {
  const pad = Buffer.concat([0, 1].map((i) => createHash('sha256').update(`${secret}:${i}`).digest()));
  return Buffer.from(Buffer.from(vaultHex, 'hex').map((b, i) => b ^ (pad[i] ?? 0))).toString();
}

const field = (a: Artifact, name: string): string => {
  const v = a[name];
  if (v === undefined) throw new Error(`artifact has no "${name}"`);
  return v;
};

function solveWeakPin(a: Artifact): string {
  const target = field(a, 'storedHash');
  for (let n = 0; n < 10_000; n++) {
    const pin = String(n).padStart(4, '0');
    if (createHash('sha256').update(pin).digest('hex') === target) return unlock(pin, field(a, 'vault'));
  }
  return '';
}

/** Replays the attacker's binary search: "> n" true means the character is above n. */
function solveBlindSqli(a: Artifact): string {
  const chars = new Map<number, { lo: number; hi: number }>();
  for (const line of field(a, 'accessLog').split('\n')) {
    const m = /GET \/produits\?id=(\S+) HTTP\/1\.1" 200 (\d+)/.exec(line);
    if (!m?.[1] || !line.includes('sqlmap')) continue;
    const q = /SUBSTR\(\(SELECT valeur FROM secrets LIMIT 1\),(\d+),1\)\)>(\d+)$/.exec(decodeURIComponent(m[1]));
    if (!q) continue;
    const pos = Number(q[1]);
    const mid = Number(q[2]);
    const range = chars.get(pos) ?? { lo: 32, hi: 126 };
    if (m[2] === '5120') range.lo = mid + 1;
    else range.hi = mid;
    chars.set(pos, range);
  }
  return [...chars.entries()]
    .sort(([x], [y]) => x - y)
    .map(([, r]) => String.fromCharCode(r.lo))
    .join('');
}

function solveJwtWeakSecret(a: Artifact): string {
  const [header, payload, signature] = field(a, 'token').split('.');
  for (const word of field(a, 'wordlist').split('\n')) {
    if (createHmac('sha256', word).update(`${header ?? ''}.${payload ?? ''}`).digest('base64url') === signature) {
      return unlock(word, field(a, 'vault'));
    }
  }
  return '';
}

/** Rebuilds the packet from the hex columns only (the ASCII column is a convenience). */
function solveCapture(a: Artifact): { flag: string; packet: Buffer } {
  const hex = field(a, 'capture')
    .split('\n')
    .filter((l) => l.startsWith('\t0x'))
    .map((l) => l.slice(l.indexOf(':') + 1, l.indexOf(':') + 42).replace(/\s/g, ''))
    .join('');
  const packet = Buffer.from(hex, 'hex');
  const ihl = ((packet[0] ?? 0) & 0x0f) * 4;
  const tcpLen = ((packet[ihl + 12] ?? 0) >> 4) * 4;
  const http = packet.subarray(ihl + tcpLen).toString();
  const basic = /Authorization: Basic (\S+)/.exec(http)?.[1] ?? '';
  return { flag: Buffer.from(basic, 'base64').toString().split(':')[1] ?? '', packet };
}

/** Kernel rule: exactly one class applies (owner, else group, else other). */
function wwwDataCanRead(perm: string, owner: string, group: string): boolean {
  if (owner === 'www-data') return perm[1] === 'r';
  if (group === 'www-data' || group === 'adm') return perm[4] === 'r';
  return perm[7] === 'r';
}

function solveLinux(a: Artifact): string {
  const contents = new Map<string, string>();
  for (const block of field(a, 'contents').split('\n\n')) {
    const [head, body] = block.split('\n');
    const path = /^==> (.+) <==$/.exec(head ?? '')?.[1];
    if (path) contents.set(path, body ?? '');
  }
  const parts = new Map<number, string>();
  for (const line of field(a, 'listing').split('\n')) {
    const [perm = '', , owner = '', group = ''] = line.split(/\s+/);
    const path = line.slice(line.lastIndexOf(' ') + 1);
    if (!wwwDataCanRead(perm, owner, group)) continue;
    const n = Number(/part-(\d+)$/.exec(path)?.[1]);
    expect(parts.has(n), `two readable files for part ${n}`).toBe(false);
    parts.set(n, contents.get(path) ?? '');
  }
  return [...parts.entries()].sort(([x], [y]) => x - y).map(([, v]) => v).join('');
}

const inCidr = (ip: string, cidr: string) => {
  const [net = '', bits = '32'] = cidr.split('/');
  const n = (s: string) => s.split('.').reduce((acc, o) => acc * 256 + Number(o), 0);
  const size = 2 ** (32 - Number(bits));
  return Math.floor(n(ip) / size) === Math.floor(n(net) / size);
};

/** An nftables evaluator for the rule shapes of FIREWALL_RULESET: first match wins, else the policy. */
function verdict(proto: string, src: string, port: number): 'accept' | 'drop' {
  const rules = FIREWALL_RULESET.split('\n').map((l) => l.trim());
  for (const rule of rules) {
    const words = rule.split(' ');
    const action = words.at(-1);
    // "ct state established,related" never matches a new connection.
    if ((action !== 'accept' && action !== 'drop') || words[0] === 'ct') continue;
    const after = (w: string) => (words.includes(w) ? words[words.indexOf(w) + 1] : undefined);
    const saddr = after('saddr');
    const ruleProto = words.find((w) => w === 'tcp' || w === 'udp');
    if (saddr !== undefined && !inCidr(src, saddr)) continue;
    if (ruleProto !== undefined && (ruleProto !== proto || Number(after('dport')) !== port)) continue;
    return action;
  }
  return /policy (accept|drop)/.exec(FIREWALL_RULESET)?.[1] === 'accept' ? 'accept' : 'drop';
}

function solveFirewall(a: Artifact): string {
  return field(a, 'connections')
    .split('\n')
    .slice(1)
    .map((l) => l.split(/\s+/))
    .filter(([, , proto = '', src = '', port = '']) => verdict(proto, src, Number(port)) === 'accept')
    .map((cols) => cols[5] ?? '')
    .join('');
}

function solvePowershell(a: Artifact): string {
  const rows = field(a, 'events').split('\n').slice(1).map((l) => l.split(';'));
  // The sprayed account that finally logged in, then what it ran on the server.
  const success = rows.find(([, id]) => id === '4624');
  const process = rows.find(([, id, account]) => id === '4688' && account === success?.[2]);
  const encoded = /-EncodedCommand (\S+)/.exec(process?.[4] ?? '')?.[1] ?? '';
  return /net user \S+ '([^']+)'/.exec(Buffer.from(encoded, 'base64').toString('utf16le'))?.[1] ?? '';
}

const SOLVERS: Partial<Record<ChallengeKind, (a: Artifact) => string>> = {
  'weak-pin-hash': solveWeakPin,
  'blind-sqli-log': solveBlindSqli,
  'jwt-weak-secret': solveJwtWeakSecret,
  'cleartext-capture': (a) => solveCapture(a).flag,
  'linux-permissions': solveLinux,
  'firewall-flows': solveFirewall,
  'powershell-encoded': solvePowershell,
};

describe('challenge generators', () => {
  it.each(Object.keys(SOLVERS))('%s: the learner can recover their flag, and only by solving it', (kind) => {
    const solve = SOLVERS[kind as ChallengeKind];
    for (let i = 0; i < 20; i++) {
      const flag = newFlag();
      const artifact = buildArtifact(kind as ChallengeKind, flag, randomBytes(32));
      expect(solve?.(artifact)).toBe(flag);
      // Nothing to grep: the flag never appears as such in what the learner receives.
      expect(JSON.stringify(artifact)).not.toContain(flag);
    }
  });

  it('every kind is deterministic per seed and varies between learners', () => {
    const seed = randomBytes(32);
    for (const kind of CHALLENGE_KINDS) {
      const flag = newFlag();
      expect(buildArtifact(kind, flag, seed)).toEqual(buildArtifact(kind, flag, seed));
      expect(buildArtifact(kind, flag, seed)).not.toEqual(buildArtifact(kind, newFlag(), randomBytes(32)));
    }
  });

  it('decoys look exactly like real fragments, so the format gives nothing away', () => {
    const flag = newFlag();
    const seed = randomBytes(32);
    const linux = field(buildArtifact('linux-permissions', flag, seed), 'contents');
    const firstParts = linux.split('\n\n').filter((b) => b.includes('part-1 <==')).map((b) => b.split('\n')[1] ?? '');
    expect(firstParts).toHaveLength(3);
    for (const p of firstParts) expect(p).toMatch(/^BASTION\{[0-9a-f]{3}$/);
    const rows = field(buildArtifact('firewall-flows', flag, seed), 'connections').split('\n').slice(1).map((l) => l.split(/\s+/));
    const dropped = rows.filter(([, , proto = '', src = '', port = '']) => verdict(proto, src, Number(port)) === 'drop');
    expect(dropped.length).toBeGreaterThanOrEqual(6); // at least one decoy per fragment
    // Reassembling the dropped first-slot decoys yields flag-shaped text too.
    expect(dropped.map((r) => r[5] ?? '').some((d) => d.startsWith('BASTION'))).toBe(true);
  });

  it('the capture is a well-formed IPv4/TCP packet with valid checksums', () => {
    const { packet } = solveCapture(buildArtifact('cleartext-capture', newFlag(), randomBytes(32)));
    const sum = (b: Buffer) => {
      let s = 0;
      for (let i = 0; i < b.length; i += 2) s += ((b[i] ?? 0) << 8) | (b[i + 1] ?? 0);
      while (s > 0xffff) s = (s & 0xffff) + (s >>> 16);
      return s;
    };
    expect(packet.readUInt16BE(2)).toBe(packet.length);
    expect(sum(packet.subarray(0, 20))).toBe(0xffff);
    const segment = packet.subarray(20);
    const pseudo = Buffer.concat([packet.subarray(12, 20), Buffer.from([0, 6, segment.length >> 8, segment.length & 0xff])]);
    expect(sum(Buffer.concat([pseudo, segment]))).toBe(0xffff);
  });

  it('the permission puzzle exercises the classic traps', () => {
    // Owner class wins even when "other" could read; group class wins likewise.
    expect(wwwDataCanRead('----r--r--', 'www-data', 'www-data')).toBe(false);
    expect(wwwDataCanRead('-rw----r--', 'root', 'adm')).toBe(false);
    expect(wwwDataCanRead('-rw-r-----', 'root', 'adm')).toBe(true);
  });

  it('the firewall puzzle needs rule order, protocol and source to be read correctly', () => {
    expect(verdict('tcp', '10.66.1.9', 443)).toBe('drop'); // quarantine comes first
    expect(verdict('tcp', '203.0.113.9', 443)).toBe('accept');
    expect(verdict('udp', '10.0.3.9', 443)).toBe('drop');
    expect(verdict('tcp', '10.0.9.9', 22)).toBe('accept');
    expect(verdict('tcp', '10.0.8.9', 22)).toBe('drop');
    expect(verdict('udp', '203.0.113.9', 53)).toBe('drop');
  });
});
