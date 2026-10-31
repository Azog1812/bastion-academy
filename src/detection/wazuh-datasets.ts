import { rng, T0 } from './datasets.js';
import type { StockRule, WazuhDataset, WazuhEvent } from './wazuh.js';

/**
 * Labelled datasets for the Wazuh rule challenges (ADR 0014), generated per learner
 * from an HMAC seed like the JSON ones (ADR 0010). Each event is what Wazuh would
 * have produced before any local rule: the decoded fields and the stock rule it
 * reached. The raw lines are real `sshd` syslog and JSON lines, so a learner can
 * replay them in `wazuh-logtest` on the real stack (ADR 0013).
 */
export const WAZUH_DATASET_KINDS = ['wazuh-ssh', 'wazuh-bastion'] as const;
export type WazuhDatasetKind = (typeof WAZUH_DATASET_KINDS)[number];

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'] as const;
const pad = (n: number) => String(n).padStart(2, '0');
function syslogTime(ts: number): string {
  const d = new Date(ts * 1000);
  return `${MONTHS[d.getUTCMonth()] ?? 'Jan'} ${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

type Draft = Omit<WazuhEvent, 'id'>;

/** Sorts by time and numbers events, so ids say nothing about which ones are malicious. */
function finish(drafts: { e: Draft; bad: boolean }[]): { events: WazuhEvent[]; bad: Set<string> } {
  const sorted = [...drafts].sort((a, b) => a.e.ts - b.e.ts);
  const bad = new Set<string>();
  const events = sorted.map(({ e, bad: isBad }, i) => {
    const id = `e${String(i + 1).padStart(3, '0')}`;
    if (isBad) bad.add(id);
    return Object.freeze({ id, ...e, fields: Object.freeze({ ...e.fields }) });
  });
  return { events, bad };
}

/* ------------------------------------------------------------------ wazuh-ssh */

/**
 * Stock sshd rules of Wazuh 4.14 (0095-sshd_rules.xml) that these events reach, with their
 * parents, as wazuh-logtest shows them: "Failed password" walks 5700 → 5716 → 5760. The
 * compliance groups (pci_dss_…, gdpr_…) are left out. The stock correlation rules (5712,
 * 5720, 5763, 40111) are left out on purpose: writing one is the exercise.
 */
const SSH_STOCK: readonly StockRule[] = [
  { id: 5700, level: 0, description: 'SSHD messages grouped.', groups: ['syslog', 'sshd'] },
  { id: 5710, level: 5, description: 'sshd: Attempt to login using a non-existent user', groups: ['syslog', 'sshd', 'authentication_failed', 'invalid_login'], parent: 5700 },
  { id: 5715, level: 3, description: 'sshd: authentication success.', groups: ['syslog', 'sshd', 'authentication_success'], parent: 5700 },
  { id: 5716, level: 5, description: 'sshd: authentication failed.', groups: ['syslog', 'sshd', 'authentication_failed'], parent: 5700 },
  { id: 5760, level: 5, description: 'sshd: authentication failed.', groups: ['syslog', 'sshd', 'authentication_failed'], parent: 5716 },
  { id: 5721, level: 0, description: 'sshd: System disconnected from sshd.', groups: ['syslog', 'sshd'], parent: 5700 },
];

function wazuhSsh(seed: Buffer): WazuhDataset {
  const r = rng(seed, 'wazuh-ssh');
  const drafts: { e: Draft; bad: boolean }[] = [];
  const line = (ts: number, message: string) => `${syslogTime(ts)} srv-web-01 sshd[${String(1000 + r.int(30_000))}]: ${message}`;
  const port = () => String(32_768 + r.int(28_000));
  // The sshd decoder puts the account of "Accepted/Failed … for x" in dstuser, of "Invalid user x" in srcuser.
  const ok = (ts: number, user: string, ip: string, method = 'publickey') =>
    drafts.push({ e: { ts, sid: 5715, srcip: ip, user, userKey: 'dstuser', action: '', program_name: 'sshd', full_log: line(ts, `Accepted ${method} for ${user} from ${ip} port ${port()} ssh2`), fields: {} }, bad: false });
  const failed = (ts: number, user: string, ip: string, bad: boolean) =>
    drafts.push({ e: { ts, sid: 5760, srcip: ip, user, userKey: 'dstuser', action: '', program_name: 'sshd', full_log: line(ts, `Failed password for ${user} from ${ip} port ${port()} ssh2`), fields: {} }, bad });
  const invalid = (ts: number, user: string, ip: string, bad: boolean) =>
    drafts.push({ e: { ts, sid: 5710, srcip: ip, user, userKey: 'srcuser', action: '', program_name: 'sshd', full_log: line(ts, `Invalid user ${user} from ${ip} port ${port()}`), fields: {} }, bad });

  // Admins with keys, all day; the jump host, constantly.
  for (let k = 0; k < 40; k++) ok(T0 + r.int(28_800), r.pick(['deploy', 'florian', 'admin']), `10.2.0.${String(5 + r.int(3))}`);
  for (let k = 0; k < 25; k++) ok(T0 + r.int(7200), 'deploy', '10.2.0.1');
  // Monitoring opens the port and leaves before authenticating (stock rule 5721, level 0).
  for (let k = 0; k < 30; k++) {
    const ts = T0 + k * 120;
    drafts.push({ e: { ts, sid: 5721, srcip: '10.2.0.9', user: '', action: '', program_name: 'sshd', full_log: line(ts, `Received disconnect from 10.2.0.9 port ${port()}:11: Bye Bye [preauth]`), fields: {} }, bad: false });
  }
  // A developer mistyping twice, then in.
  failed(T0 + 5000, 'marc', '10.2.3.40', false);
  failed(T0 + 5010, 'marc', '10.2.3.40', false);
  ok(T0 + 5030, 'marc', '10.2.3.40', 'password');
  // TRAP: six tries over eight minutes, a call to the help desk, then in.
  for (let n = 0; n < 6; n++) failed(T0 + 9000 + n * 90, 'julie', '10.2.3.41', false);
  ok(T0 + 9700, 'julie', '10.2.3.41', 'password');
  // TRAP: the backup server's account has an expired password; its job retries every five minutes, all day.
  for (let k = 0; k < 96; k++) failed(T0 + k * 300 + r.int(20), 'svc-sauvegarde', '10.0.5.20', false);

  // Fast brute forcer #1 tries only accounts that do not exist (5710, never 5716).
  const a = `198.51.100.${String(2 + r.int(250))}`;
  const ta = T0 + 2000 + r.int(18_000);
  for (let k = 0, n = 25 + r.int(15); k < n; k++) invalid(ta + k * (1 + r.int(4)), r.pick(['admin', 'test', 'oracle', 'ubuntu', 'postgres', 'guest']), a, true);
  // Fast brute forcer #2 hammers root (5716).
  const b = `203.0.113.${String(2 + r.int(250))}`;
  const tb = T0 + 2000 + r.int(18_000);
  for (let k = 0, n = 20 + r.int(10); k < n; k++) failed(tb + k * (2 + r.int(3)), 'root', b, true);
  // TRAP for wide exclusions: a compromised machine on the backup server's own subnet.
  const tc = T0 + 15_000 + r.int(8000);
  for (let k = 0; k < 15; k++) {
    if (k % 3 === 0) invalid(tc + k * 12, r.pick(['admin', 'backup', 'ftp']), '10.0.5.77', true);
    else failed(tc + k * 12, 'root', '10.0.5.77', true);
  }
  // TRAP for short windows: a slow brute forcer, twelve tries in under an hour.
  const slow = `192.0.2.${String(2 + r.int(250))}`;
  const ts = T0 + 12_000;
  for (let k = 0; k < 12; k++) failed(ts + k * (270 + r.int(30)), 'root', slow, true);

  const { events } = finish(drafts);
  return {
    decoder: 'sshd',
    fields: [],
    stock: SSH_STOCK,
    events,
    unit: 'entity',
    entityField: 'srcip',
    malicious: new Set([a, b, '10.0.5.77', slow]),
    minLevel: 10,
  };
}

/* -------------------------------------------------------------- wazuh-bastion */

/** The base rule the brief gives: every line of Bastion's audit log, decoded by the JSON decoder. */
export const BASTION_BASE_RULE = `<group name="bastion,">
  <rule id="100000" level="3">
    <decoded_as>json</decoded_as>
    <field name="service">^bastion$</field>
    <description>Bastion : événement du journal d'audit ($(action))</description>
  </rule>
</group>`;

const BASTION_STOCK: readonly StockRule[] = [{ id: 100_000, level: 3, description: "Bastion : événement du journal d'audit", groups: ['bastion'] }];
/** Dynamic fields for `<field>`. `action` and `srcip` are static fields in Wazuh: `<action>`, `<srcip>`. */
const BASTION_FIELDS = ['service', 'outcome', 'actor', 'target', 'reason', 'required', 'resource'] as const;

function wazuhBastion(seed: Buffer): WazuhDataset {
  const r = rng(seed, 'wazuh-bastion');
  const drafts: { e: Draft; bad: boolean }[] = [];
  const learners = Array.from({ length: 30 }, (_, k) => ({ actor: `u-${(0x3a00 + k * 37).toString(16)}`, ip: `10.3.0.${String(20 + k)}` }));
  const audit = (ts: number, who: { actor: string; ip: string }, action: string, outcome: string, extra: Record<string, string> = {}, bad = false) => {
    const fields = { service: 'bastion', outcome, actor: who.actor, ...extra };
    const { service, ...rest } = fields;
    const full = JSON.stringify({ ts: new Date(ts * 1000).toISOString(), service, action, ...rest, srcip: who.ip });
    drafts.push({ e: { ts, sid: 100_000, srcip: who.ip, user: '', action, program_name: '', full_log: full, fields }, bad });
  };
  const any = () => r.pick(learners);
  const day = () => T0 + r.int(43_200);
  const lesson = () => r.pick(['injection-sql', 'jwt-pieges', 'journaux-sources', 'regles-sigma', 'kerberos-bases']);
  const challenge = () => r.pick(['artefact-base64', 'lab-sqli-connexion', 'detecter-pulverisation', 'lab-idor-notes']);

  for (let k = 0; k < 60; k++) audit(day(), any(), 'auth.login', 'success');
  for (let k = 0; k < 40; k++) audit(day(), any(), 'auth.refresh', 'success'); // TRAP: "refresh" is not "refresh reuse".
  for (let k = 0; k < 18; k++) audit(day(), any(), 'auth.login', 'failure', { reason: r.pick(['bad_password', 'bad_password', 'unknown_user']) });
  for (let k = 0; k < 30; k++) audit(day(), any(), 'lesson.complete', 'success', { target: lesson() });
  // TRAP: learners clicking lessons they have not unlocked: "denied", every day, harmless.
  for (let k = 0; k < 14; k++) audit(day(), any(), 'lesson.complete', 'denied', { target: lesson(), reason: r.pick(['locked', 'not_added']) });
  for (let k = 0; k < 25; k++) audit(day(), any(), 'challenge.submit', 'failure', { target: challenge() });
  for (let k = 0; k < 8; k++) audit(day(), any(), 'challenge.submit', 'success', { target: challenge() });
  for (let k = 0; k < 4; k++) audit(day(), any(), 'challenge.submit', 'denied', { target: challenge(), reason: 'locked' });
  for (let k = 0; k < 20; k++) audit(day(), any(), 'note.read', 'success', { target: `n-${r.int(1 << 30).toString(16)}` });
  for (let k = 0; k < 10; k++) audit(day(), any(), 'note.create', 'success');
  // TRAP: the administrator reading the audit log ("admin" everywhere, all legitimate).
  const admin = { actor: 'u-adm1', ip: '10.3.0.2' };
  for (let k = 0; k < 4; k++) audit(day(), admin, 'admin.audit_read', 'success', { target: '/v1/admin/audit' });
  // TRAP: the nightly DAST scan of the CI pipeline probes admin routes and other users' notes on purpose.
  const dast = { actor: 'u-dast', ip: '10.0.9.50' };
  const night = T0 + 40_000;
  for (let k = 0; k < 6; k++) audit(night + k * 3, dast, 'authz.denied', 'denied', { target: r.pick(['/v1/admin/audit', '/v1/admin/audit/verify']), required: 'admin' });
  for (let k = 0; k < 3; k++) audit(night + 30 + k * 3, dast, 'authz.denied', 'denied', { target: `n-${r.int(1 << 30).toString(16)}`, resource: 'note' });

  // A stolen session: the old refresh token comes back from another place.
  const thief = { actor: r.pick(learners).actor, ip: `203.0.113.${String(2 + r.int(250))}` };
  for (let k = 0; k < 2; k++) audit(day(), thief, 'auth.refresh_reuse_detected', 'denied', {}, true);
  // Two learners exchange a flag.
  for (let k = 0; k < 2; k++) audit(day(), any(), 'challenge.flag_shared', 'denied', { target: challenge() }, true);
  // A learner probing the admin API (privilege escalation)…
  const probe = learners[3 + r.int(10)] ?? any();
  const tp = T0 + r.int(30_000);
  for (let k = 0; k < 4; k++) audit(tp + k * 20, probe, 'authz.denied', 'denied', { target: r.pick(['/v1/admin/audit', '/v1/admin/audit/verify']), required: 'admin' }, true);
  // …and another one walking other learners' note ids (IDOR).
  const idor = learners[15 + r.int(10)] ?? any();
  const ti = T0 + r.int(30_000);
  for (let k = 0; k < 6; k++) audit(ti + k * 7, idor, 'authz.denied', 'denied', { target: `n-${r.int(1 << 30).toString(16)}`, resource: 'note' }, true);

  const { events, bad } = finish(drafts);
  return { decoder: 'json', fields: BASTION_FIELDS, stock: BASTION_STOCK, events, unit: 'event', malicious: bad, minLevel: 10 };
}

export function buildWazuhDataset(kind: WazuhDatasetKind, seed: Buffer): WazuhDataset {
  switch (kind) {
    case 'wazuh-ssh':
      return wazuhSsh(seed);
    case 'wazuh-bastion':
      return wazuhBastion(seed);
  }
}

/**
 * The learner's view: one Wazuh alert per line (alerts.json shape), with the stock
 * rule each event reached. Labels never appear.
 */
export function toAlertLines(d: WazuhDataset): string {
  const stock = new Map(d.stock.map((s) => [s.id, s]));
  return d.events
    .map((e) => {
      const rule = stock.get(e.sid);
      return JSON.stringify({
        id: e.id,
        timestamp: new Date(e.ts * 1000).toISOString(),
        rule: rule ? { id: String(rule.id), level: rule.level, description: rule.description, groups: rule.groups } : null,
        decoder: { name: d.decoder },
        ...(e.program_name ? { predecoder: { program_name: e.program_name, hostname: 'srv-web-01' } } : {}),
        data: { srcip: e.srcip, ...(e.user ? { [e.userKey ?? 'srcuser']: e.user } : {}), ...(e.action ? { action: e.action } : {}), ...e.fields },
        full_log: e.full_log,
      });
    })
    .join('\n');
}
