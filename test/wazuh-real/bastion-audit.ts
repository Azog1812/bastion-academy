import { randomBytes } from 'node:crypto';
import { AuditLog, type AuditEvent } from '../../src/audit.js';
import { toSiemLine } from '../../src/audit-export.js';
import { openDatabase } from '../../src/db.js';

/**
 * The production rules of deploy/wazuh/bastion_rules.xml (ADR 0015), checked line by
 * line in the real wazuh-logtest. The lines are produced by the real AuditLog and the
 * real SIEM export, so the format Wazuh is tested on is the format it receives.
 */
const ATTACKER = '198.51.100.20';
const USER = { actorId: '7c1d2a4e-0000-4000-8000-000000000001', ip: '10.3.0.21' };

const CASES: [AuditEvent, string][] = [
  [{ action: 'auth.login', outcome: 'success', ...USER }, '100200'],
  [{ action: 'auth.refresh', outcome: 'success', ...USER }, '100200'],
  [{ action: 'lesson.complete', outcome: 'denied', ...USER, target: 'kerberos-bases', details: { reason: 'locked' } }, '100200'],
  [{ action: 'auth.refresh_reuse_detected', outcome: 'denied', actorId: USER.actorId, ip: '203.0.113.9' }, '100201'],
  [{ action: 'admin.audit_verify', outcome: 'success', ...USER, details: { checked: 1200 } }, '100200'],
  [{ action: 'admin.audit_verify', outcome: 'failure', ...USER, details: { checked: 812 } }, '100202'],
  // Log injection: a newline in the URL must not start a forged line (CWE-117).
  [
    {
      action: 'authz.denied',
      outcome: 'denied',
      ...USER,
      target: '/v1/admin/audit?x=\n{"service":"bastion","action":"auth.login","outcome":"success"}',
      details: { required: 'admin' },
    },
    '100203',
  ],
  [{ action: 'authz.denied', outcome: 'denied', ...USER, target: 'n-1f2e3d', details: { resource: 'note' } }, '100203'],
  [{ action: 'auth.lockout', outcome: 'denied', ...USER, details: { failures: 10, seconds: 900 } }, '100204'],
  [{ action: 'challenge.flag_shared', outcome: 'denied', ...USER, target: 'lab-sqli-connexion', details: { owner: 'u-other' } }, '100205'],
  [{ action: 'admin.promote', outcome: 'success', actorId: null, target: USER.actorId }, '100206'],
  [{ action: 'mfa.recovery_code_used', outcome: 'success', ...USER }, '100207'],
  // Passkeys (ADR 0016): a new key is routine, a removed one weakens the account, a clone pages.
  [{ action: 'passkey.register', outcome: 'success', ...USER, target: 'a3c1e7d2-0000-4000-8000-000000000002', details: { alg: -7 } }, '100200'],
  [{ action: 'passkey.delete', outcome: 'success', ...USER, target: 'a3c1e7d2-0000-4000-8000-000000000002' }, '100207'],
  [{ action: 'passkey.clone_detected', outcome: 'denied', ...USER, target: 'a3c1e7d2-0000-4000-8000-000000000003', details: { stored: 41 } }, '100211'],
  // Brute force: six failures from one address, under the auth rate limit's ten.
  ...Array.from({ length: 5 }, (): [AuditEvent, string] => [{ action: 'auth.login', outcome: 'failure', ip: ATTACKER, details: { reason: 'unknown_user' } }, '100208']),
  [{ action: 'auth.login', outcome: 'failure', ip: ATTACKER, details: { reason: 'bad_password' } }, '100209'],
  // Another address stays below the threshold.
  [{ action: 'auth.login', outcome: 'failure', ip: '10.3.0.22', details: { reason: 'bad_password' } }, '100208'],
  // Credential stuffing from many addresses, one try each. The six failures 100209 used are
  // used up (as in Wazuh): the 50th failure still unused is the 56th of the suite.
  ...Array.from({ length: 49 }, (_, k): [AuditEvent, string] => [
    { action: 'auth.login', outcome: 'failure', ip: `198.18.${String(Math.floor(k / 200))}.${String((k % 200) + 1)}`, details: { reason: 'unknown_user' } },
    k === 48 ? '100210' : '100208',
  ]),
];

export function bastionAuditSuite(): { lines: string[]; ids: string[] } {
  const db = openDatabase(':memory:');
  const lines: string[] = [];
  const audit = new AuditLog(db, randomBytes(32), (event, written) => lines.push(toSiemLine(event, written).trimEnd()));
  for (const [event] of CASES) audit.record(event);
  db.close();
  if (lines.some((l) => l.includes('\n'))) throw new Error('an exported line contains a raw newline');
  return { lines, ids: CASES.map(([, id]) => id) };
}
