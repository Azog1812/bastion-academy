import { mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { describe, expect, it } from 'vitest';
import { auditFileExport, toSiemLine } from '../../src/audit-export.js';
import { newUser, setup } from '../helpers.js';

const silent = pino({ level: 'silent' });
const dir = () => mkdtempSync(join(tmpdir(), 'bastion-siem-'));
const at = { seq: 42, ts: Date.parse('2026-10-31T12:00:00Z') };

describe('SIEM export of the audit log (ADR 0015)', () => {
  it('writes one flat JSON object per entry, in the shape the Wazuh rules expect', () => {
    const line = toSiemLine({ action: 'authz.denied', outcome: 'denied', actorId: 'u-1', ip: '10.3.0.4', target: '/v1/admin/audit', details: { required: 'admin' } }, at);
    expect(line.endsWith('\n')).toBe(true);
    expect(JSON.parse(line)).toEqual({
      ts: '2026-10-31T12:00:00.000Z',
      service: 'bastion',
      seq: 42,
      action: 'authz.denied',
      outcome: 'denied',
      actor: 'u-1',
      target: '/v1/admin/audit',
      srcip: '10.3.0.4',
      required: 'admin',
    });
    // Absent fields are left out rather than sent as null.
    expect(JSON.parse(toSiemLine({ action: 'auth.login', outcome: 'failure' }, at))).not.toHaveProperty('actor');
  });

  it('cannot be used to forge lines or fields (log injection, CWE-117)', () => {
    const line = toSiemLine(
      {
        action: 'authz.denied',
        outcome: 'denied',
        target: '/x\n{"service":"bastion","action":"admin.promote"}\r\n',
        details: { action: 'auth.login', service: 'other', seq: 1, srcip: '1.2.3.4', reason: 'x' },
      },
      at,
    );
    // One line: control characters are escaped by JSON.stringify.
    expect(line.slice(0, -1)).not.toMatch(/[\r\n]/);
    // Details never overwrite the line's own keys.
    expect(JSON.parse(line)).toMatchObject({ action: 'authz.denied', service: 'bastion', seq: 42, reason: 'x' });
    expect(JSON.parse(line)).not.toHaveProperty('srcip');
  });

  it('appends in order, to a file only its owner can read', () => {
    const path = join(dir(), 'audit.json');
    const exp = auditFileExport(path, silent);
    exp.write({ action: 'auth.login', outcome: 'success' }, { seq: 1, ts: at.ts });
    exp.write({ action: 'auth.logout', outcome: 'success' }, { seq: 2, ts: at.ts });
    exp.close();
    const lines = readFileSync(path, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as { seq: number });
    expect(lines.map((l) => l.seq)).toEqual([1, 2]);
    // POSIX permissions: not meaningful on Windows.
    if (process.platform !== 'win32') expect(statSync(path).mode & 0o777).toBe(0o600);
    // Reopening appends: a restart never truncates what Wazuh has not read yet.
    const again = auditFileExport(path, silent);
    again.write({ action: 'auth.login', outcome: 'success' }, { seq: 3, ts: at.ts });
    again.close();
    expect(readFileSync(path, 'utf8').trim().split('\n')).toHaveLength(3);
  });

  it('rotates by size and keeps the previous file', () => {
    const path = join(dir(), 'audit.json');
    const exp = auditFileExport(path, silent, undefined, 400);
    for (let seq = 1; seq <= 6; seq++) exp.write({ action: 'auth.login', outcome: 'success', target: 'x'.repeat(100) }, { seq, ts: at.ts });
    exp.close();
    const seqs = (p: string) => readFileSync(p, 'utf8').trim().split('\n').map((l) => (JSON.parse(l) as { seq: number }).seq);
    expect(statSync(path).size).toBeLessThanOrEqual(400);
    expect([...seqs(`${path}.1`), ...seqs(path)]).toEqual(seqs(`${path}.1`).concat(seqs(path)).sort((a, b) => a - b));
    expect(seqs(path).at(-1)).toBe(6);
  });

  it('counts a failed write and carries on: the platform never stops for its SIEM copy', () => {
    const d = dir();
    const path = join(d, 'audit.json');
    // The rotation target is a non-empty directory: the rename fails.
    mkdirSync(`${path}.1`);
    writeFileSync(join(`${path}.1`, 'keep'), 'x');
    let failures = 0;
    const exp = auditFileExport(path, silent, () => failures++, 200);
    expect(() => {
      for (let seq = 1; seq <= 4; seq++) exp.write({ action: 'auth.login', outcome: 'success', target: 'x'.repeat(100) }, { seq, ts: at.ts });
    }).not.toThrow();
    exp.close();
    expect(failures).toBeGreaterThan(0);
    // Later lines still land in the file: the failed rotation reopened it.
    expect(readFileSync(path, 'utf8')).toContain('"seq":4');
  });

  it('refuses to start with a path it cannot open (fail closed at boot)', () => {
    expect(() => auditFileExport(join(dir(), 'missing', 'audit.json'), silent)).toThrow();
  });

  it('is fed by the audit log of the running app, with the database sequence', async () => {
    const path = join(dir(), 'audit.json');
    const t = setup({ env: { AUDIT_EXPORT_FILE: path } });
    await newUser(t);
    const lines = readFileSync(path, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as { action: string; seq: number; service: string });
    const rows = t.services.audit.list(100).reverse();
    expect(lines.map((l) => l.seq)).toEqual(rows.map((r) => r.seq));
    expect(lines.map((l) => l.action)).toEqual(rows.map((r) => r.action));
    expect(lines.every((l) => l.service === 'bastion')).toBe(true);
  });
});
