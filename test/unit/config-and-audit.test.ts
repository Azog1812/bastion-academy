import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AuditLog } from '../../src/audit.js';
import { loadConfig } from '../../src/config.js';
import { openDatabase } from '../../src/db.js';
import { testEnv } from '../helpers.js';

describe('configuration fails closed', () => {
  it('loads a valid configuration and freezes it', () => {
    const cfg = loadConfig(testEnv());
    expect(cfg.ENCRYPTION_KEYS.get('k1')).toHaveLength(32);
    expect(Object.isFrozen(cfg)).toBe(true);
  });

  it.each([
    ['missing JWT secret', { JWT_SECRET: '' }, 'JWT_SECRET'],
    ['short JWT secret', { JWT_SECRET: randomBytes(16).toString('base64') }, 'at least 32 bytes'],
    ['placeholder secret', { JWT_SECRET: 'change-me-change-me-change-me-change-me-12345' }, 'placeholder'],
    ['16-byte AES key', { ENCRYPTION_KEYS: `k1:${randomBytes(16).toString('base64')}` }, 'exactly 32 bytes'],
    ['malformed key ring', { ENCRYPTION_KEYS: 'nokey' }, 'invalid key entry'],
    ['empty key ring', { ENCRYPTION_KEYS: ' , ' }, 'at least one'],
    ['active key not in ring', { ACTIVE_KEY_ID: 'k9' }, 'ACTIVE_KEY_ID'],
    ['weak scrypt in production', { NODE_ENV: 'production' }, 'SCRYPT_LOG_N'],
  ])('refuses to start with a %s', (_name, override, message) => {
    expect(() => loadConfig(testEnv(override))).toThrow(message);
  });

  it('reads secrets from files (Docker / Kubernetes secrets convention)', () => {
    const env = testEnv();
    const secret = env.JWT_SECRET!;
    delete env.JWT_SECRET;
    const files: Record<string, string> = { '/run/secrets/jwt': `${secret}\n` };
    const cfg = loadConfig({ ...env, JWT_SECRET_FILE: '/run/secrets/jwt' }, (p) => files[p]!);
    expect(cfg.JWT_SECRET.toString('base64')).toBe(secret);
  });

  it('refuses ambiguous or unreadable secret files', () => {
    expect(() => loadConfig(testEnv({ JWT_SECRET_FILE: '/x' }), () => 'y')).toThrow('not both');
    const env = testEnv();
    delete env.JWT_SECRET;
    expect(() =>
      loadConfig({ ...env, JWT_SECRET_FILE: '/missing' }, () => {
        throw new Error('ENOENT');
      }),
    ).toThrow('cannot read secret file');
  });

  it('never echoes secret values in the error', () => {
    const bad = randomBytes(8).toString('base64');
    try {
      loadConfig(testEnv({ JWT_SECRET: bad }));
      expect.unreachable();
    } catch (err) {
      expect(String(err)).not.toContain(bad);
    }
  });
});

describe('tamper-evident audit log', () => {
  const make = () => {
    const db = openDatabase(':memory:');
    const key = randomBytes(32);
    const log = new AuditLog(db, key);
    for (let i = 0; i < 5; i++) log.record({ action: 'note.read', outcome: 'success', actorId: `u${i}` });
    return { db, key, log };
  };

  it('verifies an untouched chain', () => {
    expect(make().log.verify()).toEqual({ valid: true, checked: 5, firstInvalidSeq: null });
  });

  it('blocks UPDATE and DELETE at the database level', () => {
    const { db } = make();
    expect(() => db.prepare("UPDATE audit_log SET outcome = 'failure' WHERE seq = 2").run()).toThrow('append-only');
    expect(() => db.prepare('DELETE FROM audit_log WHERE seq = 2').run()).toThrow('append-only');
  });

  it('pinpoints a modified entry even if the attacker drops the triggers', () => {
    const { db, log } = make();
    db.exec('DROP TRIGGER audit_no_update');
    db.prepare("UPDATE audit_log SET actor_id = 'someone-else' WHERE seq = 3").run();
    expect(log.verify()).toEqual({ valid: false, checked: 2, firstInvalidSeq: 3 });
  });

  it('detects a deleted entry (broken link)', () => {
    const { db, log } = make();
    db.exec('DROP TRIGGER audit_no_delete');
    db.prepare('DELETE FROM audit_log WHERE seq = 2').run();
    expect(log.verify().firstInvalidSeq).toBe(3);
  });

  it('cannot be re-forged without the HMAC key', () => {
    const { db } = make();
    const attacker = new AuditLog(db, randomBytes(32));
    expect(attacker.verify().valid).toBe(false);
  });

  it('paginates newest first', () => {
    const { log } = make();
    const page = log.list(2);
    expect(page.map((r) => r.seq)).toEqual([5, 4]);
    expect(log.list(2, 4).map((r) => r.seq)).toEqual([3, 2]);
  });
});
