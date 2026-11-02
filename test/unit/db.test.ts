import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AuditLog } from '../../src/audit.js';
import { isUniqueViolation, type Database } from '../../src/db.js';
import { openPostgres, toPositional } from '../../src/postgres.js';
import { dropAuditTrigger, testDb, withLatency } from '../helpers.js';

/**
 * The async database layer (ADR 0020, 0021), against SQLite or, with TEST_DATABASE_URL,
 * PostgreSQL. One SQLite connection serves every request, so a transaction must keep other
 * requests' statements out of it: interleaved, they would commit or roll back with it.
 */
describe('database layer', () => {
  const user = async (db: Database, id: string) =>
    db.run('INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)', id, `${id}@example.test`, 'x', 0);

  it('keeps other requests out of an open transaction: a rollback takes only its own writes', async () => {
    const db = testDb();
    let inside!: () => void;
    const paused = new Promise<void>((resolve) => {
      inside = resolve;
    });
    const failing = db.transaction(async (tx) => {
      await user(tx, 'in-tx');
      inside();
      // While this transaction waits (a KMS call, a slow query), another request writes.
      await new Promise((resolve) => setTimeout(resolve, 20));
      throw new Error('boom');
    });
    await paused;
    const outside = user(db, 'outside');
    await expect(failing).rejects.toThrow('boom');
    await outside;
    expect(await db.many('SELECT id FROM users ORDER BY id')).toEqual([{ id: 'outside' }]);
  });

  it('refuses the outer handle inside a transaction instead of deadlocking', async () => {
    const db = testDb();
    await expect(db.transaction(async () => db.one('SELECT 1'))).rejects.toThrow(/inside its own transaction/);
    // The failed transaction rolled back and released the connection.
    expect(await db.one('SELECT 1 AS ok')).toEqual({ ok: 1 });
  });

  it('refuses a transaction handle kept after the transaction ended, and nested transactions', async () => {
    const db = testDb();
    let leaked: Parameters<Parameters<typeof db.transaction>[0]>[0] | undefined;
    await db.transaction(async (tx) => {
      leaked = tx;
      await expect(tx.transaction(async () => Promise.resolve())).rejects.toThrow(/nested/);
    });
    await expect(leaked?.one('SELECT 1') ?? Promise.resolve()).rejects.toThrow(/after the transaction ended/);
  });

  it('reports how many rows a write touched, and recognises a UNIQUE violation', async () => {
    const db = testDb();
    expect(await user(db, 'a')).toEqual({ changes: 1 });
    expect(await db.run('UPDATE users SET role = ? WHERE id = ?', 'admin', 'nobody')).toEqual({ changes: 0 });
    const dup = await user(db, 'a').catch((err: unknown) => err);
    expect(isUniqueViolation(dup)).toBe(true);
    expect(isUniqueViolation(new Error('something else'))).toBe(false);
  });

  it('keeps the audit chain linear under concurrent appends', async () => {
    // With a remote-like database, appends started together interleave between reading
    // the chain head and inserting: without one transaction per append they fork the chain.
    const log = new AuditLog(withLatency(testDb()), randomBytes(32));
    await Promise.all(Array.from({ length: 20 }, (_, i) => log.record({ action: 'note.read', outcome: 'success', actorId: `u${String(i)}` })));
    expect(await log.verify()).toEqual({ valid: true, checked: 20, firstInvalidSeq: null });
  });

  // 1005 appends, each a transaction behind the audit lock: seconds on a networked PostgreSQL.
  // Under SERIALIZABLE alone the chain stays correct, but appends that read the same head
  // abort and retry; with a full pool, 82 of 300 ran out of retries (lost audit events,
  // failed requests) when this lock was removed. With it they queue: none fails.
  it.skipIf(!process.env.TEST_DATABASE_URL)('loses no audit append under load on PostgreSQL', { timeout: 60_000 }, async () => {
    const db = openPostgres(process.env.TEST_DATABASE_URL ?? '', { schema: `t_${randomBytes(8).toString('hex')}`, poolSize: 20, migrate: true });
    const log = new AuditLog(db, randomBytes(32));
    const results = await Promise.allSettled(Array.from({ length: 300 }, () => log.record({ action: 'note.read', outcome: 'success' })));
    expect(results.filter((r) => r.status === 'rejected')).toEqual([]);
    expect(await log.verify()).toEqual({ valid: true, checked: 300, firstInvalidSeq: null });
    await db.close();
  });

  it('verifies a chain longer than one page', { timeout: 60_000 }, async () => {
    const db = testDb();
    const log = new AuditLog(db, randomBytes(32));
    for (let i = 0; i < 1005; i++) await log.record({ action: 'note.read', outcome: 'success' });
    expect(await log.verify()).toEqual({ valid: true, checked: 1005, firstInvalidSeq: null });
    await dropAuditTrigger(db, 'update');
    await db.run("UPDATE audit_log SET outcome = 'failure' WHERE seq = 1003");
    expect(await log.verify()).toEqual({ valid: false, checked: 1002, firstInvalidSeq: 1003 });
  });

  it('keeps a count-then-insert under its cap when transactions race', async () => {
    // The shape of the passkey and login-challenge caps. On PostgreSQL the losers of the
    // race fail with a serialization error and run again; on SQLite they wait their turn.
    const db = withLatency(testDb());
    await user(db, 'owner');
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        db.transaction(async (tx) => {
          const { n } = (await tx.one('SELECT COUNT(*) AS n FROM module_choices WHERE user_id = ?', 'owner')) as { n: number };
          if (n >= 3) return false;
          await tx.run('INSERT INTO module_choices (user_id, module_id, added_at) VALUES (?, ?, ?)', 'owner', `m${String(i)}`, 0);
          return true;
        }),
      ),
    );
    expect(results.filter(Boolean)).toHaveLength(3);
    expect(await db.one('SELECT COUNT(*) AS n FROM module_choices WHERE user_id = ?', 'owner')).toEqual({ n: 3 });
  });

  it('returns rows of the same shape on both engines', async () => {
    const db = testDb();
    await user(db, 'shape');
    const secret = Uint8Array.from([0, 1, 2, 250, 255]);
    await db.run('INSERT INTO user_mfa (user_id, key_id, secret, created_at) VALUES (?, ?, ?, ?)', 'shape', 'k1', secret, Date.now());
    const row = (await db.one('SELECT secret, last_step, created_at FROM user_mfa WHERE user_id = ?', 'shape')) as Record<string, unknown>;
    // BYTEA as a plain Uint8Array, BIGINT and COUNT as numbers, never strings.
    expect(row.secret).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(row.secret as Uint8Array).equals(Buffer.from(secret))).toBe(true);
    expect(typeof row.created_at).toBe('number');
    expect(await db.one('SELECT COUNT(*) AS n FROM user_mfa WHERE secret = ?', secret)).toEqual({ n: 1 });
  });

  it('compares e-mails and pseudonyms without regard to case', async () => {
    const db = testDb();
    await user(db, 'Case');
    expect(await db.one('SELECT id FROM users WHERE email = ?', 'CASE@EXAMPLE.TEST')).toEqual({ id: 'Case' });
    await db.run('UPDATE users SET display_name = ? WHERE id = ?', 'Alice', 'Case');
    await user(db, 'other');
    const dup = await db.run('UPDATE users SET display_name = ? WHERE id = ?', 'ALICE', 'other').catch((err: unknown) => err);
    expect(isUniqueViolation(dup)).toBe(true);
  });
});

describe('PostgreSQL placeholders', () => {
  it('numbers ? outside quotes only', () => {
    expect(toPositional("SELECT a FROM t WHERE b = ? AND c = '?' AND \"d?\" = ?")).toEqual({
      text: "SELECT a FROM t WHERE b = $1 AND c = '?' AND \"d?\" = $2",
      count: 2,
    });
  });

  it('refuses $n placeholders and unterminated quotes', () => {
    expect(() => toPositional('SELECT $1')).toThrow(/use \? placeholders/);
    expect(() => toPositional("SELECT 'oops")).toThrow(/unterminated/);
  });

  it('recognises the PostgreSQL unique-violation code', () => {
    expect(isUniqueViolation(Object.assign(new Error('duplicate key value'), { code: '23505' }))).toBe(true);
    expect(isUniqueViolation(Object.assign(new Error('deadlock'), { code: '40P01' }))).toBe(false);
  });
});
