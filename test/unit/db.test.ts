import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AuditLog } from '../../src/audit.js';
import { isUniqueViolation, openDatabase } from '../../src/db.js';
import { withLatency } from '../helpers.js';

/**
 * The async database layer (ADR 0020). One SQLite connection serves every request, so a
 * transaction must keep other requests' statements out of it: interleaved, they would
 * commit or roll back with it.
 */
describe('database layer', () => {
  const user = async (db: ReturnType<typeof openDatabase>, id: string) =>
    db.run('INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)', id, `${id}@example.test`, 'x', 0);

  it('keeps other requests out of an open transaction: a rollback takes only its own writes', async () => {
    const db = openDatabase(':memory:');
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
    const db = openDatabase(':memory:');
    await expect(db.transaction(async () => db.one('SELECT 1'))).rejects.toThrow(/inside its own transaction/);
    // The failed transaction rolled back and released the connection.
    expect(await db.one('SELECT 1 AS ok')).toEqual({ ok: 1 });
  });

  it('refuses a transaction handle kept after the transaction ended, and nested transactions', async () => {
    const db = openDatabase(':memory:');
    let leaked: Parameters<Parameters<typeof db.transaction>[0]>[0] | undefined;
    await db.transaction(async (tx) => {
      leaked = tx;
      await expect(tx.transaction(async () => Promise.resolve())).rejects.toThrow(/nested/);
    });
    await expect(leaked?.one('SELECT 1') ?? Promise.resolve()).rejects.toThrow(/after the transaction ended/);
  });

  it('reports how many rows a write touched, and recognises a UNIQUE violation', async () => {
    const db = openDatabase(':memory:');
    expect(await user(db, 'a')).toEqual({ changes: 1 });
    expect(await db.run('UPDATE users SET role = ? WHERE id = ?', 'admin', 'nobody')).toEqual({ changes: 0 });
    const dup = await user(db, 'a').catch((err: unknown) => err);
    expect(isUniqueViolation(dup)).toBe(true);
    expect(isUniqueViolation(new Error('something else'))).toBe(false);
  });

  it('keeps the audit chain linear under concurrent appends', async () => {
    // With a remote-like database, appends started together interleave between reading
    // the chain head and inserting: without one transaction per append they fork the chain.
    const log = new AuditLog(withLatency(openDatabase(':memory:')), randomBytes(32));
    await Promise.all(Array.from({ length: 20 }, (_, i) => log.record({ action: 'note.read', outcome: 'success', actorId: `u${String(i)}` })));
    expect(await log.verify()).toEqual({ valid: true, checked: 20, firstInvalidSeq: null });
  });

  it('verifies a chain longer than one page', async () => {
    const db = openDatabase(':memory:');
    const log = new AuditLog(db, randomBytes(32));
    for (let i = 0; i < 1005; i++) await log.record({ action: 'note.read', outcome: 'success' });
    expect(await log.verify()).toEqual({ valid: true, checked: 1005, firstInvalidSeq: null });
    await db.run('DROP TRIGGER audit_no_update');
    await db.run("UPDATE audit_log SET outcome = 'failure' WHERE seq = 1003");
    expect(await log.verify()).toEqual({ valid: false, checked: 1002, firstInvalidSeq: 1003 });
  });
});
