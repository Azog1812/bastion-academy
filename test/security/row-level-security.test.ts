import { describe, expect, it } from 'vitest';
import { assertAppRole } from '../../src/postgres.js';
import { auditActions, newUser, setup, type TestContext } from '../helpers.js';

/**
 * Row-level security (ADR 0022), PostgreSQL only: the second IDOR barrier. Every note query
 * already carries its owner_id (invariant 2, Semgrep rule); these tests play the bug that
 * forgets it, and the injected SQL that tries to get out of the API's role.
 */
describe.skipIf(!process.env.TEST_DATABASE_URL)('row-level security on notes', () => {
  const twoNotes = async (t: TestContext) => {
    const alice = await newUser(t);
    const mallory = await newUser(t);
    const a = await t.http.post('/v1/notes').set(alice.auth).send({ title: 'alice', body: "alice's secret" }).expect(201);
    const m = await t.http.post('/v1/notes').set(mallory.auth).send({ title: 'mallory', body: 'mine' }).expect(201);
    return { alice, mallory, aliceNote: a.body.id as string, malloryNote: m.body.id as string };
  };

  it('hides other owners’ notes from a query that forgot its owner_id', async () => {
    const t = setup();
    const { mallory, aliceNote, malloryNote } = await twoNotes(t);
    // The bug: "SELECT … WHERE id = ?" with no owner_id, on Mallory's request.
    const leaked = await t.appDb.transaction((tx) => tx.one('SELECT id FROM notes WHERE id = ?', aliceNote), { user: mallory.id });
    expect(leaked).toBeUndefined();
    expect(await t.appDb.transaction((tx) => tx.many('SELECT id FROM notes'), { user: mallory.id })).toEqual([{ id: malloryNote }]);
    // The administrator still sees both: the policy binds the API's role, not the data.
    expect(await t.db.one('SELECT COUNT(*) AS n FROM notes')).toEqual({ n: 2 });
  });

  it('refuses writes to someone else’s notes, and notes written in someone else’s name', async () => {
    const t = setup();
    const { alice, mallory, aliceNote, malloryNote } = await twoNotes(t);
    const asMallory = <T>(fn: Parameters<typeof t.appDb.transaction<T>>[0]) => t.appDb.transaction(fn, { user: mallory.id });
    expect(await asMallory((tx) => tx.run('UPDATE notes SET version = version + 1 WHERE id = ?', aliceNote))).toEqual({ changes: 0 });
    expect(await asMallory((tx) => tx.run('DELETE FROM notes WHERE id = ?', aliceNote))).toEqual({ changes: 0 });
    // Giving her own note to Alice, or planting one in Alice's account: WITH CHECK refuses both.
    await expect(asMallory((tx) => tx.run('UPDATE notes SET owner_id = ? WHERE id = ?', alice.id, malloryNote))).rejects.toThrow(/row-level security/);
    await expect(
      asMallory((tx) =>
        tx.run('INSERT INTO notes (id, owner_id, key_id, wrapped_dek, iv, tag, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', 'planted', alice.id, 'k1', new Uint8Array(1), new Uint8Array(1), new Uint8Array(1), new Uint8Array(1), 0, 0),
      ),
    ).rejects.toThrow(/row-level security/);
    await t.http.get(`/v1/notes/${aliceNote}`).set(alice.auth).expect(200);
  });

  it('shows nothing without a user context, and the context never outlives its transaction', async () => {
    const t = setup();
    const { alice } = await twoNotes(t);
    expect(await t.appDb.many('SELECT id FROM notes')).toEqual([]);
    // A pooled connection that just served Alice carries nothing into the next statement.
    for (let i = 0; i < 5; i++) {
      await t.appDb.transaction((tx) => tx.many('SELECT id FROM notes'), { user: alice.id });
      expect(await t.appDb.many('SELECT id FROM notes')).toEqual([]);
      expect(await t.appDb.one("SELECT current_setting('app.user_id', true) AS v")).not.toEqual({ v: alice.id });
    }
  });

  it('keeps the API role boxed: no way back to the owner, no schema change, append-only audit log', async () => {
    const t = setup();
    await twoNotes(t);
    // RESET ROLE goes back to the connection's role parameter, which is bastion_app itself.
    expect(await t.appDb.one('SELECT current_user AS u')).toEqual({ u: 'bastion_app' });
    await t.appDb.run('RESET ROLE');
    expect(await t.appDb.one('SELECT current_user AS u')).toEqual({ u: 'bastion_app' });
    await expect(t.appDb.run('SET ROLE postgres')).rejects.toThrow(/permission denied/);
    await expect(t.appDb.run('ALTER TABLE notes DISABLE ROW LEVEL SECURITY')).rejects.toThrow(/must be owner/);
    await expect(t.appDb.run('DROP POLICY notes_owner ON notes')).rejects.toThrow(/must be owner/);
    await expect(t.appDb.run('DROP TRIGGER audit_no_update ON audit_log')).rejects.toThrow(/must be owner/);
    await expect(t.appDb.run("UPDATE audit_log SET outcome = 'failure'")).rejects.toThrow(/permission denied/);
    await expect(t.appDb.run('TRUNCATE audit_log')).rejects.toThrow(/permission denied/);
  });

  it('still records a probe of someone else’s note, through an existence-only function', async () => {
    const t = setup();
    const { mallory, aliceNote } = await twoNotes(t);
    const res = await t.http.get(`/v1/notes/${aliceNote}`).set(mallory.auth).expect(404);
    expect(res.body.message).toBe('Note not found');
    expect(await auditActions(t)).toContain('authz.denied:denied');
    // The function answers yes or no; the API role cannot read the row through it.
    expect(await t.appDb.one('SELECT note_exists(?) AS e', aliceNote)).toEqual({ e: true });
  });

  it('refuses to start the API under a role that would skip row-level security', async () => {
    const t = setup();
    await expect(assertAppRole(t.appDb)).resolves.toBeUndefined();
    // The owner (here also a superuser): every policy would be skipped. Fail closed at boot.
    await expect(assertAppRole(t.db)).rejects.toThrow(/skips row-level security/);
    // A schema the migration job has not brought up to date.
    await t.db.run('UPDATE schema_version SET version = version - 1');
    await expect(assertAppRole(t.appDb)).rejects.toThrow(/run the migration/);
  });
});
