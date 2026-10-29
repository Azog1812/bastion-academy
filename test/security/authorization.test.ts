import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { auditActions, newUser, setup, STRONG_PASSWORD, type TestContext } from '../helpers.js';

async function aliceWithNote(t: TestContext) {
  const alice = await newUser(t, 'alice@example.test');
  const note = await t.http.post('/v1/notes').set(alice.auth).send({ title: 'private', body: "alice's secret" }).expect(201);
  return { alice, noteId: note.body.id as string };
}

describe('object-level authorization (IDOR / OWASP API1:2023)', () => {
  it('owner can do full CRUD with optimistic concurrency', async () => {
    const t = setup();
    const { alice, noteId } = await aliceWithNote(t);

    const got = await t.http.get(`/v1/notes/${noteId}`).set(alice.auth).expect(200);
    expect(got.body).toMatchObject({ title: 'private', body: "alice's secret", version: 1 });

    const upd = await t.http.put(`/v1/notes/${noteId}`).set(alice.auth).send({ title: 'renamed', body: 'v2', version: 1 }).expect(200);
    expect(upd.body.version).toBe(2);

    // Stale write (lost update) is refused.
    await t.http.put(`/v1/notes/${noteId}`).set(alice.auth).send({ title: 'stale', body: 'v?', version: 1 }).expect(409);

    const list = await t.http.get('/v1/notes').set(alice.auth).expect(200);
    expect(list.body.total).toBe(1);
    expect(list.body.items[0]).not.toHaveProperty('body');

    await t.http.delete(`/v1/notes/${noteId}`).set(alice.auth).expect(204);
    await t.http.get(`/v1/notes/${noteId}`).set(alice.auth).expect(404);
  });

  it("another user can neither read, modify nor delete it — and can't tell it exists", async () => {
    const t = setup();
    const { alice, noteId } = await aliceWithNote(t);
    const mallory = await newUser(t, 'mallory@example.test');

    const read = await t.http.get(`/v1/notes/${noteId}`).set(mallory.auth).expect(404);
    const missing = await t.http.get('/v1/notes/00000000-0000-4000-8000-000000000000').set(mallory.auth).expect(404);
    expect(read.body.message).toBe(missing.body.message); // indistinguishable from a non-existent id

    await t.http.put(`/v1/notes/${noteId}`).set(mallory.auth).send({ title: 'pwned', body: 'x', version: 1 }).expect(404);
    await t.http.delete(`/v1/notes/${noteId}`).set(mallory.auth).expect(404);

    const list = await t.http.get('/v1/notes').set(mallory.auth).expect(200);
    expect(list.body.total).toBe(0);

    // Alice's note is intact.
    const intact = await t.http.get(`/v1/notes/${noteId}`).set(alice.auth).expect(200);
    expect(intact.body).toMatchObject({ title: 'private', version: 1 });

    // Probing is logged for detection.
    expect(auditActions(t).filter((a) => a === 'authz.denied:denied')).toHaveLength(3);
  });

  it('paginates within the owner scope only', async () => {
    const t = setup();
    const a = await newUser(t);
    const b = await newUser(t);
    for (let i = 0; i < 5; i++) await t.http.post('/v1/notes').set(a.auth).send({ title: `a${i}`, body: '' });
    await t.http.post('/v1/notes').set(b.auth).send({ title: 'b', body: '' });
    const page = await t.http.get('/v1/notes?limit=2&offset=2').set(a.auth).expect(200);
    expect(page.body).toMatchObject({ total: 5, limit: 2, offset: 2 });
    expect(page.body.items).toHaveLength(2);
  });
});

describe('function-level authorization (OWASP API5:2023)', () => {
  it('a regular user cannot reach admin endpoints, and the attempt is audited', async () => {
    const t = setup();
    const user = await newUser(t);
    await t.http.get('/v1/admin/audit').set(user.auth).expect(403);
    await t.http.get('/v1/admin/audit/verify').set(user.auth).expect(403);
    expect(auditActions(t)).toContain('authz.denied:denied');
  });

  it('there is no HTTP path to become admin (mass assignment)', async () => {
    const t = setup();
    const res = await t.http
      .post('/v1/auth/register')
      .send({ email: 'sneaky@example.test', password: STRONG_PASSWORD, role: 'admin' })
      .expect(400);
    expect(res.body.error).toBe('validation_error');
    expect(res.body.issues[0].message).toMatch(/[Uu]nrecognized key/);
  });

  it('an admin can read and verify the audit trail; a demotion applies instantly', async () => {
    const t = setup();
    const admin = await newUser(t, 'root@example.test');
    // Promotion happens out-of-band (operator CLI). It bumps token_version, so log in again.
    t.db.prepare("UPDATE users SET role = 'admin', token_version = token_version + 1 WHERE id = ?").run(admin.id);
    await t.http.get('/v1/admin/audit').set(admin.auth).expect(401);
    const login = await t.http.post('/v1/auth/login').send({ email: admin.email, password: STRONG_PASSWORD }).expect(200);
    const auth = { Authorization: `Bearer ${login.body.accessToken as string}` };

    const audit = await t.http.get('/v1/admin/audit?limit=5').set(auth).expect(200);
    expect(audit.body.items.length).toBeGreaterThan(0);
    expect(audit.body.items[0]).toHaveProperty('hash');

    const verify = await t.http.get('/v1/admin/audit/verify').set(auth).expect(200);
    expect(verify.body.valid).toBe(true);

    // Role is read from the DB on each request, not trusted from the token.
    t.db.prepare("UPDATE users SET role = 'user' WHERE id = ?").run(admin.id);
    await t.http.get('/v1/admin/audit').set(auth).expect(403);
  });
});

describe('data at rest', () => {
  it('stores no plaintext: a raw database dump reveals nothing', async () => {
    const t = setup();
    const { noteId } = await aliceWithNote(t);
    const row = t.db.prepare('SELECT * FROM notes WHERE id = ?').get(noteId) as Record<string, unknown>;
    const dump = Object.values(row)
      .map((v) => (v instanceof Uint8Array ? Buffer.from(v).toString('latin1') : String(v)))
      .join('|');
    expect(dump).not.toContain("alice's secret");
    expect(dump).not.toContain('private');
  });

  it('a DB-level attacker who moves a ciphertext to their own account gets nothing', async () => {
    const t = setup();
    const { noteId } = await aliceWithNote(t);
    const mallory = await newUser(t, 'mallory@example.test');
    t.db.prepare('UPDATE notes SET owner_id = ? WHERE id = ?').run(mallory.id, noteId);

    const res = await t.http.get(`/v1/notes/${noteId}`).set(mallory.auth).expect(500);
    expect(res.body).toMatchObject({ error: 'internal_error' });
    expect(JSON.stringify(res.body)).not.toMatch(/secret|aes|gcm|stack/i);
  });

  it('survives a key rotation end to end', async () => {
    const t = setup();
    const { alice, noteId } = await aliceWithNote(t);
    const { randomBytes } = await import('node:crypto');
    const { NoteService } = await import('../../src/services/note-service.js');
    const ring = { keys: new Map([...t.config.ENCRYPTION_KEYS, ['k2', randomBytes(32)]]), activeKeyId: 'k2' };
    expect(new NoteService(t.db, ring, t.services.audit).rotateKeys()).toEqual({ rewrapped: 1 });
    const row = t.db.prepare('SELECT key_id FROM notes WHERE id = ?').get(noteId) as { key_id: string };
    expect(row.key_id).toBe('k2');
    // The running app (k1 only) can no longer open it: proof the DEK really moved to k2.
    await t.http.get(`/v1/notes/${noteId}`).set(alice.auth).expect(500);
    expect(new NoteService(t.db, ring, t.services.audit).get(alice.id, noteId, null).body).toBe("alice's secret");
  });
});

describe('operator CLI', () => {
  it('generates fresh, valid secrets', () => {
    // Run tsx through the current node binary: spawning `npx` directly fails on Windows (npx.cmd).
    const out = execFileSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', 'gen-secrets'], { encoding: 'utf8' });
    expect(out).toMatch(/^JWT_SECRET=.+\nAUDIT_HMAC_KEY=.+\nENCRYPTION_KEYS=k1:.+\nACTIVE_KEY_ID=k1\n$/);
  });
});
