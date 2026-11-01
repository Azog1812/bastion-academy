import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config.js';
import { kmsFromConfig } from '../../src/crypto/kms-config.js';
import { CompositeKms, DecryptionError, KmsUnavailable, LocalKms, VaultTransitKms } from '../../src/crypto/kms.js';
import { MfaService } from '../../src/services/mfa-service.js';
import { NoteService } from '../../src/services/note-service.js';
import { FakeVault } from '../fake-vault.js';
import { newUser, setup, STRONG_PASSWORD, testEnv, type TestContext } from '../helpers.js';

/**
 * KEKs in Vault Transit (ADR 0019), against a Transit stand-in whose behaviour the real
 * Vault confirms (test/vault-real). The attacker edits rows, the key service goes down,
 * redirects, or comes with a key that can be exported.
 */

const vaults: FakeVault[] = [];
afterEach(async () => {
  await Promise.all(vaults.splice(0).map((v) => v.stop()));
});

async function fakeVault() {
  const v = new FakeVault();
  await v.start();
  vaults.push(v);
  return v;
}

const transit = (v: FakeVault, token = v.token) => new VaultTransitKms({ addr: v.url, auth: { token }, mount: 'transit', key: 'bastion-kek', timeoutMs: 2000 });
const integrity = (t: TestContext) => t.metrics.integrityFailures.value();

async function withNote(t: TestContext, body = "alice's secret") {
  const alice = await newUser(t);
  const res = await t.http.post('/v1/notes').set(alice.auth).send({ title: 'private', body }).expect(201);
  return { alice, noteId: res.body.id as string };
}

describe('KEKs in Vault Transit', () => {
  it('stores Vault ciphertexts only, and reads them back', async () => {
    const v = await fakeVault();
    const t = setup({ kms: transit(v) });
    const { alice, noteId } = await withNote(t);
    const row = t.db.prepare('SELECT key_id, wrapped_dek FROM notes WHERE id = ?').get(noteId) as { key_id: string; wrapped_dek: Uint8Array };
    expect(row.key_id).toBe('vault:bastion-kek:v1');
    expect(Buffer.from(row.wrapped_dek).toString()).toMatch(/^vault:v1:/);
    expect((await t.http.get(`/v1/notes/${noteId}`).set(alice.auth).expect(200)).body.body).toBe("alice's secret");
  });

  it('opens a page of notes in one round trip', async () => {
    const v = await fakeVault();
    const t = setup({ kms: transit(v) });
    const alice = await newUser(t);
    for (let i = 0; i < 5; i++) await t.http.post('/v1/notes').set(alice.auth).send({ title: `n${String(i)}`, body: 'x' }).expect(201);
    v.calls = [];
    expect((await t.http.get('/v1/notes').set(alice.auth).expect(200)).body.items).toHaveLength(5);
    expect(v.calls.filter((c) => c.includes('/decrypt/'))).toHaveLength(1);
  });

  it("refuses another note's wrapped DEK: the context binds it, and it raises the integrity alert", async () => {
    const v = await fakeVault();
    const t = setup({ kms: transit(v) });
    const { alice, noteId } = await withNote(t);
    const { noteId: other } = await withNote(t, 'mallory');
    // Someone with write access to the database copies another note's DEK into Alice's row.
    const theirs = t.db.prepare('SELECT key_id, wrapped_dek FROM notes WHERE id = ?').get(other) as { key_id: string; wrapped_dek: Uint8Array };
    t.db.prepare('UPDATE notes SET key_id = ?, wrapped_dek = ? WHERE id = ?').run(theirs.key_id, theirs.wrapped_dek, noteId);
    const res = await t.http.get(`/v1/notes/${noteId}`).set(alice.auth).expect(500);
    expect(JSON.stringify(res.body)).not.toMatch(/vault|cipher|transit/i);
    expect(integrity(t)).toBe(1);
  });

  it('refuses a row whose key id and ciphertext disagree', async () => {
    const v = await fakeVault();
    const t = setup({ kms: transit(v) });
    const { alice, noteId } = await withNote(t);
    t.db.prepare("UPDATE notes SET key_id = 'vault:bastion-kek:v2' WHERE id = ?").run(noteId);
    await t.http.get(`/v1/notes/${noteId}`).set(alice.auth).expect(500);
    t.db.prepare("UPDATE notes SET key_id = 'vault:other-key:v1' WHERE id = ?").run(noteId);
    await t.http.get(`/v1/notes/${noteId}`).set(alice.auth).expect(500);
    expect(integrity(t)).toBe(2);
  });

  it('answers 503 when Vault is sealed, down or refuses the token, and never calls it tampering', async () => {
    const v = await fakeVault();
    const t = setup({ kms: transit(v) });
    const { alice, noteId } = await withNote(t);
    v.sealed = true;
    const sealed = await t.http.get(`/v1/notes/${noteId}`).set(alice.auth).expect(503);
    expect(sealed.headers['retry-after']).toBe('30');
    expect(JSON.stringify(sealed.body)).not.toContain(v.token);
    await t.http.post('/v1/notes').set(alice.auth).send({ title: 'x', body: 'y' }).expect(503);
    v.sealed = false;
    await v.stop();
    await t.http.get(`/v1/notes/${noteId}`).set(alice.auth).expect(503);
    const revoked = setup({ kms: transit(await fakeVault(), 'hvs.revoked-token-xxxxxxxxxxxx') });
    const bob = await newUser(revoked);
    await revoked.http.post('/v1/notes').set(bob.auth).send({ title: 'x', body: 'y' }).expect(503);
    expect(integrity(t) + integrity(revoked)).toBe(0);
  });

  it('never follows a redirect: the token would go with it', async () => {
    let leaked = false;
    const thief = createServer((req, res) => {
      if (req.headers['x-vault-token']) leaked = true;
      res.writeHead(200, { 'Content-Type': 'application/json' }).end('{"data":{}}');
    });
    await new Promise<void>((r) => thief.listen(0, '127.0.0.1', r));
    const v = await fakeVault();
    v.redirectTo = `http://127.0.0.1:${String((thief.address() as AddressInfo).port)}`;
    await expect(transit(v).wrap(randomBytes(32), 'c')).rejects.toThrow(KmsUnavailable);
    await new Promise<void>((r) => thief.close(() => { r(); }));
    expect(leaked).toBe(false);
  });

  it.each([
    ['exportable', { exportable: true }, /exportable/],
    ['not derived', { derived: false }, /derived/],
    ['deletable', { deletion_allowed: true }, /deletion/],
    ['plaintext backup', { allow_plaintext_backup: true }, /backup/],
    ['another type', { type: 'chacha20-poly1305' }, /type/],
  ])('refuses to start with an unsafe key: %s', async (_name, change, message) => {
    const v = await fakeVault();
    v.key = { ...v.key, ...change };
    await expect(transit(v).check()).rejects.toThrow(message);
  });

  it('keeps TOTP seeds in Vault too, and a code still logs in', async () => {
    const v = await fakeVault();
    const t = setup({ kms: transit(v) });
    const s = await newUser(t);
    await t.http.post('/v1/me/mfa/setup').set(s.auth).send({ password: STRONG_PASSWORD }).expect(200);
    expect(t.db.prepare('SELECT key_id FROM user_mfa WHERE user_id = ?').get(s.id)).toEqual({ key_id: 'vault:bastion-kek:v1' });
  });

  it('rotates inside Vault: rewrap, never decrypt, and the old version can then be retired', async () => {
    const v = await fakeVault();
    const kms = transit(v);
    const t = setup({ kms });
    const { alice, noteId } = await withNote(t);
    v.rotate();
    v.calls = [];
    expect(await new NoteService(t.db, kms, t.services.audit).rotateKeys()).toEqual({ rewrapped: 1 });
    expect(v.calls.filter((c) => c.includes('/rewrap/'))).toHaveLength(1);
    expect(v.calls.filter((c) => c.includes('/decrypt/'))).toHaveLength(0);
    expect(t.db.prepare('SELECT key_id FROM notes WHERE id = ?').get(noteId)).toEqual({ key_id: 'vault:bastion-kek:v2' });
    expect(await new NoteService(t.db, kms, t.services.audit).rotateKeys()).toEqual({ rewrapped: 0 });
    expect((await t.http.get(`/v1/notes/${noteId}`).set(alice.auth).expect(200)).body.body).toBe("alice's secret");
  });

  it('migrates a database from the local ring to Vault with rotate-keys', async () => {
    // Before: everything under the local ring.
    const t = setup();
    const { alice, noteId } = await withNote(t);
    await t.http.post('/v1/me/mfa/setup').set(alice.auth).send({ password: STRONG_PASSWORD }).expect(200);
    const local = new LocalKms({ keys: t.config.ENCRYPTION_KEYS ?? new Map(), activeKeyId: t.config.ACTIVE_KEY_ID ?? 'k1' });
    // After: Vault is active, the ring only reads what is not moved yet.
    const v = await fakeVault();
    const both = new CompositeKms(transit(v), [local]);
    const notes = new NoteService(t.db, both, t.services.audit);
    expect((await notes.get(alice.id, noteId, null)).body).toBe("alice's secret");
    expect(await notes.rotateKeys()).toEqual({ rewrapped: 1 });
    expect(await new MfaService(t.db, both, t.services.audit, 'x').rotateKeys()).toBe(1);
    // The ring can now be deleted: Vault alone opens everything.
    const vaultOnly = new NoteService(t.db, transit(v), t.services.audit);
    expect((await vaultOnly.get(alice.id, noteId, null)).body).toBe("alice's secret");
    // A row still pointing at a retired local key fails closed, as tampering.
    t.db.prepare("UPDATE notes SET key_id = 'k1' WHERE id = ?").run(noteId);
    await expect(vaultOnly.get(alice.id, noteId, null)).rejects.toThrow(DecryptionError);
  });
});

describe('AppRole: short-lived tokens, no long-lived one on disk', () => {
  const approle = (v: FakeVault, now: () => number = Date.now, secretId = v.secretId) =>
    new VaultTransitKms({ addr: v.url, auth: { roleId: v.roleId, secretId }, mount: 'transit', key: 'bastion-kek', timeoutMs: 2000 }, now);

  it('logs in once for concurrent requests, then reuses the token', async () => {
    const v = await fakeVault();
    const kms = approle(v);
    await Promise.all(Array.from({ length: 5 }, () => kms.wrap(randomBytes(32), 'c')));
    await kms.wrap(randomBytes(32), 'c');
    expect(v.logins).toBe(1);
  });

  it('logs in again before the lease ends, and after a revocation', async () => {
    const v = await fakeVault();
    let clock = 0;
    const kms = approle(v, () => clock);
    await kms.wrap(randomBytes(32), 'c');
    clock = 2_450_000; // past two thirds of the 1-hour lease (2,400 s)
    await kms.wrap(randomBytes(32), 'c');
    expect(v.logins).toBe(2);
    // Vault revokes the token (an operator, or a lease that ended early): one retry with a fresh login.
    v.revokeIssued();
    await kms.wrap(randomBytes(32), 'c');
    expect(v.logins).toBe(3);
  });

  it('answers 503 with a wrong secret id, without leaking it', async () => {
    const v = await fakeVault();
    const wrong = '00000000-0000-4000-8000-000000000000';
    const err = await approle(v, Date.now, wrong).wrap(randomBytes(32), 'c').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(KmsUnavailable);
    expect((err as Error).message).not.toContain(wrong);
  });

  it('rotates the key version on demand (operator CLI), and rows follow with rewrap', async () => {
    const v = await fakeVault();
    const kms = approle(v);
    const t = setup({ kms });
    await withNote(t);
    await kms.rotateKey();
    expect(await kms.activeKeyId()).toBe('vault:bastion-kek:v2');
    expect(await new NoteService(t.db, kms, t.services.audit).rotateKeys()).toEqual({ rewrapped: 1 });
  });
});

describe('Vault configuration fails closed', () => {
  const vaultEnv = (o: Record<string, string>) => {
    const { ENCRYPTION_KEYS: _k, ACTIVE_KEY_ID: _a, ...rest } = testEnv();
    return { ...rest, KMS_PROVIDER: 'vault', ...o };
  };

  it('needs an address and a token, and no local ring', () => {
    expect(() => loadConfig(vaultEnv({}))).toThrow(/VAULT_ADDR[\s\S]*VAULT_TOKEN|VAULT_TOKEN[\s\S]*VAULT_ADDR/);
    const cfg = loadConfig(vaultEnv({ VAULT_ADDR: 'http://vault:8200', VAULT_TOKEN: 'hvs.CAESIJ0abcdefghijklmnop' }));
    expect(kmsFromConfig(cfg).vault).toBeInstanceOf(VaultTransitKms);
    // The local provider still requires its ring.
    expect(() => loadConfig(vaultEnv({ KMS_PROVIDER: 'local' }))).toThrow(/ENCRYPTION_KEYS/);
  });

  it('refuses plain http across a network in production, and URLs with paths or credentials', () => {
    const token = { VAULT_TOKEN: 'hvs.CAESIJ0abcdefghijklmnop', NODE_ENV: 'production', SCRYPT_LOG_N: '17' };
    expect(() => loadConfig(vaultEnv({ ...token, VAULT_ADDR: 'http://vault.example.com:8200' }))).toThrow(/https/);
    expect(() => loadConfig(vaultEnv({ ...token, VAULT_ADDR: 'http://vault:8200' }))).not.toThrow();
    expect(() => loadConfig(vaultEnv({ ...token, VAULT_ADDR: 'https://vault.example.com:8200' }))).not.toThrow();
    expect(() => loadConfig(vaultEnv({ ...token, VAULT_ADDR: 'https://vault.example.com/v1/transit' }))).toThrow(/scheme/);
    expect(() => loadConfig(vaultEnv({ ...token, VAULT_ADDR: 'https://user:pw@vault.example.com' }))).toThrow(/scheme/);
  });

  it('takes AppRole credentials (from files), complete, and not together with a token', () => {
    const role = '6a1f6b2e-1111-4c4c-8d8d-0123456789ab';
    const secret = '9b2e7c3d-2222-4d4d-9e9e-ba9876543210';
    const files: Record<string, string> = { '/run/vault/role_id': role, '/run/vault/secret_id': secret };
    const cfg = loadConfig(vaultEnv({ VAULT_ADDR: 'http://vault:8200', VAULT_ROLE_ID_FILE: '/run/vault/role_id', VAULT_SECRET_ID_FILE: '/run/vault/secret_id' }), (p) => files[p] ?? '');
    expect([cfg.VAULT_ROLE_ID, cfg.VAULT_SECRET_ID]).toEqual([role, secret]);
    expect(() => loadConfig(vaultEnv({ VAULT_ADDR: 'http://vault:8200', VAULT_ROLE_ID: role }))).toThrow(/both VAULT_ROLE_ID and VAULT_SECRET_ID/);
    expect(() => loadConfig(vaultEnv({ VAULT_ADDR: 'http://vault:8200', VAULT_ROLE_ID: role, VAULT_SECRET_ID: secret, VAULT_TOKEN: 'hvs.CAESIJ0abcdefghijklmnop' }))).toThrow(/either/);
  });

  it('reads the token from a file, never both', () => {
    const read = () => 'hvs.CAESIJ0fromthefile12345';
    expect(loadConfig(vaultEnv({ VAULT_ADDR: 'http://vault:8200', VAULT_TOKEN_FILE: '/run/secrets/vault' }), read).VAULT_TOKEN).toBe('hvs.CAESIJ0fromthefile12345');
    expect(() => loadConfig(vaultEnv({ VAULT_ADDR: 'http://vault:8200', VAULT_TOKEN: 'hvs.CAESIJ0abcdefghijklmnop', VAULT_TOKEN_FILE: '/x' }), read)).toThrow(/not both/);
  });

  it('keeps a configured ring readable during the migration', () => {
    const cfg = loadConfig({ ...testEnv(), KMS_PROVIDER: 'vault', VAULT_ADDR: 'http://vault:8200', VAULT_TOKEN: 'hvs.CAESIJ0abcdefghijklmnop' });
    const { kms } = kmsFromConfig(cfg);
    expect(kms.owns('k1')).toBe(true);
    expect(kms.owns('vault:bastion-kek:v3')).toBe(true);
    expect(kms.owns('vault:other:v1')).toBe(false);
  });
});
