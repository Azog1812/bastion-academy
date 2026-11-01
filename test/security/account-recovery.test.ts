import { describe, expect, it } from 'vitest';
import { base32Decode, hotp, totpStep } from '../../src/crypto/totp.js';
import { recoverAccount } from '../../src/services/recovery.js';
import { auditActions, newUser, setup, STRONG_PASSWORD } from '../helpers.js';
import { SoftAuthenticator } from '../webauthn-authenticator.js';

/**
 * Last-resort recovery (ADR 0017): operator CLI only. It must leave nothing of the old
 * identity behind, an attacker's passkey or session included, and must not exist over HTTP.
 */
describe('operator account recovery', () => {
  it('removes every factor and session, and only the temporary password gets in', async () => {
    const t = setup();
    const s = await newUser(t);
    // TOTP, a passkey (discoverable), and a lock from someone guessing the password.
    const totp = await t.http.post('/v1/me/mfa/setup').set(s.auth).send({ password: STRONG_PASSWORD }).expect(200);
    await t.http.post('/v1/me/mfa/enable').set(s.auth).send({ code: hotp(base32Decode(totp.body.secret as string), totpStep(Date.now())) }).expect(200);
    const key = new SoftAuthenticator();
    const opts = await t.http.post('/v1/me/passkeys/options').set(s.auth).send({ password: STRONG_PASSWORD }).expect(200);
    key.userHandle = opts.body.user.id as string;
    await t.http.post('/v1/me/passkeys').set(s.auth).send({ name: 'Clé', credential: key.register(opts.body.challenge as string) }).expect(201);
    for (let n = 0; n < 5; n++) await t.http.post('/v1/auth/login').send({ email: s.email, password: 'wrong password number x' }).expect(401);

    const { temporaryPassword } = await recoverAccount(t.db, t.services.audit, s.email, 10);

    // Old password, old sessions, old passkey: all dead.
    await t.http.post('/v1/auth/login').send({ email: s.email, password: STRONG_PASSWORD }).expect(401);
    await t.http.get('/v1/me').set(s.auth).expect(401);
    await t.http.post('/v1/auth/refresh').send({ refreshToken: s.refreshToken }).expect(401);
    const c = (await t.http.post('/v1/auth/passkey/options').expect(200)).body.challenge as string;
    await t.http.post('/v1/auth/passkey').send({ passkey: key.discover(c) }).expect(401);
    // The temporary password logs in at once (no factor left, lock cleared).
    const login = await t.http.post('/v1/auth/login').send({ email: s.email, password: temporaryPassword }).expect(200);
    expect(login.body.accessToken).toBeDefined();
    const me = (await t.http.get('/v1/me').set({ Authorization: `Bearer ${login.body.accessToken as string}` }).expect(200)).body;
    expect(me).toMatchObject({ mfaEnabled: false, totpEnabled: false, passkeys: 0 });

    const entry = t.services.audit.list(50).find((r) => r.action === 'admin.account_recovery');
    expect(entry).toMatchObject({ outcome: 'success', target: s.id, actor_id: null });
    expect(JSON.parse(entry?.details ?? '{}')).toEqual({ via: 'cli', passkeys: 1, totp: 1, recoveryCodes: 10 });
    // The temporary password is never written to the audit log.
    expect(JSON.stringify(t.services.audit.list(1000))).not.toContain(temporaryPassword);
    expect(auditActions(t)).toContain('admin.account_recovery:success');
  });

  it('refuses an unknown account', async () => {
    const t = setup();
    await expect(recoverAccount(t.db, t.services.audit, 'nobody@example.test', 10)).rejects.toThrow('no such user');
  });

  it('has no HTTP door', async () => {
    const t = setup();
    const s = await newUser(t);
    for (const path of ['/v1/auth/recover', '/v1/auth/recovery', '/v1/me/recover', '/v1/admin/recover-account']) {
      const r = await t.http.post(path).set(s.auth).send({ email: s.email });
      expect([404, 403]).toContain(r.status);
    }
  });
});
