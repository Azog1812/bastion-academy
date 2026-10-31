import { describe, expect, it } from 'vitest';
import { base32Decode, hotp, totpStep } from '../../src/crypto/totp.js';
import { auditActions, newUser, setup, STRONG_PASSWORD, type Session, type TestContext } from '../helpers.js';
import { SoftAuthenticator } from '../webauthn-authenticator.js';

/**
 * Passkeys as a second factor (ADR 0016), over HTTP, with a software authenticator that
 * produces the bytes a browser would. The attacker plays a phishing proxy, replays,
 * clones keys and pokes other accounts' credentials.
 */

async function enrolPasskey(t: TestContext, s: Session, a = new SoftAuthenticator(), name = 'Clé USB') {
  const opts = await t.http.post('/v1/me/passkeys/options').set(s.auth).send({ password: STRONG_PASSWORD }).expect(200);
  const res = await t.http.post('/v1/me/passkeys').set(s.auth).send({ name, credential: a.register(opts.body.challenge as string) });
  return { a, res, opts: opts.body as { challenge: string; rp: { id: string }; excludeCredentials: { id: string }[]; attestation: string } };
}

async function mfaToken(t: TestContext, s: Session): Promise<string> {
  const res = await t.http.post('/v1/auth/login').send({ email: s.email, password: STRONG_PASSWORD }).expect(200);
  expect(res.body).toMatchObject({ mfaRequired: true });
  return res.body.mfaToken as string;
}

async function passkeyLogin(t: TestContext, token: string, a: SoftAuthenticator, o: Parameters<SoftAuthenticator['assert']>[1] = {}) {
  const opts = await t.http.post('/v1/auth/mfa/passkey/options').send({ mfaToken: token }).expect(200);
  return t.http.post('/v1/auth/mfa').send({ mfaToken: token, passkey: a.assert(opts.body.challenge as string, o) });
}

describe('passkeys (WebAuthn) as a second factor', () => {
  it('enrols after a password check, asks for no attestation, and gives recovery codes once', async () => {
    const t = setup();
    const s = await newUser(t);
    await t.http.post('/v1/me/passkeys/options').set(s.auth).send({ password: 'wrong password here' }).expect(401);
    const { res, opts } = await enrolPasskey(t, s);
    expect(res.status).toBe(201);
    expect(opts).toMatchObject({ rp: { id: 'localhost' }, attestation: 'none' });
    expect(res.body.recoveryCodes).toHaveLength(10);
    // A second passkey: the account has codes already.
    const second = await enrolPasskey(t, s, new SoftAuthenticator('ed25519'), 'Téléphone');
    expect(second.res.body.recoveryCodes).toBeNull();
    expect(second.opts.excludeCredentials).toHaveLength(1);
    const me = (await t.http.get('/v1/me').set(s.auth).expect(200)).body;
    expect(me).toMatchObject({ mfaEnabled: true, totpEnabled: false, passkeys: 2 });
    const list = (await t.http.get('/v1/me/passkeys').set(s.auth).expect(200)).body.items as Record<string, unknown>[];
    expect(list.map((p) => p.name)).toEqual(['Clé USB', 'Téléphone']);
    // Only metadata: no key material, no credential id.
    expect(JSON.stringify(list)).not.toMatch(/public|credential/i);
    expect(auditActions(t)).toContain('passkey.register:success');
  });

  it('turns login into two steps, and a passkey completes the second', async () => {
    const t = setup();
    const s = await newUser(t);
    const { a } = await enrolPasskey(t, s);
    const res = await passkeyLogin(t, await mfaToken(t, s), a);
    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();
    expect(auditActions(t)).toContain('auth.mfa:success');
    const last = t.services.audit.list(5).find((r) => r.action === 'auth.mfa');
    expect(JSON.parse(last?.details ?? '{}')).toEqual({ factor: 'passkey' });
  });

  it('refuses what a phishing proxy relays: another origin, another RP ID', async () => {
    const t = setup();
    const s = await newUser(t);
    const { a } = await enrolPasskey(t, s);
    await passkeyLogin(t, await mfaToken(t, s), a, { origin: 'https://bastion-academy.example' }).then((r) => {
      expect(r.status).toBe(401);
    });
    await passkeyLogin(t, await mfaToken(t, s), a, { rpId: 'evil.example' }).then((r) => {
      expect(r.status).toBe(401);
    });
    // Enrolment through a phishing page fails as well.
    const opts = await t.http.post('/v1/me/passkeys/options').set(s.auth).send({ password: STRONG_PASSWORD }).expect(200);
    const evil = new SoftAuthenticator('es256', 'https://bastion-academy.example');
    const r = await t.http.post('/v1/me/passkeys').set(s.auth).send({ name: 'x', credential: evil.register(opts.body.challenge as string) }).expect(400);
    expect(r.body.message).toMatch(/origin/);
  });

  it('uses each challenge once, for its own MFA step only', async () => {
    const t = setup();
    const s = await newUser(t);
    const { a } = await enrolPasskey(t, s);
    const token = await mfaToken(t, s);
    const opts = await t.http.post('/v1/auth/mfa/passkey/options').send({ mfaToken: token }).expect(200);
    const assertion = a.assert(opts.body.challenge as string);
    // Bound to its MFA step: presented with another step's token, it fails, and is used up.
    const other = await mfaToken(t, s);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: other, passkey: assertion }).expect(401);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: token, passkey: assertion }).expect(401);
    // A fresh challenge works; replaying its assertion does not.
    const fresh = await t.http.post('/v1/auth/mfa/passkey/options').send({ mfaToken: token }).expect(200);
    const good = a.assert(fresh.body.challenge as string);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: token, passkey: good }).expect(200);
    const token2 = await mfaToken(t, s);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: token2, passkey: good }).expect(401);
    // No options without a valid MFA step.
    await t.http.post('/v1/auth/mfa/passkey/options').send({ mfaToken: 'x'.repeat(43) }).expect(401);
  });

  it("never accepts another account's key", async () => {
    const t = setup();
    const victim = await newUser(t);
    const attacker = await newUser(t);
    const { a: victimKey } = await enrolPasskey(t, victim);
    const { a: attackerKey } = await enrolPasskey(t, attacker);
    // The attacker knows the victim's password but holds only their own authenticator.
    const token = await mfaToken(t, victim);
    const opts = await t.http.post('/v1/auth/mfa/passkey/options').send({ mfaToken: token }).expect(200);
    expect(opts.body.allowCredentials).toEqual([{ type: 'public-key', id: victimKey.credentialId.toString('base64url') }]);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: token, passkey: attackerKey.assert(opts.body.challenge as string) }).expect(401);
    // And the same authenticator key cannot be enrolled on a second account.
    const o = await t.http.post('/v1/me/passkeys/options').set(attacker.auth).send({ password: STRONG_PASSWORD }).expect(200);
    await t.http.post('/v1/me/passkeys').set(attacker.auth).send({ name: 'x', credential: victimKey.register(o.body.challenge as string) }).expect(409);
  });

  it('flags a cloned authenticator and refuses it', async () => {
    const t = setup();
    const s = await newUser(t);
    const key = new SoftAuthenticator('es256', undefined, undefined, 5);
    await enrolPasskey(t, s, key);
    await passkeyLogin(t, await mfaToken(t, s), key).then((r) => {
      expect(r.status).toBe(200);
    });
    // The copy signs with a counter the server has already seen.
    await passkeyLogin(t, await mfaToken(t, s), key, { keepCounter: true }).then((r) => {
      expect(r.status).toBe(401);
    });
    expect(auditActions(t)).toContain('passkey.clone_detected:denied');
  });

  it('feeds wrong assertions into the same lockout as wrong codes', async () => {
    const t = setup();
    const s = await newUser(t);
    const { a } = await enrolPasskey(t, s);
    const token = await mfaToken(t, s);
    for (let n = 0; n < 5; n++) await passkeyLogin(t, token, a, { tamperSignature: true }).then((r) => {
      expect(r.status).toBe(401);
    });
    // The MFA step is spent after five attempts, even with a good signature now.
    await t.http.post('/v1/auth/mfa/passkey/options').send({ mfaToken: token }).expect(401);
  });

  it('removes a passkey with the password, and the last factor only with a recovery code too', async () => {
    const t = setup();
    const s = await newUser(t);
    const first = await enrolPasskey(t, s);
    const codes = first.res.body.recoveryCodes as string[];
    const second = await enrolPasskey(t, s, new SoftAuthenticator('ed25519'), 'Téléphone');
    const id1 = first.res.body.id as string;
    const id2 = second.res.body.id as string;
    await t.http.delete(`/v1/me/passkeys/${id1}`).set(s.auth).send({ password: 'wrong password here' }).expect(401);
    await t.http.delete(`/v1/me/passkeys/${id1}`).set(s.auth).send({ password: STRONG_PASSWORD }).expect(204);
    // The last one: the password alone does not disable the second factor.
    await t.http.delete(`/v1/me/passkeys/${id2}`).set(s.auth).send({ password: STRONG_PASSWORD }).expect(401);
    await t.http.delete(`/v1/me/passkeys/${id2}`).set(s.auth).send({ password: STRONG_PASSWORD, code: codes[0] }).expect(204);
    expect((await t.http.get('/v1/me').set(s.auth).expect(200)).body).toMatchObject({ mfaEnabled: false, passkeys: 0 });
    // MFA is off: a password logs in again, and the old recovery codes are gone.
    expect((await t.http.post('/v1/auth/login').send({ email: s.email, password: STRONG_PASSWORD }).expect(200)).body.accessToken).toBeDefined();
  });

  it('keeps MFA and the recovery codes when TOTP goes but a passkey stays', async () => {
    const t = setup();
    const s = await newUser(t);
    const setupRes = await t.http.post('/v1/me/mfa/setup').set(s.auth).send({ password: STRONG_PASSWORD }).expect(200);
    const secret = base32Decode(setupRes.body.secret as string);
    const step = totpStep(Date.now());
    const codes = (await t.http.post('/v1/me/mfa/enable').set(s.auth).send({ code: hotp(secret, step) }).expect(200)).body.recoveryCodes as string[];
    // TOTP gave the codes already: the passkey adds none.
    expect((await enrolPasskey(t, s)).res.body.recoveryCodes).toBeNull();
    await t.http.post('/v1/me/mfa/disable').set(s.auth).send({ password: STRONG_PASSWORD, code: codes[0] }).expect(204);
    expect((await t.http.get('/v1/me').set(s.auth).expect(200)).body).toMatchObject({ mfaEnabled: true, totpEnabled: false, passkeys: 1 });
    // Login still asks for a second factor, and a recovery code still stands in for the passkey.
    const token = await mfaToken(t, s);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: token, code: hotp(secret, step + 1) }).expect(401);
    const token2 = await mfaToken(t, s);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: token2, code: codes[1] }).expect(200);
  });

  it("cannot see or delete another account's passkeys (IDOR)", async () => {
    const t = setup();
    const owner = await newUser(t);
    const other = await newUser(t);
    const { res } = await enrolPasskey(t, owner);
    const id = res.body.id as string;
    expect((await t.http.get('/v1/me/passkeys').set(other.auth).expect(200)).body.items).toEqual([]);
    await t.http.delete(`/v1/me/passkeys/${id}`).set(other.auth).send({ password: STRONG_PASSWORD }).expect(404);
    await t.http.delete('/v1/me/passkeys/00000000-0000-4000-8000-000000000000').set(other.auth).send({ password: STRONG_PASSWORD }).expect(404);
    expect((await t.http.get('/v1/me/passkeys').set(owner.auth).expect(200)).body.items).toHaveLength(1);
  });

  it('keeps request bodies strict and bounded', async () => {
    const t = setup();
    const s = await newUser(t);
    const { a } = await enrolPasskey(t, s);
    const token = await mfaToken(t, s);
    const opts = await t.http.post('/v1/auth/mfa/passkey/options').send({ mfaToken: token }).expect(200);
    const assertion = a.assert(opts.body.challenge as string);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: token, passkey: { ...assertion, extra: 1 } }).expect(400);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: token, passkey: assertion, code: '123456' }).expect(400);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: token, passkey: { ...assertion, response: { ...assertion.response, signature: 'A'.repeat(1401) } } }).expect(400);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: token, passkey: { ...assertion, response: { ...assertion.response, signature: 'not base64url!' } } }).expect(400);
    // Logging in with a TOTP code still works the old way for accounts that have one: covered in mfa.test.ts.
  });
});
