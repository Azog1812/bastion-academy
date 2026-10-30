import { afterEach, describe, expect, it, vi } from 'vitest';
import { randomBytes } from 'node:crypto';
import { MfaService } from '../../src/services/mfa-service.js';
import { base32Decode, hotp, totpStep } from '../../src/crypto/totp.js';
import { auditActions, newUser, setup, STRONG_PASSWORD, type Session, type TestContext } from '../helpers.js';

/**
 * Time is frozen (Date only, timers keep running for supertest) so tests can
 * pick which 30-second step a code belongs to.
 */
const T0 = 1_800_000_000_000;
const STEP = totpStep(T0);

afterEach(() => {
  vi.useRealTimers();
});

function freeze(ms = T0): void {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(ms);
}

const code = (secret: Buffer, step: number) => hotp(secret, step);

/** Enrols a user; the enabling code consumes STEP. */
async function enrol(t: TestContext, s: Session): Promise<{ secret: Buffer; recoveryCodes: string[] }> {
  const setupRes = await t.http.post('/v1/me/mfa/setup').set(s.auth).send({ password: STRONG_PASSWORD }).expect(200);
  const secret = base32Decode(setupRes.body.secret as string);
  const en = await t.http.post('/v1/me/mfa/enable').set(s.auth).send({ code: code(secret, STEP) }).expect(200);
  return { secret, recoveryCodes: en.body.recoveryCodes as string[] };
}

const login = (t: TestContext, s: Session) => t.http.post('/v1/auth/login').send({ email: s.email, password: STRONG_PASSWORD });

async function mfaToken(t: TestContext, s: Session): Promise<string> {
  const res = await login(t, s).expect(200);
  expect(res.body).toMatchObject({ mfaRequired: true, expiresIn: 300 });
  expect(res.body.accessToken).toBeUndefined();
  expect(res.body.refreshToken).toBeUndefined();
  return res.body.mfaToken as string;
}

describe('MFA enrolment', () => {
  it('requires the password, then a valid first code, and returns 10 one-time recovery codes', async () => {
    freeze();
    const t = setup();
    const s = await newUser(t);
    await t.http.post('/v1/me/mfa/setup').set(s.auth).send({ password: 'wrong password here' }).expect(401);
    const res = await t.http.post('/v1/me/mfa/setup').set(s.auth).send({ password: STRONG_PASSWORD }).expect(200);
    expect(res.body.secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(res.body.otpauthUri).toMatch(/^otpauth:\/\/totp\//);

    const secret = base32Decode(res.body.secret as string);
    await t.http.post('/v1/me/mfa/enable').set(s.auth).send({ code: '000000' }).expect(400);
    // Not enabled until a code is confirmed: login still works with a password only.
    expect((await login(t, s).expect(200)).body.accessToken).toBeDefined();

    const en = await t.http.post('/v1/me/mfa/enable').set(s.auth).send({ code: code(secret, STEP) }).expect(200);
    expect(en.body.recoveryCodes).toHaveLength(10);
    expect((await t.http.get('/v1/me').set(s.auth).expect(200)).body.mfaEnabled).toBe(true);
    await t.http.post('/v1/me/mfa/setup').set(s.auth).send({ password: STRONG_PASSWORD }).expect(409);
    expect(auditActions(t)).toEqual(expect.arrayContaining(['mfa.setup:success', 'mfa.enable:failure', 'mfa.enable:success']));
  });

  it('stores the seed encrypted and the recovery codes hashed', async () => {
    freeze();
    const t = setup();
    const s = await newUser(t);
    const { secret, recoveryCodes } = await enrol(t, s);
    const row = t.db.prepare('SELECT secret FROM user_mfa WHERE user_id = ?').get(s.id) as { secret: Uint8Array };
    expect(Buffer.from(row.secret).includes(secret)).toBe(false);
    const dump = JSON.stringify(t.db.prepare('SELECT code_hash FROM mfa_recovery_codes WHERE user_id = ?').all(s.id));
    for (const c of recoveryCodes) expect(dump).not.toContain(c.replaceAll('-', ''));
  });
});

describe('MFA login', () => {
  it('issues tokens only after a valid second factor', async () => {
    freeze();
    const t = setup();
    const s = await newUser(t);
    const { secret } = await enrol(t, s);
    const token = await mfaToken(t, s);
    const res = await t.http.post('/v1/auth/mfa').send({ mfaToken: token, code: code(secret, STEP + 1) }).expect(200);
    await t.http.get('/v1/me').set({ Authorization: `Bearer ${res.body.accessToken as string}` }).expect(200);
    expect(auditActions(t)).toContain('auth.mfa:success');
  });

  it('refuses a replayed TOTP code, even within its validity window', async () => {
    freeze();
    const t = setup();
    const s = await newUser(t);
    const { secret } = await enrol(t, s);
    const tok1 = await mfaToken(t, s);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: tok1, code: code(secret, STEP + 1) }).expect(200);
    // The attacker who saw that code (phishing proxy, shoulder surfing) replays it.
    const tok2 = await mfaToken(t, s);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: tok2, code: code(secret, STEP + 1) }).expect(401);
    // An older code is refused too: steps only move forward.
    const tok3 = await mfaToken(t, s);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: tok3, code: code(secret, STEP) }).expect(401);
  });

  it('a challenge token is single-use', async () => {
    freeze();
    const t = setup();
    const s = await newUser(t);
    const { secret } = await enrol(t, s);
    const token = await mfaToken(t, s);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: token, code: code(secret, STEP + 1) }).expect(200);
    freeze(T0 + 30_000);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: token, code: code(secret, STEP + 2) }).expect(401);
  });

  it('a challenge dies after 5 wrong codes, even if the 6th is right (brute force)', async () => {
    freeze();
    const t = setup({ env: { MAX_FAILED_LOGINS: '20' } });
    const s = await newUser(t);
    const { secret } = await enrol(t, s);
    const token = await mfaToken(t, s);
    for (let i = 0; i < 5; i++) await t.http.post('/v1/auth/mfa').send({ mfaToken: token, code: String(100000 + i) }).expect(401);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: token, code: code(secret, STEP + 1) }).expect(401);
  });

  it('wrong codes feed the account lockout, so a stolen password does not buy unlimited guesses', async () => {
    freeze();
    const t = setup(); // MAX_FAILED_LOGINS = 5
    const s = await newUser(t);
    await enrol(t, s);
    const token = await mfaToken(t, s);
    for (let i = 0; i < 5; i++) await t.http.post('/v1/auth/mfa').send({ mfaToken: token, code: String(200000 + i) }).expect(401);
    expect(auditActions(t)).toContain('auth.lockout:denied');
    // Locked: same generic 401 at the password step (no enumeration), whatever the code.
    const res = await login(t, s).expect(401);
    expect(res.body.message).toBe('Invalid e-mail or password');
  });

  it('an expired challenge is refused', async () => {
    freeze();
    const t = setup();
    const s = await newUser(t);
    const { secret } = await enrol(t, s);
    const token = await mfaToken(t, s);
    freeze(T0 + 5 * 60_000 + 1);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: token, code: code(secret, totpStep(T0 + 5 * 60_000 + 1)) }).expect(401);
  });

  it('a recovery code works exactly once', async () => {
    freeze();
    const t = setup();
    const s = await newUser(t);
    const { recoveryCodes } = await enrol(t, s);
    const rc = recoveryCodes[0] ?? '';
    const tok4 = await mfaToken(t, s);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: tok4, code: rc.toLowerCase() }).expect(200);
    const tok5 = await mfaToken(t, s);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: tok5, code: rc }).expect(401);
    const used = t.services.audit.list(100).find((r) => r.action === 'mfa.recovery_code_used');
    expect(JSON.parse(used?.details ?? '{}')).toEqual({ left: 9 });
  });

  it('rejects malformed second-step payloads', async () => {
    const t = setup();
    await t.http.post('/v1/auth/mfa').send({ mfaToken: 'x'.repeat(43), code: '123456', remember: true }).expect(400);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: 'short', code: '123456' }).expect(400);
    await t.http.post('/v1/auth/mfa').send({ mfaToken: 'x'.repeat(43), code: '123456' }).expect(401);
  });

  it('browser flow: the refresh cookie is only set after the second factor', async () => {
    freeze();
    const t = setup();
    const s = await newUser(t);
    const { secret } = await enrol(t, s);
    const first = await t.http.post('/v1/session/login').send({ email: s.email, password: STRONG_PASSWORD }).expect(200);
    expect(first.headers['set-cookie']).toBeUndefined();
    expect(first.body.mfaRequired).toBe(true);
    const second = await t.http
      .post('/v1/session/mfa')
      .send({ mfaToken: first.body.mfaToken as string, code: code(secret, STEP + 1) })
      .expect(200);
    expect(String(second.headers['set-cookie'])).toMatch(/^__Host-bastion_rt=.+HttpOnly; SameSite=Strict/);
    expect(second.body.refreshToken).toBeUndefined();
    await t.http.post('/v1/session/mfa').set('Origin', 'https://evil.example').send({ mfaToken: 'x'.repeat(43), code: '123456' }).expect(403);
  });
});

describe('MFA removal', () => {
  it('needs both the password and a valid code', async () => {
    freeze();
    const t = setup();
    const s = await newUser(t);
    const { secret } = await enrol(t, s);
    await t.http.post('/v1/me/mfa/disable').set(s.auth).send({ password: 'not the password', code: code(secret, STEP + 1) }).expect(401);
    await t.http.post('/v1/me/mfa/disable').set(s.auth).send({ password: STRONG_PASSWORD, code: '000000' }).expect(401);
    expect(auditActions(t)).toContain('mfa.disable:failure');
    await t.http.post('/v1/me/mfa/disable').set(s.auth).send({ password: STRONG_PASSWORD, code: code(secret, STEP + 1) }).expect(204);
    expect((await login(t, s).expect(200)).body.accessToken).toBeDefined();
    expect(t.db.prepare('SELECT COUNT(*) AS n FROM mfa_recovery_codes WHERE user_id = ?').get(s.id)).toEqual({ n: 0 });
  });
});

describe('MFA key rotation (CLI)', () => {
  it('re-seals every seed under the new KEK; codes keep working', async () => {
    freeze();
    const t = setup();
    const s = await newUser(t);
    const { secret } = await enrol(t, s);
    const keys = new Map([...t.config.ENCRYPTION_KEYS, ['k2', randomBytes(32)]]);
    const rotated = new MfaService(t.db, { keys, activeKeyId: 'k2' }, t.services.audit, 'Bastion Academy');
    expect(rotated.rotateKeys()).toBe(1);
    expect(rotated.rotateKeys()).toBe(0); // idempotent
    expect(t.db.prepare('SELECT key_id FROM user_mfa WHERE user_id = ?').get(s.id)).toEqual({ key_id: 'k2' });
    expect(rotated.verify(s.id, code(secret, STEP + 1), null)).toBe('totp');
  });
});
