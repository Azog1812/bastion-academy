import { describe, expect, it } from 'vitest';
import { auditActions, newUser, setup, STRONG_PASSWORD, type Session, type TestContext } from '../helpers.js';
import { SoftAuthenticator } from '../webauthn-authenticator.js';

/**
 * Passwordless login with a discoverable passkey (ADR 0017). The passkey replaces the
 * password and the second factor, so every test here plays someone trying to get in
 * without it: another account's handle, a key without PIN, a replayed or borrowed
 * challenge, a phishing origin, a clone, a flood of challenges.
 */

const FLAG_UP = 0x01;

async function enrol(t: TestContext, s: Session, a = new SoftAuthenticator()) {
  const opts = await t.http.post('/v1/me/passkeys/options').set(s.auth).send({ password: STRONG_PASSWORD }).expect(200);
  // What the authenticator stores with a discoverable credential: the page's user.id.
  a.userHandle = opts.body.user.id as string;
  await t.http.post('/v1/me/passkeys').set(s.auth).send({ name: 'Téléphone', credential: a.register(opts.body.challenge as string) }).expect(201);
  return a;
}

async function challenge(t: TestContext): Promise<string> {
  const res = await t.http.post('/v1/auth/passkey/options').send({}).expect(200);
  return res.body.challenge as string;
}

async function passwordless(t: TestContext, a: SoftAuthenticator, o: Parameters<SoftAuthenticator['discover']>[1] = {}) {
  const c = await challenge(t);
  return t.http.post('/v1/auth/passkey').send({ passkey: a.discover(c, o) });
}

const failedFor = (t: TestContext) =>
  t.services.audit
    .list(1000)
    .filter((r) => r.action === 'auth.login' && r.outcome === 'failure')
    .map((r) => ({ actor: r.actor_id, ...(JSON.parse(r.details) as { method?: string; reason?: string }) }));

describe('passwordless login with a passkey', () => {
  it('logs in with no e-mail and no password, and asks for no second factor', async () => {
    const t = setup();
    const s = await newUser(t);
    const a = await enrol(t, s);
    const opts = (await t.http.post('/v1/auth/passkey/options').expect(200)).body as Record<string, unknown>;
    // No account named: nothing in the options depends on who will log in.
    expect(opts).toMatchObject({ rpId: 'localhost', userVerification: 'required', allowCredentials: [] });
    const res = await passwordless(t, a);
    expect(res.status).toBe(200);
    const me = await t.http.get('/v1/me').set({ Authorization: `Bearer ${res.body.accessToken as string}` }).expect(200);
    expect(me.body.id).toBe(s.id);
    const last = t.services.audit.list(5).find((r) => r.action === 'auth.login');
    expect(last).toMatchObject({ outcome: 'success', actor_id: s.id });
    expect(JSON.parse(last?.details ?? '{}')).toEqual({ method: 'passkey' });
    // The password login is unchanged for the same account: two steps.
    expect((await t.http.post('/v1/auth/login').send({ email: s.email, password: STRONG_PASSWORD }).expect(200)).body.mfaRequired).toBe(true);
  });

  it('requires user verification: a security key that only proves presence is not enough alone', async () => {
    const t = setup();
    const s = await newUser(t);
    const a = await enrol(t, s);
    const res = await passwordless(t, a, { flags: FLAG_UP });
    expect(res.status).toBe(401);
    expect(failedFor(t)).toContainEqual({ actor: s.id, method: 'passkey', reason: 'user_verification' });
  });

  it("refuses another account's handle, a forged handle and an unknown key, all alike", async () => {
    const t = setup();
    const victim = await newUser(t);
    const attacker = await newUser(t);
    const victimKey = await enrol(t, victim);
    const attackerKey = await enrol(t, attacker);
    // The attacker's valid key, presented as the victim's.
    const borrowed = await passwordless(t, attackerKey, { userHandle: victimKey.userHandle ?? '' });
    // A handle that is no account id at all, and a key the server never saw.
    const forged = await passwordless(t, attackerKey, { userHandle: Buffer.from('admin').toString('base64url') });
    const stranger = new SoftAuthenticator();
    stranger.userHandle = victimKey.userHandle ?? '';
    const unknown = await passwordless(t, stranger);
    for (const r of [borrowed, forged, unknown]) {
      expect(r.status).toBe(401);
      expect(r.body.message).toBe('Passkey not recognised');
    }
    // No real credential of the victim's account was involved: the audit names nobody.
    expect(failedFor(t)).toEqual(expect.arrayContaining([
      { actor: null, method: 'passkey', reason: 'unknown_credential' },
      { actor: null, method: 'passkey', reason: 'user_handle' },
    ]));
    expect(failedFor(t).every((f) => f.actor === null)).toBe(true);
  });

  it('uses each challenge once, and never one issued for an MFA step', async () => {
    const t = setup();
    const s = await newUser(t);
    const a = await enrol(t, s);
    const c = await challenge(t);
    const assertion = a.discover(c);
    await t.http.post('/v1/auth/passkey').send({ passkey: assertion }).expect(200);
    await t.http.post('/v1/auth/passkey').send({ passkey: assertion }).expect(401);
    // A challenge from the second-factor step lives in another table, for another ceremony.
    const step = await t.http.post('/v1/auth/login').send({ email: s.email, password: STRONG_PASSWORD }).expect(200);
    const mfaOpts = await t.http.post('/v1/auth/mfa/passkey/options').send({ mfaToken: step.body.mfaToken as string }).expect(200);
    await t.http.post('/v1/auth/passkey').send({ passkey: a.discover(mfaOpts.body.challenge as string) }).expect(401);
    // And the other way round: a passwordless challenge does not complete an MFA step.
    const c2 = await challenge(t);
    const { userHandle: _drop, ...response } = a.discover(c2).response;
    await t.http.post('/v1/auth/mfa').send({ mfaToken: step.body.mfaToken as string, passkey: { id: assertion.id, type: 'public-key', response } }).expect(401);
    // Expired: five minutes, then gone.
    const late = await challenge(t);
    t.db.prepare('UPDATE webauthn_login_challenges SET expires_at = ?').run(Date.now() - 1);
    await t.http.post('/v1/auth/passkey').send({ passkey: a.discover(late) }).expect(401);
    expect(failedFor(t).filter((f) => f.reason === 'challenge')).toHaveLength(3);
  });

  it('refuses what a phishing proxy relays', async () => {
    const t = setup();
    const s = await newUser(t);
    const a = await enrol(t, s);
    expect((await passwordless(t, a, { origin: 'https://bastion-academy.example' })).status).toBe(401);
    expect((await passwordless(t, a, { rpId: 'evil.example' })).status).toBe(401);
    expect((await passwordless(t, a, { tamperSignature: true })).status).toBe(401);
    expect(failedFor(t).map((f) => f.reason)).toEqual(['assertion', 'assertion', 'assertion']);
  });

  it('gets the owner in while a password guesser is locked out, and lifts nothing for the guesser', async () => {
    const t = setup();
    const s = await newUser(t);
    const a = await enrol(t, s);
    for (let n = 0; n < 5; n++) await t.http.post('/v1/auth/login').send({ email: s.email, password: 'wrong password number x' }).expect(401);
    expect(auditActions(t)).toContain('auth.lockout:denied');
    // Locked: even the right password is refused.
    await t.http.post('/v1/auth/login').send({ email: s.email, password: STRONG_PASSWORD }).expect(401);
    // The passkey is not guessable: the lockout is not its business.
    expect((await passwordless(t, a)).status).toBe(200);
    // ... and the lock stays for the password.
    await t.http.post('/v1/auth/login').send({ email: s.email, password: STRONG_PASSWORD }).expect(401);
  });

  it('cannot be turned into a way to lock an account: failed assertions are not failed logins', async () => {
    const t = setup();
    const s = await newUser(t);
    const a = await enrol(t, s);
    for (let n = 0; n < 8; n++) expect((await passwordless(t, a, { tamperSignature: true })).status).toBe(401);
    const row = t.db.prepare('SELECT failed_logins, locked_until FROM users WHERE id = ?').get(s.id) as { failed_logins: number; locked_until: number };
    expect(row).toEqual({ failed_logins: 0, locked_until: 0 });
    // The password login still works in two steps.
    await t.http.post('/v1/auth/login').send({ email: s.email, password: STRONG_PASSWORD }).expect(200);
  });

  it('flags a cloned authenticator', async () => {
    const t = setup();
    const s = await newUser(t);
    const key = await enrol(t, s, new SoftAuthenticator('ed25519', undefined, undefined, 7));
    expect((await passwordless(t, key)).status).toBe(200);
    expect((await passwordless(t, key, { keepCounter: true })).status).toBe(401);
    expect(auditActions(t)).toContain('passkey.clone_detected:denied');
    expect(failedFor(t)).toContainEqual({ actor: s.id, method: 'passkey', reason: 'clone' });
  });

  it('opens a browser session in an HttpOnly cookie, same origin only', async () => {
    const t = setup();
    const s = await newUser(t);
    const a = await enrol(t, s);
    const c1 = await challenge(t);
    const ok = await t.http.post('/v1/session/passkey').send({ passkey: a.discover(c1) }).expect(200);
    expect(ok.body.refreshToken).toBeUndefined();
    expect(ok.body.accessToken).toBeDefined();
    expect(String(ok.headers['set-cookie'])).toMatch(/^__Host-bastion_rt=.+; Path=\/; Secure; HttpOnly; SameSite=Strict/);
    const c2 = await challenge(t);
    await t.http.post('/v1/session/passkey').set('Origin', 'https://evil.example').send({ passkey: a.discover(c2) }).expect(403);
  });

  it('bounds how many challenges can be pending, whoever asks', async () => {
    const t = setup();
    const insert = t.db.prepare('INSERT INTO webauthn_login_challenges (challenge_hash, expires_at) VALUES (?, ?)');
    const until = Date.now() + 60_000;
    t.db.exec('BEGIN');
    for (let n = 0; n < 10_000; n++) insert.run(`h${String(n)}`, until);
    t.db.exec('COMMIT');
    await t.http.post('/v1/auth/passkey/options').expect(503);
    // Expired ones are swept first: the cap counts live challenges only.
    t.db.prepare('UPDATE webauthn_login_challenges SET expires_at = ?').run(Date.now() - 1);
    await t.http.post('/v1/auth/passkey/options').expect(200);
    expect((t.db.prepare('SELECT COUNT(*) AS n FROM webauthn_login_challenges').get() as { n: number }).n).toBe(1);
  });

  it('keeps bodies strict', async () => {
    const t = setup();
    const s = await newUser(t);
    const a = await enrol(t, s);
    await t.http.post('/v1/auth/passkey/options').send({ email: s.email }).expect(400);
    const c = await challenge(t);
    const good = a.discover(c);
    const { userHandle: _drop, ...noHandle } = good.response;
    await t.http.post('/v1/auth/passkey').send({ passkey: { ...good, response: noHandle } }).expect(400);
    await t.http.post('/v1/auth/passkey').send({ passkey: good, email: s.email }).expect(400);
    await t.http.post('/v1/auth/passkey').send({ passkey: { ...good, response: { ...good.response, userHandle: 'A'.repeat(89) } } }).expect(400);
  });
});
