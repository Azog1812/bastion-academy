import { describe, expect, it } from 'vitest';
import { auditActions, newUser, setup, STRONG_PASSWORD } from '../helpers.js';

describe('authentication', () => {
  it('registers, logs in and reaches a protected route', async () => {
    const t = setup();
    const s = await newUser(t, 'alice@example.test');
    const me = await t.http.get('/v1/me').set(s.auth).expect(200);
    expect(me.body).toEqual({ id: s.id, role: 'user', displayName: null, mfaEnabled: false });
  });

  it('normalises e-mails so "Alice@X" and "alice@x" are one account', async () => {
    const t = setup();
    await newUser(t, 'alice@example.test');
    await t.http.post('/v1/auth/register').send({ email: '  ALICE@Example.TEST ', password: STRONG_PASSWORD }).expect(409);
    await t.http.post('/v1/auth/login').send({ email: 'Alice@EXAMPLE.test', password: STRONG_PASSWORD }).expect(200);
  });

  it('rejects weak and breached passwords at registration', async () => {
    const t = setup();
    // Known-breached password under test, not a credential.
    const res = await t.http.post('/v1/auth/register').send({ email: 'a@example.test', password: '1qaz2wsx3edc' }).expect(400); // nosemgrep
    expect(res.body.message).toMatch(/too common/);
  });

  it('never returns the password hash or internal fields', async () => {
    const t = setup();
    const res = await t.http.post('/v1/auth/register').send({ email: 'leak@example.test', password: STRONG_PASSWORD });
    expect(Object.keys(res.body).sort()).toEqual(['email', 'id']);
    expect(JSON.stringify(res.body)).not.toMatch(/scrypt|hash/);
  });

  describe('account enumeration resistance', () => {
    it('answers identically for an unknown e-mail and a wrong password', async () => {
      const t = setup();
      await newUser(t, 'known@example.test');
      const unknown = await t.http.post('/v1/auth/login').send({ email: 'nobody@example.test', password: STRONG_PASSWORD });
      const wrong = await t.http.post('/v1/auth/login').send({ email: 'known@example.test', password: 'not the password!' });
      expect(unknown.status).toBe(401);
      expect(wrong.status).toBe(401);
      expect(unknown.body.message).toBe(wrong.body.message);
      expect(unknown.headers['www-authenticate']).toBe(wrong.headers['www-authenticate']);
    });

    it('pays the hashing cost for unknown users too (no timing oracle)', async () => {
      const t = setup({ env: { SCRYPT_LOG_N: '14' } });
      await newUser(t, 'known@example.test');
      const time = async (email: string) => {
        const start = process.hrtime.bigint();
        await t.http.post('/v1/auth/login').send({ email, password: 'wrong password here' });
        return Number(process.hrtime.bigint() - start) / 1e6;
      };
      await time('warmup@example.test');
      const unknown = await time('ghost@example.test');
      const known = await time('known@example.test');
      // Without the dummy hash, the unknown-user path would be ~100x faster.
      expect(unknown).toBeGreaterThan(known * 0.4);
    });
  });

  describe('brute-force protection', () => {
    it('locks the account after 5 failures, without revealing the lock', async () => {
      const t = setup();
      await newUser(t, 'victim@example.test');
      for (let i = 0; i < 5; i++) {
        await t.http.post('/v1/auth/login').send({ email: 'victim@example.test', password: `guess number ${i}` }).expect(401);
      }
      // Even the right password is refused while locked, with the same generic message.
      const res = await t.http.post('/v1/auth/login').send({ email: 'victim@example.test', password: STRONG_PASSWORD }).expect(401);
      expect(res.body.message).toBe('Invalid e-mail or password');
      expect(auditActions(t)).toContain('auth.lockout:denied');
      expect(auditActions(t)).toContain('auth.login:denied');
    });

    it('counts concurrent failures atomically (no race to bypass the lockout)', async () => {
      const t = setup();
      await newUser(t, 'race@example.test');
      await Promise.all(
        Array.from({ length: 8 }, (_, i) => t.http.post('/v1/auth/login').send({ email: 'race@example.test', password: `parallel guess ${i}` })),
      );
      const row = t.db.prepare('SELECT failed_logins, locked_until FROM users WHERE email = ?').get('race@example.test') as {
        failed_logins: number;
        locked_until: number;
      };
      // Exactly the threshold: attempts landing after the lock are refused without being counted.
      expect(row.failed_logins).toBe(5);
      expect(row.locked_until).toBeGreaterThan(Date.now());
    });

    it('rate-limits authentication endpoints per client IP', async () => {
      const t = setup({ rateLimits: { global: 1000, auth: 3, refresh: 1000 } });
      for (let i = 0; i < 3; i++) await t.http.post('/v1/auth/login').send({ email: 'x@example.test', password: 'whatever pass' });
      const res = await t.http.post('/v1/auth/login').send({ email: 'x@example.test', password: 'whatever pass' }).expect(429);
      expect(res.headers.ratelimit).toBeDefined();
    });

    it('resets the failure counter after a successful login', async () => {
      const t = setup();
      await newUser(t, 'reset@example.test');
      for (let i = 0; i < 3; i++) await t.http.post('/v1/auth/login').send({ email: 'reset@example.test', password: `bad guess ${i}` });
      await t.http.post('/v1/auth/login').send({ email: 'reset@example.test', password: STRONG_PASSWORD }).expect(200);
      const row = t.db.prepare('SELECT failed_logins FROM users WHERE email = ?').get('reset@example.test') as { failed_logins: number };
      expect(row.failed_logins).toBe(0);
    });
  });

  it('transparently upgrades password hashes when the cost factor increases', async () => {
    const t = setup();
    await newUser(t, 'legacy@example.test');
    const t2 = { ...setup({ env: { SCRYPT_LOG_N: '11' } }) };
    // Same database, stronger configuration.
    const { createApp } = await import('../../src/app.js');
    const { createLogger } = await import('../../src/logger.js');
    const { loadCurriculum } = await import('../../src/curriculum/catalog.js');
    const upgraded = createApp({ config: t2.config, db: t.db, logger: createLogger('silent'), curriculum: loadCurriculum() });
    const request = (await import('supertest')).default;
    await request(upgraded.app).post('/v1/auth/login').send({ email: 'legacy@example.test', password: STRONG_PASSWORD }).expect(200);
    const row = t.db.prepare('SELECT password_hash FROM users WHERE email = ?').get('legacy@example.test') as { password_hash: string };
    expect(row.password_hash).toMatch(/^scrypt\$ln=11,/);
  });
});

describe('session management', () => {
  it('rotates refresh tokens: each one is single-use', async () => {
    const t = setup();
    const s = await newUser(t);
    const first = await t.http.post('/v1/auth/refresh').send({ refreshToken: s.refreshToken }).expect(200);
    expect(first.body.refreshToken).not.toBe(s.refreshToken);
    await t.http.post('/v1/auth/refresh').send({ refreshToken: first.body.refreshToken }).expect(200);
  });

  it('detects refresh-token reuse and kills the whole session family (RFC 9700)', async () => {
    const t = setup();
    const s = await newUser(t);
    // Legitimate client rotates…
    const rotated = await t.http.post('/v1/auth/refresh').send({ refreshToken: s.refreshToken }).expect(200);
    // …then an attacker replays the stolen, already-used token.
    await t.http.post('/v1/auth/refresh').send({ refreshToken: s.refreshToken }).expect(401);

    // The legitimate client's new refresh token AND its access token are now dead too.
    await t.http.post('/v1/auth/refresh').send({ refreshToken: rotated.body.refreshToken }).expect(401);
    await t.http.get('/v1/me').set({ Authorization: `Bearer ${rotated.body.accessToken}` }).expect(401);
    expect(auditActions(t)).toContain('auth.refresh_reuse_detected:denied');
  });

  it('lets only one of two concurrent refreshes with the same token succeed (TOCTOU)', async () => {
    const t = setup();
    const s = await newUser(t);
    const results = await Promise.all([
      t.http.post('/v1/auth/refresh').send({ refreshToken: s.refreshToken }),
      t.http.post('/v1/auth/refresh').send({ refreshToken: s.refreshToken }),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 401]);
  });

  it('rejects unknown and expired refresh tokens', async () => {
    const t = setup();
    const s = await newUser(t);
    await t.http.post('/v1/auth/refresh').send({ refreshToken: 'A'.repeat(43) }).expect(401);
    t.db.prepare('UPDATE refresh_tokens SET expires_at = 0').run();
    const res = await t.http.post('/v1/auth/refresh').send({ refreshToken: s.refreshToken }).expect(401);
    expect(res.body.message).toMatch(/expired/);
  });

  it('logout revokes the refresh token and is idempotent', async () => {
    const t = setup();
    const s = await newUser(t);
    await t.http.post('/v1/auth/logout').send({ refreshToken: s.refreshToken }).expect(204);
    await t.http.post('/v1/auth/logout').send({ refreshToken: s.refreshToken }).expect(204);
    await t.http.post('/v1/auth/logout').send({ refreshToken: 'B'.repeat(43) }).expect(204);
    await t.http.post('/v1/auth/refresh').send({ refreshToken: s.refreshToken }).expect(401);
  });

  it('"log out everywhere" invalidates still-unexpired access tokens immediately', async () => {
    const t = setup();
    const s = await newUser(t);
    await t.http.post('/v1/me/logout-all').set(s.auth).expect(204);
    const res = await t.http.get('/v1/me').set(s.auth).expect(401);
    expect(res.body.message).toBe('Session revoked');
    await t.http.post('/v1/auth/refresh').send({ refreshToken: s.refreshToken }).expect(401);
  });

  it('a password change revokes every existing session', async () => {
    const t = setup();
    const s = await newUser(t);
    await t.http
      .post('/v1/me/password')
      .set(s.auth)
      .send({ currentPassword: STRONG_PASSWORD, newPassword: 'an even longer new passphrase' })
      .expect(204);
    await t.http.get('/v1/me').set(s.auth).expect(401);
    await t.http.post('/v1/auth/login').send({ email: s.email, password: 'an even longer new passphrase' }).expect(200);
    await t.http.post('/v1/auth/login').send({ email: s.email, password: STRONG_PASSWORD }).expect(401);
  });

  it('password change requires the current password and a new, valid one', async () => {
    const t = setup();
    const s = await newUser(t);
    await t.http.post('/v1/me/password').set(s.auth).send({ currentPassword: 'wrong current pw', newPassword: 'whatever long enough' }).expect(401);
    await t.http.post('/v1/me/password').set(s.auth).send({ currentPassword: STRONG_PASSWORD, newPassword: 'short' }).expect(400);
    await t.http.post('/v1/me/password').set(s.auth).send({ currentPassword: STRONG_PASSWORD, newPassword: STRONG_PASSWORD }).expect(400);
  });

  it('rejects a token for a deleted account', async () => {
    const t = setup();
    const s = await newUser(t);
    t.db.prepare('DELETE FROM users WHERE id = ?').run(s.id);
    await t.http.get('/v1/me').set(s.auth).expect(401);
    await t.http.post('/v1/auth/refresh').send({ refreshToken: s.refreshToken }).expect(401);
  });

  it.each([
    ['no header', {}],
    ['wrong scheme', { Authorization: 'Basic dXNlcjpwYXNz' }],
    ['malformed token', { Authorization: 'Bearer not-a-jwt' }],
    ['garbage JWT', { Authorization: 'Bearer aaa.bbb.ccc' }],
  ])('rejects requests with %s', async (_n, headers) => {
    const t = setup();
    const res = await t.http.get('/v1/me').set(headers).expect(401);
    expect(res.headers['www-authenticate']).toContain('Bearer');
  });
});
