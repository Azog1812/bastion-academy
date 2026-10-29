import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { REFRESH_COOKIE, readCookie } from '../../src/http/session.js';
import { WEB_CSP } from '../../src/http/web.js';
import { auditActions, setup, STRONG_PASSWORD, type TestContext } from '../helpers.js';

const HOST = 'academy.test';
const ORIGIN = `http://${HOST}`;

async function browserLogin(t: TestContext, email = 'web@example.test') {
  await t.http.post('/v1/auth/register').send({ email, password: STRONG_PASSWORD }).expect(201);
  const res = await t.http.post('/v1/session/login').set('Host', HOST).set('Origin', ORIGIN).send({ email, password: STRONG_PASSWORD }).expect(200);
  return { res, cookie: cookieFrom(res.headers['set-cookie']) };
}

function cookieFrom(setCookie: unknown): string {
  const header = (Array.isArray(setCookie) ? setCookie : [setCookie]).join(';');
  const value = readCookie(header, REFRESH_COOKIE);
  if (value === undefined) throw new Error('no refresh cookie');
  return `${REFRESH_COOKIE}=${value}`;
}

const refresh = (t: TestContext, cookie?: string) => {
  const req = t.http.post('/v1/session/refresh').set('Host', HOST).set('Origin', ORIGIN);
  return (cookie ? req.set('Cookie', cookie) : req).send({});
};

describe('browser sessions: refresh token in an HttpOnly cookie (ADR 0007)', () => {
  it('login sets a hardened __Host- cookie and never returns the refresh token to JavaScript', async () => {
    const t = setup();
    const { res } = await browserLogin(t);
    const setCookie = String(res.headers['set-cookie']);
    expect(setCookie).toMatch(/^__Host-bastion_rt=[A-Za-z0-9_-]{20,}; /);
    for (const attr of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/', `Max-Age=${String(t.config.REFRESH_TOKEN_TTL_SECONDS)}`]) {
      expect(setCookie).toContain(attr);
    }
    expect(setCookie).not.toMatch(/Domain=/i);
    expect(res.body).toEqual({ accessToken: expect.any(String), tokenType: 'Bearer', expiresIn: t.config.ACCESS_TOKEN_TTL_SECONDS });
    await t.http.get('/v1/me').set('Authorization', `Bearer ${res.body.accessToken as string}`).expect(200);
  });

  it('refresh rotates the cookie; replaying the old one kills the session and clears the cookie', async () => {
    const t = setup();
    const { cookie } = await browserLogin(t);

    const first = await refresh(t, cookie).expect(200);
    const rotated = cookieFrom(first.headers['set-cookie']);
    expect(rotated).not.toBe(cookie);
    expect(first.body).not.toHaveProperty('refreshToken');

    const replay = await refresh(t, cookie).expect(401);
    expect(String(replay.headers['set-cookie'])).toMatch(/^__Host-bastion_rt=; Max-Age=0/);
    // Reuse detection revoked the whole family, including the legitimate rotated cookie.
    await refresh(t, rotated).expect(401);
    expect(auditActions(t)).toContain('auth.refresh_reuse_detected:denied');
  });

  it('refuses refresh without a well-formed cookie', async () => {
    const t = setup();
    await refresh(t).expect(401);
    await refresh(t, `${REFRESH_COOKIE}=../../etc/passwd`).expect(401);
    await refresh(t, `${REFRESH_COOKIE}=${'a'.repeat(500)}`).expect(401);
    await refresh(t, 'other=1').expect(401);
  });

  it('logout revokes the session server-side, clears the cookie and is idempotent', async () => {
    const t = setup();
    const { cookie } = await browserLogin(t);
    const out = await t.http.post('/v1/session/logout').set('Host', HOST).set('Origin', ORIGIN).set('Cookie', cookie).send({}).expect(204);
    expect(String(out.headers['set-cookie'])).toContain('Max-Age=0');
    await refresh(t, cookie).expect(401);
    await t.http.post('/v1/session/logout').set('Host', HOST).set('Origin', ORIGIN).send({}).expect(204);
  });

  it('rejects cross-origin and non-JSON requests on cookie routes (CSRF)', async () => {
    const t = setup();
    const { cookie } = await browserLogin(t);
    await t.http.post('/v1/session/refresh').set('Host', HOST).set('Origin', 'https://evil.test').set('Cookie', cookie).send({}).expect(403);
    await t.http.post('/v1/session/logout').set('Host', HOST).set('Origin', 'null').set('Cookie', cookie).send({}).expect(403);
    await t.http
      .post('/v1/session/login')
      .set('Host', HOST)
      .set('Origin', 'https://evil.test')
      .send({ email: 'web@example.test', password: STRONG_PASSWORD })
      .expect(403);
    // An HTML form can only send form-encoded bodies: refused before any cookie is used.
    await t.http.post('/v1/session/refresh').set('Host', HOST).set('Cookie', cookie).type('form').send('x=1').expect(415);
    // The session survived all of the above.
    await refresh(t, cookie).expect(200);
  });

  it('keeps login enumeration-proof on the browser route', async () => {
    const t = setup();
    await browserLogin(t);
    const wrong = await t.http.post('/v1/session/login').set('Host', HOST).send({ email: 'web@example.test', password: 'wrong password!!' }).expect(401);
    const unknown = await t.http.post('/v1/session/login').set('Host', HOST).send({ email: 'nobody@example.test', password: 'wrong password!!' }).expect(401);
    expect(wrong.body.message).toBe(unknown.body.message);
    expect(wrong.headers['set-cookie']).toBeUndefined();
  });
});

describe('web front-end delivery', () => {
  const jsDir = mkdtempSync(join(tmpdir(), 'web-js-'));
  writeFileSync(join(jsDir, 'main.js'), 'export {};');
  afterAll(() => {
    rmSync(jsDir, { recursive: true, force: true });
  });

  it('serves the page with a strict CSP including Trusted Types', async () => {
    const t = setup({ web: { jsDir } });
    const page = await t.http.get('/').expect(200);
    expect(page.headers['content-type']).toMatch(/text\/html/);
    expect(page.text).toContain('<script type="module" src="/js/main.js">');
    expect(page.headers['content-security-policy']).toBe(WEB_CSP);
    expect(WEB_CSP).toContain("require-trusted-types-for 'script'");
    expect(WEB_CSP).not.toMatch(/unsafe-inline|unsafe-eval|\*/);
    expect(page.headers['x-frame-options']).toBe('DENY');

    const js = await t.http.get('/js/main.js').expect(200);
    expect(js.headers['content-type']).toMatch(/javascript/);
    expect(js.headers['content-security-policy']).toBe(WEB_CSP);
  });

  it('pages contain no inline script or style (they would be blocked by the CSP anyway)', async () => {
    const t = setup({ web: { jsDir } });
    const page = await t.http.get('/').expect(200);
    expect(page.text).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/);
    expect(page.text).not.toMatch(/\son[a-z]+=|<style|style=/i);
  });

  it('API responses keep their own default-src none policy', async () => {
    const t = setup({ web: { jsDir } });
    const res = await t.http.get('/v1/me').expect(401);
    expect(res.headers['content-security-policy']).toMatch(/^default-src 'none'/);
    expect(res.headers['content-type']).toMatch(/json/);
  });

  it('does not list directories, serve dotfiles or escape the web root', async () => {
    const t = setup({ web: { jsDir } });
    await t.http.get('/js/').expect(404);
    await t.http.get('/.env').expect((r) => {
      expect([403, 404]).toContain(r.status);
    });
    for (const path of ['/..%2Fpackage.json', '/js/..%2F..%2Fpackage.json', '/%2e%2e/%2e%2e/package.json', '/js/%2e%2e%2f%2e%2e%2fpackage.json']) {
      const res = await t.http.get(path);
      expect(res.text, path).not.toContain('"name": "bastion"');
      expect([400, 403, 404], path).toContain(res.status);
    }
  });
});
