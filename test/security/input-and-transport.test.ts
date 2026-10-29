import { describe, expect, it } from 'vitest';
import { newUser, setup, STRONG_PASSWORD } from '../helpers.js';

describe('injection resistance', () => {
  it.each([
    "' OR '1'='1",
    "admin'--",
    "x'; DROP TABLE users; --",
    '1 UNION SELECT password_hash FROM users',
  ])('treats SQL payload %j as plain data', async (payload) => {
    const t = setup();
    const s = await newUser(t);
    const note = await t.http.post('/v1/notes').set(s.auth).send({ title: payload, body: payload }).expect(201);
    const back = await t.http.get(`/v1/notes/${note.body.id as string}`).set(s.auth).expect(200);
    expect(back.body.title).toBe(payload.trim());
    // Login with an injection payload as e-mail is rejected by validation, never reaches SQL.
    await t.http.post('/v1/auth/login').send({ email: payload, password: 'x' }).expect(400);
    // Schema still intact.
    expect(t.db.prepare('SELECT COUNT(*) AS n FROM users').get()).toEqual({ n: 1 });
  });

  it('stores HTML/JS verbatim and serves it as JSON only (no reflected XSS surface)', async () => {
    const t = setup();
    const s = await newUser(t);
    const xss = '<script>alert(document.cookie)</script>';
    const res = await t.http.post('/v1/notes').set(s.auth).send({ title: xss, body: xss }).expect(201);
    expect(res.headers['content-type']).toMatch(/^application\/json/);
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['content-security-policy']).toContain("default-src 'none'");
  });

  it('rejects prototype-pollution keys instead of merging them', async () => {
    const t = setup();
    const s = await newUser(t);
    await t.http
      .post('/v1/notes')
      .set(s.auth)
      .set('content-type', 'application/json')
      .send('{"title":"t","body":"b","__proto__":{"isAdmin":true}}')
      .expect(400);
    expect(({} as Record<string, unknown>).isAdmin).toBeUndefined();
  });

  it('rejects array / nested query parameters (HTTP parameter pollution)', async () => {
    const t = setup();
    const s = await newUser(t);
    await t.http.get('/v1/notes?limit=1&limit=99999').set(s.auth).expect(400);
    await t.http.get('/v1/notes?limit[$gt]=0').set(s.auth).expect(400);
  });

  it.each(['../../etc/passwd', '1', "1' OR 1=1", '%00'])('rejects non-UUID object id %j', async (id) => {
    const t = setup();
    const s = await newUser(t);
    await t.http.get(`/v1/notes/${encodeURIComponent(id)}`).set(s.auth).expect(400);
  });
});

describe('request hardening', () => {
  it('rejects malformed JSON with a generic message', async () => {
    const t = setup();
    const res = await t.http.post('/v1/auth/login').set('content-type', 'application/json').send('{"email":').expect(400);
    expect(res.body.error).toBe('malformed_body');
    expect(JSON.stringify(res.body)).not.toMatch(/at JSON|SyntaxError|node_modules/);
  });

  it('caps body size at 100 kB (resource exhaustion)', async () => {
    const t = setup();
    const res = await t.http
      .post('/v1/auth/login')
      .set('content-type', 'application/json')
      .send(JSON.stringify({ email: 'a@b.co', password: 'x'.repeat(200_000) }))
      .expect(413);
    expect(res.body.error).toBe('payload_too_large');
  });

  it('refuses oversized passwords before they reach the hash function', async () => {
    const t = setup();
    await t.http.post('/v1/auth/login').send({ email: 'a@example.test', password: 'x'.repeat(600) }).expect(400);
  });

  it('requires application/json on write requests (blocks HTML-form CSRF)', async () => {
    const t = setup();
    const res = await t.http
      .post('/v1/auth/login')
      .set('content-type', 'application/x-www-form-urlencoded')
      .send(`email=a@example.test&password=${encodeURIComponent(STRONG_PASSWORD)}`)
      .expect(415);
    expect(res.body.error).toBe('unsupported_media_type');
  });

  it('enforces size limits on note fields', async () => {
    const t = setup();
    const s = await newUser(t);
    await t.http.post('/v1/notes').set(s.auth).send({ title: 'x'.repeat(201), body: '' }).expect(400);
    await t.http.post('/v1/notes').set(s.auth).send({ title: '   ', body: '' }).expect(400);
  });

  it('only reuses well-formed inbound request ids (log injection)', async () => {
    const t = setup();
    const good = '3f2b8c1e-9a4d-4e7f-8b6a-1c2d3e4f5a6b';
    expect((await t.http.get('/healthz').set('x-request-id', good)).headers['x-request-id']).toBe(good);
    const evil = (await t.http.get('/healthz').set('x-request-id', 'forged" level="error" msg="admin login"')).headers['x-request-id'];
    expect(evil).toMatch(/^[0-9a-f-]{36}$/);
  });
});

describe('response hardening', () => {
  it('sends a strict set of security headers', async () => {
    const t = setup();
    const res = await t.http.get('/healthz').expect(200);
    expect(res.headers).toMatchObject({
      'content-security-policy': "default-src 'none';frame-ancestors 'none'",
      'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
      'cross-origin-resource-policy': 'same-origin',
      'cross-origin-opener-policy': 'same-origin',
    });
    expect(res.headers['permissions-policy']).toContain('camera=()');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  it('marks API responses as non-cacheable', async () => {
    const t = setup();
    const s = await newUser(t);
    const res = await t.http.get('/v1/me').set(s.auth).expect(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers.etag).toBeUndefined();
  });

  it('returns a uniform JSON 404 for unknown routes, with a correlation id', async () => {
    const t = setup();
    const res = await t.http.get('/v1/../../admin').expect(404);
    expect(res.body).toMatchObject({ error: 'not_found' });
    expect(res.body.requestId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('exposes liveness and readiness probes', async () => {
    const t = setup();
    await t.http.get('/healthz').expect(200, { status: 'ok' });
    await t.http.get('/readyz').expect(200, { status: 'ready' });
    t.db.close();
    await t.http.get('/readyz').expect(503);
  });
});
