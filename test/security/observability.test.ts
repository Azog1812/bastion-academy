import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { metricsListener } from '../../src/http/metrics.js';
import { createLogger } from '../../src/logger.js';
import { newUser, setup, STRONG_PASSWORD, type TestContext } from '../helpers.js';

const TOKEN = randomBytes(32);
const scrape = (t: TestContext) => request(createServer(metricsListener(t.metrics.registry, TOKEN, createLogger('silent'))));
const bearer = { Authorization: `Bearer ${TOKEN.toString('base64')}` };
const metricsText = async (t: TestContext) => (await scrape(t).get('/metrics').set(bearer).expect(200)).text;

describe('metrics endpoint (ADR 0011)', () => {
  it('is never served by the API listener', async () => {
    const t = setup();
    await t.http.get('/metrics').expect(404);
    await t.http.get('/v1/metrics').expect(404);
  });

  it('requires the bearer token, compared in constant time', async () => {
    const t = setup();
    await scrape(t).get('/metrics').expect(401).expect('www-authenticate', 'Bearer');
    await scrape(t).get('/metrics').set({ Authorization: `Bearer ${randomBytes(32).toString('base64')}` }).expect(401);
    await scrape(t).get('/metrics').set({ Authorization: `Basic ${TOKEN.toString('base64')}` }).expect(401);
    await scrape(t).get('/metrics').set({ Authorization: 'Bearer ' }).expect(401);
    const res = await scrape(t).get('/metrics').set(bearer).expect(200);
    expect(res.headers['content-type']).toBe('text/plain; version=0.0.4; charset=utf-8');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.text).toContain('# TYPE http_requests_total counter');
  });

  it('serves only GET /metrics', async () => {
    const t = setup();
    await scrape(t).post('/metrics').set(bearer).expect(405).expect('allow', 'GET');
    await scrape(t).get('/').set(bearer).expect(404);
    await scrape(t).get('/metrics/../admin').set(bearer).expect(404);
  });

  it('fails a scrape without leaking why when a collector breaks', async () => {
    const t = setup();
    t.db.close(); // every database gauge now throws
    const res = await scrape(t).get('/metrics').set(bearer).expect(500);
    expect(res.text).toBe('scrape failed\n');
  });
});

describe('what the metrics contain', () => {
  it('labels requests by route pattern, never by URL: no ids, no attacker input', async () => {
    const t = setup();
    const alice = await newUser(t);
    const id = '0f3c1b8e-0000-4000-8000-000000000000';
    await t.http.get(`/v1/notes/${id}`).set(alice.auth).expect(404);
    await t.http.get('/v1/does-not-exist/%22%7D%20evil').expect(404);
    const text = await metricsText(t);
    expect(text).toContain('http_requests_total{method="GET",route="/v1/notes/:id",status="404"} 1\n');
    expect(text).toContain('http_requests_total{method="GET",route="none",status="404"} 1\n');
    expect(text).toMatch(/http_request_duration_seconds_count\{method="POST",route="\/v1\/auth\/login"\} 1\n/);
    expect(text).not.toContain(id);
    expect(text).not.toContain('evil');
  });

  it('counts security events from the audit log, without personal data', async () => {
    const t = setup();
    const alice = await newUser(t, 'alice.metrics@example.test');
    for (let i = 0; i < 2; i++) {
      await t.http.post('/v1/auth/login').send({ email: alice.email, password: `${STRONG_PASSWORD} nope` }).expect(401);
    }
    await t.http.post('/v1/auth/login').send({ email: 'nobody@example.test', password: STRONG_PASSWORD }).expect(401);
    const text = await metricsText(t);
    expect(text).toContain('bastion_audit_events_total{action="auth.login",outcome="failure"} 3\n');
    expect(text).toContain('bastion_audit_events_total{action="auth.login",outcome="success"} 1\n');
    expect(text).toContain('bastion_audit_events_total{action="auth.register",outcome="success"} 1\n');
    expect(text).toContain('bastion_users 1\n');
    expect(text).toContain('bastion_mfa_enabled_users 0\n');
    expect(text).toContain('bastion_labs_active 0\n');
    expect(text).not.toContain('example.test');
    expect(text).not.toContain(alice.id);
    expect(text).not.toMatch(/127\.0\.0\.1|::ffff/);
  });

  it('counts a refresh token replay, the signal behind the token-theft alert', async () => {
    const t = setup();
    const alice = await newUser(t);
    await t.http.post('/v1/auth/refresh').send({ refreshToken: alice.refreshToken }).expect(200);
    await t.http.post('/v1/auth/refresh').send({ refreshToken: alice.refreshToken }).expect(401);
    expect(t.metrics.auditEvents.value({ action: 'auth.refresh_reuse_detected', outcome: 'denied' })).toBe(1);
  });

  it('counts ciphertext integrity failures (database tampering)', async () => {
    const t = setup();
    const alice = await newUser(t);
    const mallory = await newUser(t);
    const { body } = await t.http.post('/v1/notes').set(alice.auth).send({ title: 't', body: 'c' }).expect(201);
    t.db.prepare('UPDATE notes SET owner_id = ? WHERE id = ?').run(mallory.id, body.id);
    await t.http.get(`/v1/notes/${String(body.id)}`).set(mallory.auth).expect(500);
    expect(await metricsText(t)).toContain('bastion_integrity_failures_total 1\n');
  });

  it('exports every security counter at 0 before the first event, so increase() alerts can fire (regression)', async () => {
    const t = setup();
    const text = await metricsText(t);
    expect(text).toContain('bastion_audit_events_total{action="auth.refresh_reuse_detected",outcome="denied"} 0\n');
    expect(text).toContain('bastion_audit_events_total{action="challenge.flag_shared",outcome="denied"} 0\n');
    expect(text).toContain('bastion_integrity_failures_total 0\n');
    expect(text).toContain('bastion_metrics_series_dropped_total 0\n');
  });

  it('exposes runtime health', async () => {
    const t = setup();
    const text = await metricsText(t);
    for (const name of ['process_resident_memory_bytes', 'nodejs_heap_used_bytes', 'process_start_time_seconds', 'nodejs_eventloop_delay_p99_seconds']) {
      expect(text).toMatch(new RegExp(`^${name} [0-9.e+-]+$`, 'm'));
    }
    expect(text).toContain(`bastion_build_info{node_version="${process.version}"} 1\n`);
  });
});
