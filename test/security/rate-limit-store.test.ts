import { randomBytes } from 'node:crypto';
import { afterAll, describe, expect, it } from 'vitest';
import { RedisRateLimitStore } from '../../src/http/rate-limit-store.js';
import { RedisClient } from '../../src/redis.js';
import { setup } from '../helpers.js';

/**
 * Shared rate limits (ADR 0023). With one counter per replica, N replicas allow N times
 * the configured attempts; these tests run two replicas against one Redis and check the
 * limit holds across them, under concurrency, and what happens when Redis is gone.
 */
const login = { email: 'victim@example.test', password: 'not the password' };

describe('rate limits when Redis is unreachable', () => {
  // Nothing listens there; a connection attempt times out after 200 ms.
  const down = new RedisClient('redis://127.0.0.1:9', { timeoutMs: 200, retryAfterMs: 60_000 });
  afterAll(() => {
    down.close();
  });

  it('refuses guessing (auth fails closed, 503) but keeps serving (global fails open)', async () => {
    const t = setup({ redis: { client: down }, rateLimits: { global: 1, auth: 1, refresh: 1, quiz: 1 } });
    const res = await t.http.post('/v1/auth/login').send(login).expect(503);
    expect(res.body.message).toBe('Service temporarily unavailable, try again shortly');
    expect(JSON.stringify(res.body)).not.toMatch(/redis|127\.0\.0\.1|timeout/i);
    // Global limit is 1, yet requests keep flowing: an outage is not a lockout of everyone.
    for (let i = 0; i < 3; i++) await t.http.get('/v1/curriculum').expect(401);
    const metrics = await t.metrics.registry.render();
    expect(metrics).toMatch(/bastion_rate_limit_store_errors_total\{limiter="auth"\} [1-9]/);
    expect(metrics).toMatch(/bastion_rate_limit_store_errors_total\{limiter="global"\} [1-9]/);
    expect(metrics).toContain('bastion_rate_limit_store_errors_total{limiter="detect"} 0');
  });
});

describe.skipIf(!process.env.TEST_REDIS_URL)('rate limits shared through Redis', () => {
  const client = new RedisClient(process.env.TEST_REDIS_URL ?? 'redis://127.0.0.1:6379');
  afterAll(() => {
    client.close();
  });
  /** Two replicas: separate processes in production, separate apps here, one Redis. */
  const replicas = (auth: number) => {
    const redis = { client, namespace: randomBytes(6).toString('hex') };
    const limits = { global: 10_000, auth, refresh: 10_000, quiz: 10_000 };
    return [setup({ redis, rateLimits: limits }), setup({ redis, rateLimits: limits })] as const;
  };

  it('counts one budget across replicas, where in memory each would grant its own', async () => {
    const [a, b] = replicas(3);
    await a.http.post('/v1/auth/login').send(login).expect(401);
    await b.http.post('/v1/auth/login').send(login).expect(401);
    await a.http.post('/v1/auth/login').send(login).expect(401);
    // Fourth attempt, on the other replica: refused.
    const res = await b.http.post('/v1/auth/login').send(login).expect(429);
    expect(res.headers.ratelimit).toMatch(/r=0/);
  });

  it('keeps the budget under concurrent requests to both replicas', async () => {
    const [a, b] = replicas(10);
    const results = await Promise.all(Array.from({ length: 24 }, (_, i) => (i % 2 === 0 ? a : b).http.post('/v1/auth/login').send(login)));
    expect(results.filter((r) => r.status === 401)).toHaveLength(10);
    expect(results.filter((r) => r.status === 429)).toHaveLength(14);
  });

  it('stores counters under hashed keys, with an expiry, never below zero', async () => {
    const store = new RedisRateLimitStore(client, { name: 'auth', failOpen: false, onError: () => undefined, namespace: randomBytes(6).toString('hex') });
    store.init({ windowMs: 60_000 } as Parameters<typeof store.init>[0]);
    const first = await store.increment('203.0.113.7');
    expect(first.totalHits).toBe(1);
    expect((first.resetTime?.getTime() ?? 0) - Date.now()).toBeGreaterThan(55_000);
    expect((await store.increment('203.0.113.7')).totalHits).toBe(2);
    // The address itself is not in Redis: the key is its SHA-256.
    expect(await client.command(['EXISTS', `${store.prefix}203.0.113.7`])).toBe(0);
    expect((await store.get('203.0.113.7'))?.totalHits).toBe(2);
    await store.decrement('203.0.113.7');
    await store.decrement('203.0.113.7');
    await store.decrement('203.0.113.7');
    expect(await store.get('203.0.113.7')).toBeUndefined();
    await store.decrement('never-seen');
    expect(await store.get('never-seen')).toBeUndefined();
    await store.increment('x');
    await store.resetKey('x');
    expect(await store.get('x')).toBeUndefined();
  });
});
