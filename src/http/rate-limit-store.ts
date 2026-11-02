import { createHash } from 'node:crypto';
import type { ClientRateLimitInfo, IncrementResponse, Options, Store } from 'express-rate-limit';
import { unavailable } from '../errors.js';
import type { RedisClient } from '../redis.js';

/**
 * Rate-limit counters shared by every replica (ADR 0023). In memory, each replica counts on
 * its own and N replicas allow N times the limit; in Redis there is one counter per client.
 *
 * Increment and expiry are one Lua script, so they are atomic on the server: two replicas
 * counting the same client cannot both see "first hit" and reset each other's window, and a
 * key can never be left without an expiry (a crash between INCR and PEXPIRE would make it
 * a permanent ban). A key that somehow lost its TTL gets one back.
 */
const INCREMENT = `
local hits = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return { hits, ttl }
`;

/** Undo one hit (skipped requests), never below zero and never creating a key. */
const DECREMENT = `
if redis.call('EXISTS', KEYS[1]) == 1 and tonumber(redis.call('GET', KEYS[1])) > 0 then
  return redis.call('DECR', KEYS[1])
end
return 0
`;

/** Every rate limiter of the API: a closed set, also the label values of the error counter. */
export const LIMITERS = ['global', 'auth', 'refresh', 'quiz', 'flag', 'lab', 'detect'] as const;
export type LimiterName = (typeof LIMITERS)[number];

export interface RedisStoreOptions {
  /** Part of every key, so limiters never share a counter. */
  name: LimiterName;
  /**
   * When Redis is down: closed (503) for limiters that guard against guessing (auth, flags,
   * quizzes), open for the global flood guard, so a Redis outage does not take the whole
   * API down with it. Every store failure is counted either way.
   */
  failOpen: boolean;
  onError: (name: LimiterName, err: unknown) => void;
  /** Tests only: isolates parallel test contexts that share one Redis (still under bastion:rl:*). */
  namespace?: string;
}

export class RedisRateLimitStore implements Store {
  readonly localKeys = false;
  readonly prefix: string;
  private windowMs = 15 * 60 * 1000;

  constructor(
    private readonly redis: RedisClient,
    private readonly options: RedisStoreOptions,
  ) {
    this.prefix = `bastion:rl:${options.namespace === undefined ? '' : `${options.namespace}:`}${options.name}:`;
  }

  init(options: Options): void {
    this.windowMs = options.windowMs;
  }

  /**
   * Keys are IP addresses and user ids: hashed, so Redis holds no personal data in clear
   * and every key has the same bounded length.
   */
  private key(key: string): string {
    return this.prefix + createHash('sha256').update(key).digest('base64url');
  }

  async increment(key: string): Promise<IncrementResponse> {
    try {
      const reply = await this.redis.command(['EVAL', INCREMENT, 1, this.key(key), this.windowMs]);
      if (!Array.isArray(reply) || typeof reply[0] !== 'number' || typeof reply[1] !== 'number') throw new Error('unexpected reply');
      return { totalHits: reply[0], resetTime: new Date(Date.now() + reply[1]) };
    } catch (err) {
      this.options.onError(this.options.name, err);
      // Open: one hit in a fresh window, i.e. not limited. Closed: the request is refused.
      if (this.options.failOpen) return { totalHits: 1, resetTime: new Date(Date.now() + this.windowMs) };
      throw unavailable('Service temporarily unavailable, try again shortly');
    }
  }

  async get(key: string): Promise<ClientRateLimitInfo | undefined> {
    const reply = await this.redis.command(['EVAL', 'return { tonumber(redis.call("GET", KEYS[1]) or "0"), redis.call("PTTL", KEYS[1]) }', 1, this.key(key)]);
    if (!Array.isArray(reply) || typeof reply[0] !== 'number' || typeof reply[1] !== 'number' || reply[0] === 0) return undefined;
    return { totalHits: reply[0], resetTime: new Date(Date.now() + Math.max(reply[1], 0)) };
  }

  async decrement(key: string): Promise<void> {
    try {
      await this.redis.command(['EVAL', DECREMENT, 1, this.key(key)]);
    } catch (err) {
      // Losing an undo only makes the limit slightly stricter: never fail the request for it.
      this.options.onError(this.options.name, err);
    }
  }

  async resetKey(key: string): Promise<void> {
    await this.redis.command(['DEL', this.key(key)]);
  }
}
