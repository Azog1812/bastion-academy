import { createHash, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { RequestHandler } from 'express';
import type { Logger } from 'pino';
import type { AppMetrics, Registry } from '../metrics.js';

const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
/** Where routers are mounted in app.ts. Express clears req.baseUrl when an error leaves a router, so it is not reliable at 'finish'. */
const MOUNTS = ['/v1'];
const mountOf = (url: string) => MOUNTS.find((m) => url === m || url.startsWith(`${m}/`) || url.startsWith(`${m}?`)) ?? '';

/**
 * Counts and times every request by route *pattern* (/v1/notes/:id), never by
 * URL: the URL carries ids and anything an attacker types, which would turn
 * each request into a new series. Requests no route matched (static files,
 * 404s, the global rate limiter) share the route label "none".
 */
export function httpMetrics(m: AppMetrics): RequestHandler {
  return (req, res, next) => {
    const start = process.hrtime.bigint();
    res.on('finish', () => {
      const r: unknown = req.route;
      const pattern = typeof r === 'object' && r !== null && 'path' in r && typeof r.path === 'string' ? r.path : undefined;
      const route = pattern === undefined ? 'none' : mountOf(req.originalUrl) + pattern;
      const method = METHODS.has(req.method) ? req.method : 'OTHER';
      m.httpRequests.inc({ method, route, status: String(res.statusCode) });
      m.httpDuration.observe({ method, route }, Number(process.hrtime.bigint() - start) / 1e9);
    });
    next();
  };
}

const sha256 = (v: string | Buffer) => createHash('sha256').update(v).digest();

/**
 * The scrape endpoint, on its own listener and port (METRICS_PORT): the ingress
 * and the published port only ever reach the API, so /metrics is never on the
 * Internet even if a proxy rule is wrong. A bearer token is the second barrier:
 * metrics reveal how many accounts exist and whether a brute force is being
 * noticed. Both sides are hashed first so the comparison is constant-time
 * whatever the length of what the client sent.
 */
export function metricsListener(registry: Registry, token: Buffer, log: Logger): (req: IncomingMessage, res: ServerResponse) => void {
  const expected = sha256(token.toString('base64'));
  return (req, res) => {
    const reply = (status: number, body: string, headers: Record<string, string> = {}) => {
      res.writeHead(status, {
        'content-type': 'text/plain; charset=utf-8',
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
        ...headers,
      });
      res.end(body);
    };
    if (new URL(req.url ?? '/', 'http://metrics').pathname !== '/metrics') {
      reply(404, 'not found\n');
      return;
    }
    if (req.method !== 'GET') {
      reply(405, 'method not allowed\n', { allow: 'GET' });
      return;
    }
    const header = req.headers.authorization ?? '';
    const presented = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (!timingSafeEqual(sha256(presented), expected)) {
      reply(401, 'unauthorized\n', { 'www-authenticate': 'Bearer' });
      return;
    }
    try {
      reply(200, registry.render(), { 'content-type': 'text/plain; version=0.0.4; charset=utf-8' });
    } catch (err) {
      // A failed scrape is visible in Prometheus (up == 0); the reason stays in our logs, not in the body.
      log.error({ err }, 'metrics scrape failed');
      reply(500, 'scrape failed\n');
    }
  };
}
