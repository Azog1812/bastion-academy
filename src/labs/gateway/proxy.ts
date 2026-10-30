import { createServer, request, type IncomingHttpHeaders, type Server } from 'node:http';
import { containerName } from '../catalog.js';

/**
 * Lab gateway: the only published entry to the labs (127.0.0.1 only).
 * `l<instance>.lab.localhost` is routed to that instance's container.
 *
 * - The upstream is BUILT from a 32-hex instance id, never taken from the
 *   request: the gateway cannot be turned into an open proxy (SSRF).
 * - Every lab has its own origin, distinct from the platform's: a lab's XSS
 *   or cookies cannot reach the Bastion session (ADR 0009).
 * - It holds no secret and has no Docker access.
 */
const HOST = /^l([0-9a-f]{32})\.lab\.localhost$/;

export function instanceFromHost(host: string | undefined): string | null {
  const name = (host ?? '').toLowerCase().replace(/:\d{1,5}$/, '');
  return HOST.exec(name)?.[1] ?? null;
}

/** Hop-by-hop headers (RFC 9110 §7.6.1) are not forwarded. */
const HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
function forwardable(headers: IncomingHttpHeaders): IncomingHttpHeaders {
  return Object.fromEntries(Object.entries(headers).filter(([k]) => !HOP.has(k.toLowerCase())));
}

const PAGE = (title: string, text: string) =>
  `<!doctype html><html lang="fr"><meta charset="utf-8"><title>${title}</title><body style="font-family:system-ui,sans-serif;max-width:36rem;margin:4rem auto"><h1>${title}</h1><p>${text}</p></body></html>`;

export type Resolve = (instanceId: string) => { host: string; port: number };

export function createGateway(resolve: Resolve = (id) => ({ host: containerName(id), port: 8080 })): Server {
  return createServer((req, res) => {
    const id = instanceFromHost(req.headers.host);
    const fail = (status: number, title: string, text: string) => {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(PAGE(title, text));
    };
    if (!id) {
      if (req.url === '/healthz') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"status":"ok"}');
        return;
      }
      fail(404, 'Lab inconnu', 'Cette adresse ne correspond à aucun lab.');
      return;
    }
    const target = resolve(id);
    const upstream = request(
      { host: target.host, port: target.port, method: req.method, path: req.url, headers: forwardable(req.headers), timeout: 30_000 },
      (up) => {
        res.writeHead(up.statusCode ?? 502, forwardable(up.headers));
        up.pipe(res);
      },
    );
    upstream.on('timeout', () => upstream.destroy(new Error('timeout')));
    upstream.on('error', () => {
      fail(502, 'Lab indisponible', 'Ce lab est en cours de démarrage, arrêté ou expiré. Patiente quelques secondes, sinon arrête-le puis redémarre-le depuis la page du défi.');
    });
    req.pipe(upstream);
  });
}
