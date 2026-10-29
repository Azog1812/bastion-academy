import express, { Router } from 'express';
import { fileURLToPath } from 'node:url';

/**
 * Serves the web front-end (ADR 0007) from the same origin as the API, so no
 * CORS is needed and SameSite=Strict cookies just work.
 *
 * The API keeps its `default-src 'none'` policy. Pages get their own CSP,
 * still strict: same-origin scripts, styles and fetches only, no inline code,
 * and Trusted Types with no policy at all. The front-end never writes HTML
 * from strings (enforced by ESLint), so any `innerHTML`-style sink, ours or
 * injected, throws in the browser instead of executing.
 */
export const WEB_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "require-trusted-types-for 'script'",
  'trusted-types',
].join('; ');

/** `web/public` (HTML, CSS) and the compiled front-end, resolved from src/http or dist/http. */
export const WEB_PUBLIC_DIR = fileURLToPath(new URL('../../web/public/', import.meta.url));
export const WEB_JS_DIR = fileURLToPath(new URL('../../dist/web/', import.meta.url));

/** Applied only to files actually served, so API responses keep their own, stricter headers. */
function pageHeaders(res: express.Response): void {
  res.setHeader('Content-Security-Policy', WEB_CSP);
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  // Pages hold no secret (the access token lives in memory), but a shared
  // cache must still revalidate rather than serve a stale build.
  res.setHeader('Cache-Control', 'no-cache');
}

export function webRouter(dirs: { publicDir?: string; jsDir?: string } = {}): Router {
  const r = Router();
  const options = { dotfiles: 'deny', redirect: false, fallthrough: true, setHeaders: pageHeaders } as const;
  r.use(express.static(dirs.publicDir ?? WEB_PUBLIC_DIR, { ...options, index: 'index.html' }));
  r.use('/js', express.static(dirs.jsDir ?? WEB_JS_DIR, { ...options, index: false }));
  return r;
}
