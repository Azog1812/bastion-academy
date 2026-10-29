import type { Request, RequestHandler, Response } from 'express';
import type { TokenPair } from '../services/auth-service.js';
import { forbidden, unauthorized } from '../errors.js';

/**
 * Browser sessions (ADR 0007).
 *
 * The web front-end never sees the refresh token: it lives in a cookie that
 * JavaScript cannot read (HttpOnly), so an XSS cannot steal a long-lived
 * session. The short-lived access token stays in memory only.
 *
 * `__Host-` prefix: the browser rejects the cookie unless it is Secure, has
 * Path=/ and no Domain, so a sibling subdomain cannot overwrite it (cookie
 * tossing). Browsers treat http://localhost as a secure context, so this also
 * works for the local install.
 */
export const REFRESH_COOKIE = '__Host-bastion_rt';

/** Minimal Cookie header parser: we read one cookie and need no dependency for it. */
export function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return undefined;
}

export function setRefreshCookie(res: Response, token: string, maxAgeSeconds: number): void {
  res.setHeader(
    'Set-Cookie',
    `${REFRESH_COOKIE}=${token}; Max-Age=${maxAgeSeconds}; Path=/; Secure; HttpOnly; SameSite=Strict`,
  );
}

export function clearRefreshCookie(res: Response): void {
  res.setHeader('Set-Cookie', `${REFRESH_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict`);
}

/** What the browser receives: everything except the refresh token. */
export const browserView = ({ accessToken, tokenType, expiresIn }: TokenPair) => ({ accessToken, tokenType, expiresIn });

export function refreshTokenFrom(req: Request): string {
  const token = readCookie(req.get('cookie'), REFRESH_COOKIE);
  // Same shape as issued tokens (base64url); anything else is not worth a DB lookup.
  if (!token || !/^[A-Za-z0-9_-]{20,200}$/.test(token)) throw unauthorized('No active session');
  return token;
}

/**
 * CSRF defence in depth for cookie-authenticated routes. SameSite=Strict is
 * the main barrier, and JSON-only bodies force a CORS preflight that no
 * other origin passes. On top of that, a request that announces a foreign
 * Origin is refused outright.
 */
export const sameOriginOnly: RequestHandler = (req, _res, next) => {
  const origin = req.get('origin');
  if (origin !== undefined && origin !== `${req.protocol}://${req.get('host') ?? ''}`) {
    next(forbidden('Cross-origin request refused'));
    return;
  }
  next();
};
