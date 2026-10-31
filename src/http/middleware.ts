import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { Logger } from 'pino';
import { ZodError, type ZodType } from 'zod';
import type { AuditLog } from '../audit.js';
import { DecryptionError } from '../crypto/envelope.js';
import { InvalidTokenError, type Role, type TokenSigner } from '../crypto/tokens.js';
import { forbidden, HttpError, unauthorized } from '../errors.js';
import type { AuthService } from '../services/auth-service.js';

export interface Principal {
  id: string;
  role: Role;
}

declare module 'express-serve-static-core' {
  interface Request {
    id: string;
    principal?: Principal;
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Correlation id for logs. An inbound id is only reused if well-formed (no log injection). */
export const requestId: RequestHandler = (req, res, next) => {
  const inbound = req.get('x-request-id');
  req.id = inbound && UUID.test(inbound) ? inbound : randomUUID();
  res.setHeader('X-Request-Id', req.id);
  next();
};

/** Authenticated API responses must never be cached by browsers or intermediaries. */
export const noStore: RequestHandler = (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  next();
};

/** Bodies on write methods must be JSON: blocks content-type confusion and CSRF via HTML forms. */
export const requireJson: RequestHandler = (req, _res, next) => {
  const hasBody = ['POST', 'PUT', 'PATCH'].includes(req.method) && Number(req.get('content-length') ?? 0) > 0;
  if (hasBody && !req.is('application/json')) {
    next(new HttpError(415, 'unsupported_media_type', 'Content-Type must be application/json'));
    return;
  }
  next();
};

export function authenticate(signer: TokenSigner, auth: AuthService): RequestHandler {
  return async (req, _res, next) => {
    try {
      const header = req.get('authorization') ?? '';
      const match = /^Bearer ([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)$/.exec(header);
      if (!match) throw unauthorized();

      const claims = await signer.verify(match[1] as string);

      // A valid signature is not enough: the account must still exist and the
      // token must not predate a "log out everywhere" / password change.
      const state = auth.sessionState(claims.sub);
      if (!state || state.tokenVersion !== claims.tv) throw unauthorized('Session revoked');

      // Role comes from the database, not the token: a demotion takes effect immediately.
      req.principal = { id: claims.sub, role: state.role };
      next();
    } catch (err) {
      if (err instanceof InvalidTokenError) {
        next(unauthorized(err.reason === 'expired' ? 'Access token expired' : 'Invalid access token'));
        return;
      }
      next(err);
    }
  };
}

export function requireRole(role: Role, audit: AuditLog): RequestHandler {
  return (req, _res, next) => {
    if (req.principal?.role !== role) {
      audit.record({
        action: 'authz.denied',
        outcome: 'denied',
        actorId: req.principal?.id ?? null,
        target: req.originalUrl.slice(0, 200),
        ip: req.ip ?? null,
        details: { required: role },
      });
      next(forbidden());
      return;
    }
    next();
  };
}

export function parse<T>(schema: ZodType<T>, input: unknown): T {
  return schema.parse(input);
}

/** Express 5 forwards rejected promises to the error handler; this keeps handlers terse and typed. */
export const handler =
  (fn: (req: Request, res: Response) => Promise<void> | void): RequestHandler =>
  async (req, res, next) => {
    try {
      await fn(req, res);
    } catch (err) {
      next(err);
    }
  };

export function notFoundHandler(_req: Request, _res: Response, next: NextFunction): void {
  next(new HttpError(404, 'not_found', 'Route not found'));
}

/**
 * Single exit point for errors. Clients get a stable, minimal JSON shape
 * (RFC 9457-style); details stay in the server logs, keyed by request id.
 */
export function errorHandler(log: Logger, onIntegrityFailure: () => void = () => undefined) {
  // Express recognises error handlers by their 4-argument signature.
  return (err: unknown, req: Request, res: Response, _next: NextFunction): void => {
    let status = 500;
    let body: Record<string, unknown> = { error: 'internal_error', message: 'An unexpected error occurred' };

    if (err instanceof HttpError) {
      status = err.status;
      body = { error: err.code, message: err.message };
      for (const [k, v] of Object.entries(err.headers)) res.setHeader(k, v);
    } else if (err instanceof ZodError) {
      status = 400;
      body = {
        error: 'validation_error',
        message: 'Request validation failed',
        issues: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      };
    } else if (isBodyParserError(err)) {
      status = err.status;
      body =
        err.status === 413
          ? { error: 'payload_too_large', message: 'Payload too large' }
          : err.status === 415
            ? { error: 'unsupported_media_type', message: 'Unsupported body encoding' }
            : { error: 'malformed_body', message: 'Malformed JSON body' };
    } else if (err instanceof DecryptionError) {
      log.error({ reqId: req.id, err: { name: err.name } }, 'ciphertext integrity failure — possible tampering');
      onIntegrityFailure();
    }

    if (status >= 500) log.error({ reqId: req.id, err }, 'unhandled error');
    res.status(status).json({ ...body, requestId: req.id });
  };
}

function isBodyParserError(err: unknown): err is { status: number; type: string } {
  return (
    typeof err === 'object' &&
    err !== null &&
    'type' in err &&
    'status' in err &&
    typeof (err as { status: unknown }).status === 'number' &&
    (err as { status: number }).status >= 400 &&
    (err as { status: number }).status < 500
  );
}
