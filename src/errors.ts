/**
 * Errors that are safe to show to a client. Anything else is reported as a
 * generic 500 so internal details (stack traces, SQL, paths) never leak.
 */
export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly headers: Record<string, string> = {},
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

export const badRequest = (message: string) => new HttpError(400, 'bad_request', message);
export const unauthorized = (message = 'Authentication required') =>
  new HttpError(401, 'unauthorized', message, { 'WWW-Authenticate': 'Bearer realm="bastion"' });
export const forbidden = (message = 'Forbidden') => new HttpError(403, 'forbidden', message);
/** Also used for "exists but belongs to someone else": never confirm another user's resource exists. */
export const notFound = (message = 'Not found') => new HttpError(404, 'not_found', message);
export const conflict = (message: string) => new HttpError(409, 'conflict', message);
export const locked = (retryAfterSeconds: number) =>
  new HttpError(429, 'too_many_attempts', 'Too many failed attempts, try again later', {
    'Retry-After': String(retryAfterSeconds),
  });
