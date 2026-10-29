import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { SignJWT, jwtVerify, errors as joseErrors } from 'jose';

export type Role = 'user' | 'admin';

export interface AccessClaims {
  sub: string;
  role: Role;
  /** token version: bumped on password change / "log out everywhere" to revoke all live tokens */
  tv: number;
}

export interface TokenSigner {
  sign(claims: AccessClaims): Promise<string>;
  verify(token: string): Promise<AccessClaims>;
}

export class InvalidTokenError extends Error {
  constructor(readonly reason: 'expired' | 'invalid') {
    super(`Token ${reason}`);
    this.name = 'InvalidTokenError';
  }
}

/**
 * Short-lived access tokens (JWT, HS256).
 *
 * Classic JWT pitfalls and how they are closed here:
 *  - "alg: none" / algorithm confusion → `algorithms` is an explicit allow-list;
 *  - token replay across services       → `iss` and `aud` are required and checked;
 *  - unbounded lifetime                  → `exp` is mandatory, TTL capped at 1 h by config;
 *  - claims smuggling                    → claims are re-validated structurally after verify.
 */
export function createTokenSigner(opts: { secret: Buffer; issuer: string; audience: string; ttlSeconds: number }): TokenSigner {
  const key = new Uint8Array(opts.secret);

  return {
    async sign(claims) {
      return new SignJWT({ role: claims.role, tv: claims.tv })
        .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' })
        .setSubject(claims.sub)
        .setIssuer(opts.issuer)
        .setAudience(opts.audience)
        .setIssuedAt()
        .setNotBefore('0s')
        .setExpirationTime(`${opts.ttlSeconds}s`)
        .setJti(randomUUID())
        .sign(key);
    },

    async verify(token) {
      try {
        const { payload } = await jwtVerify(token, key, {
          algorithms: ['HS256'],
          issuer: opts.issuer,
          audience: opts.audience,
          typ: 'at+jwt',
          requiredClaims: ['exp', 'iat', 'sub', 'jti'],
          clockTolerance: 5,
        });
        const { sub, role, tv } = payload;
        if (typeof sub !== 'string' || (role !== 'user' && role !== 'admin') || typeof tv !== 'number') {
          throw new InvalidTokenError('invalid');
        }
        return { sub, role, tv };
      } catch (err) {
        if (err instanceof InvalidTokenError) throw err;
        if (err instanceof joseErrors.JWTExpired) throw new InvalidTokenError('expired');
        throw new InvalidTokenError('invalid');
      }
    },
  };
}

/** Opaque refresh token: 256 bits of entropy. Only its SHA-256 is stored. */
export function generateRefreshToken(): { token: string; hash: string } {
  const token = randomBytes(32).toString('base64url');
  return { token, hash: hashRefreshToken(token) };
}

export function hashRefreshToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}
