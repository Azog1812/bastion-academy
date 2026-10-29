# 0003 — Short-lived JWT + opaque rotating refresh tokens, revocable

**Status:** accepted

## Context
Pure stateless JWTs cannot be revoked; pure server sessions need a lookup per request
anyway. We want immediate revocation (logout everywhere, password change, theft) and
immediate demotion of admins.

## Decision
- Access token: JWT HS256, 15 min, `iss`/`aud`/`typ`/`jti` checked, algorithm allow-list.
- On each request the user's `token_version` and role are read from the DB (one indexed
  primary-key lookup). Bumping `token_version` kills every live access token at once.
- Refresh token: 256-bit opaque random value, stored as SHA-256, single use, rotated on
  every refresh, grouped in families. Reuse of a consumed token revokes the family and
  bumps `token_version` (RFC 9700, OAuth 2.0 Security BCP §4.14).

## Consequences
- Revocation and demotion are instantaneous; a stolen refresh token is self-defeating.
- One DB read per authenticated request (cheap with SQLite, would be cached with Redis at scale).
- HS256 means only this service can verify tokens; switching to EdDSA + JWKS is needed if
  another service must verify them.
