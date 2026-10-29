# Security controls — standards mapping

Each control points to the code that implements it and the test that proves it.
Standards: **OWASP API Security Top 10 (2023)** and **OWASP ASVS 4.0.3** (Level 2 target).

## OWASP API Security Top 10 — 2023

| Risk | Status | Implementation | Proof |
|---|---|---|---|
| API1 Broken Object Level Authorization | ✅ | Owner id inside every note query; same 404 for foreign and missing objects; Semgrep rule `bastion-note-query-without-owner` blocks regressions. Learning progress is scoped by `user_id` from the token, and no route accepts a user id ([`learning-service.ts`](../src/services/learning-service.ts)) | [`note-service.ts`](../src/services/note-service.ts), [`authorization.test.ts`](../test/security/authorization.test.ts) |
| API2 Broken Authentication | ✅ | scrypt, lockout, rate limit, short-lived JWT, rotating refresh tokens with reuse detection, revocation on password change | [`auth-service.ts`](../src/services/auth-service.ts), [`authentication.test.ts`](../test/security/authentication.test.ts) |
| API3 Broken Object Property Level Authorization | ✅ | Strict schemas reject unknown fields (no mass assignment); responses built explicitly, never from DB rows. Lessons are projected field by field so quiz answers never leave the server ([`learning.test.ts`](../test/security/learning.test.ts)) | [`schemas.ts`](../src/http/schemas.ts) |
| API4 Unrestricted Resource Consumption | ✅ | Rate limits, 100 kB body cap, field size caps, pagination cap (100), password length capped before hashing, socket timeouts, container memory/PID limits | [`app.ts`](../src/app.ts), [`input-and-transport.test.ts`](../test/security/input-and-transport.test.ts) |
| API5 Broken Function Level Authorization | ✅ | `requireRole('admin')` with role fetched from DB per request; no HTTP route grants privileges | [`middleware.ts`](../src/http/middleware.ts) |
| API6 Unrestricted Access to Sensitive Business Flows | ✅ | Registration and login rate-limited per IP; quiz submissions rate-limited per account; lesson completion gated by server-side prerequisites | [`routes.ts`](../src/http/routes.ts) |
| API7 Server Side Request Forgery | ✅ n/a | The API makes no outbound request; NetworkPolicy denies all egress | [`networkpolicy.yaml`](../deploy/k8s/networkpolicy.yaml) |
| API8 Security Misconfiguration | ✅ | Fail-closed config, strict headers, no `x-powered-by`, generic errors, hardened container and pod | [`config.ts`](../src/config.ts), [`deployment.yaml`](../deploy/k8s/deployment.yaml) |
| API9 Improper Inventory Management | ✅ | Versioned API (`/v1`), OpenAPI spec kept in repo and exercised by DAST | [`openapi.yaml`](openapi.yaml) |
| API10 Unsafe Consumption of APIs | ✅ n/a | No third-party API consumed | — |

## OWASP ASVS 4.0.3 (selected Level 2 requirements)

### V2 Authentication
| ID | Requirement (summary) | How |
|---|---|---|
| 2.1.1 | Passwords ≥ 12 characters | `PASSWORD_MIN = 12` |
| 2.1.2 | Passwords of 64+ characters allowed, ≤ 128 | `PASSWORD_MAX = 128` |
| 2.1.4 | Any printable Unicode allowed | No character restriction; NFKC normalisation |
| 2.1.7 | Check against breached passwords | SecLists NCSC top-100k (12+ chars) blocklist |
| 2.1.9 | No composition rules | Length + blocklist only |
| 2.2.1 | Anti-automation (brute force) | Rate limit + progressive lockout |
| 2.4.1 | Passwords stored with an approved, salted, memory-hard KDF | scrypt N=2¹⁷ r=8 p=1, 16-byte salt |
| 2.4.2 | Unique salt ≥ 32 bits | 128-bit random salt per hash |
| 2.5.2 | No password hints / knowledge questions | None exist |

### V3 Session management
| ID | Requirement (summary) | How |
|---|---|---|
| 3.2.2 | Session tokens ≥ 64 bits of entropy | Refresh: 256 bits; JWT `jti`: UUIDv4 |
| 3.3.1 | Logout invalidates the session | Refresh family revoked |
| 3.3.3 | Option to terminate all sessions after password change | Automatic on password change + `/me/logout-all` |
| 3.5.2 | Stateless tokens signed and verified | HS256, algorithm allow-list |
| 3.5.3 | Protection against token tampering / `none` algorithm | Tested explicitly |

### V4 Access control
| ID | Requirement (summary) | How |
|---|---|---|
| 4.1.1 | Access control enforced server-side | Middleware + SQL scoping |
| 4.1.3 | Least privilege | Users see only their notes; admin limited to audit |
| 4.1.5 | Access control fails securely | Missing principal → 401 (`uid()` throws) |
| 4.2.1 | Protection against IDOR | Owner scoping + uniform 404 |

### V5 Validation and injection
| ID | Requirement (summary) | How |
|---|---|---|
| 5.1.1 | HTTP parameter pollution defences | `query parser: simple` + strict query schemas |
| 5.1.3 | Positive (allow-list) input validation | zod schemas everywhere |
| 5.3.4 | Parameterised queries | `prepare()` with `?`; ESLint + Semgrep rules |
| 5.5.2 | No unsafe deserialisation / prototype pollution | Strict schemas reject `__proto__` |

### V6 Cryptography
| ID | Requirement (summary) | How |
|---|---|---|
| 6.2.1 | Crypto fails securely, no oracle | Single generic `DecryptionError` |
| 6.2.2 | Proven algorithms only | AES-256-GCM, HMAC-SHA-256, scrypt |
| 6.2.5 | No insecure modes (ECB, unauthenticated CBC) | GCM only; Semgrep `bastion-weak-crypto` |
| 6.2.6 | Nonces unique | 96-bit random IV per encryption, fresh DEK per record |
| 6.3.1 | CSPRNG for random values | `crypto.randomBytes` / `randomUUID`; Semgrep bans `Math.random` |
| 6.4.1 | Key management, keys isolated from data | KEKs in secret store, never in DB |
| 6.4.2 | Key rotation without re-encrypting data | `rotate-keys` re-wraps DEKs |

### V7 Errors and logging
| ID | Requirement (summary) | How |
|---|---|---|
| 7.1.1 | No credentials or session tokens in logs | pino redaction paths |
| 7.1.3 | Security events logged | Audit trail of auth, authz denials, admin actions |
| 7.1.4 | Logs contain enough to investigate | Actor, action, target, IP, outcome, timestamp, request id |
| 7.3.3 | Logs protected from modification | Append-only triggers + HMAC chain |
| 7.4.1 | Generic error messages with a correlation id | Central error handler, `requestId` |

### V8 Data protection · V14 Configuration
| ID | Requirement (summary) | How |
|---|---|---|
| 8.1.1 | Sensitive data not cached server-side | `Cache-Control: no-store`, ETags disabled |
| 8.3.1 | Sensitive data never in URLs | Tokens only in headers / bodies |
| 14.2.1 | Components up to date, no known vulnerabilities | Dependabot, npm audit, OSV-Scanner, Trivy |
| 14.2.4 | Third-party components from trusted sources, verified | `npm audit signatures`, lockfile integrity, SHA-pinned actions |
| 14.3.2 | Debug modes disabled in production | `NODE_ENV=production`, no stack traces |
| 14.4.3 | Content-Security-Policy | `default-src 'none'; frame-ancestors 'none'` |
| 14.4.4 | `X-Content-Type-Options: nosniff` | helmet |
| 14.4.5 | HSTS | 2 years, includeSubDomains, preload |
| 14.4.6 | Referrer-Policy | `no-referrer` |
| 14.4.7 | Anti-framing | CSP `frame-ancestors` + `X-Frame-Options: DENY` |
| 14.5.2 | Origin header not used for access control | Bearer tokens only, no cookies → no CSRF surface |

## CIS / NSA Kubernetes hardening highlights

Pod Security Standard **restricted** enforced on the namespace · `runAsNonRoot`,
UID 65532 · `readOnlyRootFilesystem` · `allowPrivilegeEscalation: false` ·
`capabilities.drop: [ALL]` · `seccompProfile: RuntimeDefault` · service-account
token not mounted · secrets mounted as files (0400), not env vars · default-deny
NetworkPolicy, no egress · signed-image admission policy (Kyverno).
