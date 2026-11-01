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
| API6 Unrestricted Access to Sensitive Business Flows | ✅ | Registration and login rate-limited per IP; quiz and flag submissions rate-limited per account; lessons and challenges gated by server-side prerequisites; per-learner flags make sharing useless and visible | [`routes.ts`](../src/http/routes.ts) |
| API7 Server Side Request Forgery | ✅ n/a | The API makes no outbound request; NetworkPolicy denies all egress | [`networkpolicy.yaml`](../deploy/k8s/networkpolicy.yaml) |
| API8 Security Misconfiguration | ✅ | Fail-closed config, strict headers, no `x-powered-by`, generic errors, hardened container and pod. Web pages: CSP without inline code plus Trusted Types, no CORS at all ([`web.ts`](../src/http/web.ts)) | [`config.ts`](../src/config.ts), [`deployment.yaml`](../deploy/k8s/deployment.yaml) |
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
| 2.5.6 | Re-authentication before sensitive changes | Password required to set up or remove MFA; removal also needs a valid code |
| 2.7.x | Out-of-band verifiers | Not used (no SMS/e-mail codes): TOTP and passkeys, see ADR 0008 and 0016 |
| 2.9.1 / 2.9.3 | Cryptographic verifiers: keys protected, approved algorithms | Passkeys: public keys only on the server (SPKI DER); Ed25519, ES256 or RS256 ≥ 2048 bits, chosen by the server |
| 2.9.2 | Challenge nonce at least 64 bits | 256-bit random challenge, single use, 5 minutes, bound to its MFA step |
| NIST 800-63B §5.2.5 | Phishing (verifier impersonation) resistance | WebAuthn origin and RP ID checks: a signature obtained by a look-alike site is refused (ADR 0016) |
| 2.8.1 | Time-based OTPs have a defined lifetime | 30-s step, ±1 step drift accepted |
| 2.8.3 | Approved algorithms for OTP | HOTP/TOTP RFC 4226/6238, HMAC-SHA1 (keyed; SHA-1 collisions do not apply), checked against RFC test vectors |
| 2.8.4 | A time-based OTP can be used only once in its validity period | Last accepted step stored, compare-and-set update |
| 2.8.5 | Reuse of an OTP is logged and refused | Refused; failures audited as `auth.mfa:failure` and fed to the lockout |
| 2.8.7 | OTP seeds protected | Sealed with AES-256-GCM under the KEK ring (or wrapped by Vault Transit), bound to the user; re-sealed on key rotation |
| 2.5.x / 2.6.x | Recovery codes | 10 × 80-bit, shown once, stored hashed, single use, each use audited |

### V3 Session management
| ID | Requirement (summary) | How |
|---|---|---|
| 3.2.2 | Session tokens ≥ 64 bits of entropy | Refresh: 256 bits; JWT `jti`: UUIDv4 |
| 3.3.1 | Logout invalidates the session | Refresh family revoked; browser cookie cleared |
| 3.4.1 | Cookie-based tokens have the Secure attribute | `__Host-bastion_rt; Secure` |
| 3.4.2 | Cookie-based tokens have the HttpOnly attribute | `HttpOnly` |
| 3.4.3 | Cookie-based tokens use SameSite | `SameSite=Strict` |
| 3.4.4 | Cookie-based tokens use the `__Host-` prefix | `__Host-bastion_rt` |
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
| 4.1.2 | Attributes used by access control cannot be manipulated by the user | Optional-module choices are per learner and scoped in SQL; every lesson, quiz, challenge and lab re-checks them server-side (ADR 0012) |

### V5 Validation and injection
| ID | Requirement (summary) | How |
|---|---|---|
| 5.1.1 | HTTP parameter pollution defences | `query parser: simple` + strict query schemas |
| 5.1.3 | Positive (allow-list) input validation | zod schemas everywhere |
| 5.3.4 | Parameterised queries | `prepare()` with `?`; ESLint + Semgrep rules |
| 5.5.2 | No unsafe deserialisation / prototype pollution | Strict schemas reject `__proto__` |
| 5.3.3 | Context-aware output escaping against XSS | The UI never builds HTML from strings: DOM nodes and text only (ESLint ban on HTML sinks), Markdown parsed to a tree, Trusted Types enforced by CSP |

### V6 Cryptography
| ID | Requirement (summary) | How |
|---|---|---|
| 6.2.1 | Crypto fails securely, no oracle | Single generic `DecryptionError` |
| 6.2.2 | Proven algorithms only | AES-256-GCM, HMAC-SHA-256, scrypt |
| 6.2.5 | No insecure modes (ECB, unauthenticated CBC) | GCM only; Semgrep `bastion-weak-crypto` |
| 6.2.6 | Nonces unique | 96-bit random IV per encryption, fresh DEK per record |
| 6.3.1 | CSPRNG for random values | `crypto.randomBytes` / `randomUUID`; Semgrep bans `Math.random` |
| 6.4.1 | Key management, keys isolated from data | KEKs in secret store, never in DB; or in Vault Transit, never in the platform (ADR 0019) |
| 6.4.2 | Key rotation without re-encrypting data | `rotate-keys` re-wraps DEKs and re-seals TOTP seeds; with Vault, a new key version and `rewrap` inside Vault (no DEK leaves it) |
| 6.4.x / NIST SP 800-57 | KEK protected by a key management system, least privilege, auditable use | Vault policy: encrypt/decrypt/rewrap on one key only, no export/backup/config/delete (checked on the real Vault); AppRole with 1-hour tokens; Vault audit device logs every use; boot refuses an exportable or deletable key |
| 6.2.1 | A KMS outage does not look like tampering | `KmsUnavailable` → 503 + `Retry-After`; `DecryptionError` alone feeds the integrity alert |
| 6.4.x | Key separation | One key per purpose: JWT, audit chain, flags, KEK ring; HMAC inputs domain-separated (`bastion:<purpose>:v1:`) |

### V7 Errors and logging
| ID | Requirement (summary) | How |
|---|---|---|
| 7.1.1 | No credentials or session tokens in logs | pino redaction paths |
| 7.1.3 | Security events logged | Audit trail of auth, authz denials, admin actions |
| 7.1.4 | Logs contain enough to investigate | Actor, action, target, IP, outcome, timestamp, request id |
| 7.3.3 | Logs protected from modification | Append-only triggers + HMAC chain |
| 7.3.1 | Log entries encoded against injection | SIEM export: one `JSON.stringify` per line, control characters escaped (ADR 0015, `audit-export.test.ts`) |
| 7.1.3 / 7.2.x | Security events sent to a monitoring system and alerted on | Audit log copied to Wazuh, rules for token theft, broken chain, denials, brute force and stuffing, checked in `wazuh-logtest` |
| 7.4.1 | Generic error messages with a correlation id | Central error handler, `requestId` |
| (beyond ASVS) | Security events acted upon, not only stored | Audit events exported as Prometheus counters; tested alerts for token replay, credential stuffing, lockouts, MFA guessing, authorization probing, ciphertext tampering (ADR 0011) |

### V8 Data protection · V14 Configuration
| ID | Requirement (summary) | How |
|---|---|---|
| 8.1.1 | Sensitive data not cached server-side | `Cache-Control: no-store`, ETags disabled |
| 8.3.1 | Sensitive data never in URLs | Tokens only in headers / bodies |
| 14.2.1 | Components up to date, no known vulnerabilities | Dependabot, npm audit, OSV-Scanner, Trivy |
| 14.2.4 | Third-party components from trusted sources, verified | `npm audit signatures`, lockfile integrity, SHA-pinned actions |
| 14.3.2 | Debug modes disabled in production | `NODE_ENV=production`, no stack traces |
| 14.4.3 | Content-Security-Policy | API: `default-src 'none'; frame-ancestors 'none'`. Pages: `script-src 'self'` (no inline, no eval) + `require-trusted-types-for 'script'` with no allowed policy |
| 14.4.4 | `X-Content-Type-Options: nosniff` | helmet |
| 14.4.5 | HSTS | 2 years, includeSubDomains, preload |
| 14.4.6 | Referrer-Policy | `no-referrer` |
| 14.4.7 | Anti-framing | CSP `frame-ancestors` + `X-Frame-Options: DENY` |
| 14.5.2 | Origin header not used for access control | Access control relies on bearer tokens. Only the three browser-session routes read a cookie; there the `Origin` check is an extra CSRF barrier on top of `SameSite=Strict` and JSON-only bodies, never the sole control |

## Observability (v6, ADR 0011) — metrics without a new attack surface

| Control | Implementation | Evidence |
|---|---|---|
| Monitoring endpoint not exposed (ASVS 14.3.x, CIS: separate admin interfaces) | Own listener on `METRICS_PORT`, not the API's; not published, not in the Service; NetworkPolicy to Prometheus only | `observability.test.ts`, `deploy/k8s/networkpolicy.yaml` |
| Authenticated scrape (ASVS 4.1.x) | Bearer `METRICS_TOKEN`, SHA-256 + `timingSafeEqual`; Prometheus reads it from a file; fail-closed config | `observability.test.ts`, `config-and-audit.test.ts` |
| No personal data in telemetry (GDPR data minimisation, ASVS 8.3.x) | Labels from closed sets: route patterns, audit actions, status codes; no user id, e-mail or IP | `observability.test.ts` › route pattern, personal data |
| Resource exhaustion (OWASP API4:2023) | Per-metric series cap, drops counted and alerted | `metrics.test.ts` › cardinality |
| Alerts that work | `promtool test rules` in CI: each alert fires on its attack and not on normal traffic; counters exported at 0 so the first event alerts | `deploy/prometheus/alerts.test.yml`, `observability.test.ts` › regression |

## Detection challenges (v6, ADR 0010) — evaluating learner input safely

| Control | Implementation | Evidence |
|---|---|---|
| ReDoS prevention (OWASP: Regular expression Denial of Service) | No regular expressions in the rule language; linear string tests only | `src/detection/engine.ts`, `detection.test.ts` |
| Input validation with an allow-list (ASVS 5.1.3, 5.1.4) | Rule keys must be fields of the dataset plus a known modifier; strict schema, bounded sizes | same |
| Prototype pollution (ASVS 5.5.x) | Field allow-list, `Object.hasOwn` reads, no merge of learner objects | same |
| Anti-automation (ASVS 11.1.4) | Per-account evaluation rate limit | `detection.test.ts` › rate limit |
| XML parser restricted against XXE (ASVS 5.5.2, OWASP XXE Prevention Cheat Sheet) | Wazuh rules are read by a closed reader: no DTD, no external or declared entity, no CDATA or processing instruction, size and depth caps (ADR 0014) | `src/detection/wazuh.ts`, `wazuh.test.ts` |
| ReDoS in a vendor rule language | Wazuh's OS_Regex/PCRE2 refused; OS_Match evaluated with linear string tests | same |

## Labs (v5, ADR 0009) — container isolation

| Control | Implementation | Evidence |
|---|---|---|
| Least privilege for the Docker API (CIS Docker 5.31: do not mount the socket into containers) | Only the lab runner mounts it; platform and gateway never do. The runner accepts closed lab ids only, behind an internal network and a token | `docker-compose.yml`, `lab-runner.test.ts` |
| Non-root, read-only, no capabilities, no-new-privileges (CIS Docker 5.3, 5.12, 5.25, 4.1) | `src/labs/runner/spec.ts`, asserted field by field | `lab-runner.test.ts` › container spec |
| Resource limits (CIS Docker 5.10, 5.11, 5.28) | 128 MiB without swap, 0.5 CPU, 64 PIDs, 1024 open files | same |
| Network segmentation, no egress (NIST SP 800-190 §4.4) | One `internal` bridge per instance, gateway as the only peer, nothing published | same; checked live |
| Ephemeral workloads | TTL enforced by the platform and independently by the runner (container labels) | `labs.test.ts` › reaper, `lab-runner.test.ts` › reaper |
| Origin isolation for untrusted web content | Each lab served from `l<id>.lab.localhost`, never the platform origin | ADR 0009 |
| Docker API scope for shared environments (CIS Docker 5.31) | The runner inspects, starts and stops only the container names of `src/labs/environments.ts`; no create, mount or image from a request | `environments.test.ts`, ADR 0013 |
| No default credentials (CIS Controls 4.7, ASVS 2.5.4) | Wazuh setup drops the demo accounts and hashes passwords generated by `gen-secrets`; TLS from a private CA made offline | `deploy/wazuh/users.sh`, `deploy/wazuh/certs.sh` |

## CIS / NSA Kubernetes hardening highlights

Pod Security Standard **restricted** enforced on the namespace · `runAsNonRoot`,
UID 65532 · `readOnlyRootFilesystem` · `allowPrivilegeEscalation: false` ·
`capabilities.drop: [ALL]` · `seccompProfile: RuntimeDefault` · service-account
token not mounted · secrets mounted as files (0400), not env vars · default-deny
NetworkPolicy, no egress · signed-image admission policy (Kyverno).
