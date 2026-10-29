# CLAUDE.md — Bastion (Azog1812/web-app)

Context file for Claude Code. Read it fully before changing anything.

## What this project is

Portfolio project of Florent Roch, aimed at **cybersecurity / DevSecOps recruiters**.
Bastion is a hardened, envelope-encrypted notes REST API (TypeScript, Express 5) plus a
complete DevSecOps supply chain. The value is not the features: it is that **every
security claim is backed by code + a test that tries to break it + documentation**.
Never add a feature without its abuse-case tests and doc update.

History: v1 (June 2026) was an Express hello-world with a broken Jenkins pipeline. v2
(29 Oct 2026) is a full rewrite — commits `478cdb7` → `7520070`. The v1 history is kept
on purpose (the README tells the "before/after" story).

Florent must be able to **defend every decision in an interview**. When working with him,
explain the *why* (threat, standard, trade-off), not only the *what*.

## Commands

```bash
npm ci --ignore-scripts      # never run install scripts
npm run lint                 # ESLint strictTypeChecked + security plugin + custom SQL rules
npm run typecheck            # tsc strict, noUncheckedIndexedAccess, exactOptionalPropertyTypes
npm test                     # vitest (134 tests)
npm run test:coverage        # thresholds: lines/statements/functions 90 %, branches 80 %
npm run check                # lint + typecheck + coverage
npm run build && node dist/cli.js gen-secrets > .env   # local secrets (gitignored)
set -a && . ./.env && set +a && NODE_ENV=development npm start
./scripts/smoke-test.sh http://127.0.0.1:3000          # end-to-end incl. IDOR check
semgrep scan --config .semgrep/ --metrics=off --error src
docker compose up --build    # same hardening as prod (read-only, cap_drop ALL)
```

Requires Node ≥ 22.13 (CI: 22 and 24; image: Node 24 distroless).

## Architecture

```
src/
  config.ts              zod schema, fail-closed; secrets via VAR or VAR_FILE (*_FILE preferred)
  db.ts                  node:sqlite (built-in, zero native deps), STRICT tables, migrations via
                         PRAGMA user_version, append-only triggers on audit_log
  audit.ts               HMAC-SHA256 chained audit log; verify() returns firstInvalidSeq
  crypto/envelope.ts     AES-256-GCM, per-note DEK wrapped by KEK from key ring; AAD binds
                         content→(noteId, ownerId) and DEK→(noteId, keyId); rewrap() for rotation
  crypto/password.ts     scrypt N=2^17 r=8 p=1, self-describing format, needsRehash, dummy hash
  crypto/tokens.ts       JWT HS256 (typ at+jwt, alg allow-list, iss/aud/exp/jti), opaque refresh
                         tokens stored as SHA-256
  security/              NIST 800-63B password policy + SecLists blocklist (generated file)
  services/auth-service  register/login/refresh/logout/logoutEverywhere/changePassword
  services/note-service  owner-scoped CRUD, optimistic concurrency (version), rotateKeys()
  services/learning-service  progress scoped by user_id, server-side prerequisites + quiz grading
  curriculum/catalog.ts  loads + validates content/ at boot (slug ids, no cycles, https links),
                         fail closed (ADR 0006)
  http/middleware.ts     requestId, noStore, requireJson, authenticate, requireRole, errorHandler
  http/schemas.ts        all zod schemas are .strict() (mass-assignment protection)
  http/routes.ts         /v1/auth/*, /v1/me*, /v1/notes*, /v1/curriculum, /v1/lessons/:id[/complete],
                         /v1/admin/audit*
  app.ts                 createApp(): helmet (CSP default-src 'none', HSTS, frameguard DENY),
                         rate limits, body limit 100 kB, trust proxy from config
  server.ts / cli.ts     entry point (timeouts, graceful shutdown) / operator CLI
content/                 curriculum as code: index.json (levels, path order), <path>/path.json
                         (modules, lessons, quizzes), <path>/<lesson>.md (French lesson bodies)
test/unit, test/security, test/helpers.ts (setup(), newUser(), auditActions())
deploy/k8s (kustomize), deploy/policies (Kyverno signed-image policy)
docs/  threat-model · security-controls (OWASP API Top 10 + ASVS 4.0.3) · security-pipeline ·
       adr/0001-0006 · runbook · openapi.yaml (used by DAST)
```

## Security invariants — never break these

1. **Every SQL query uses bound parameters.** No template literal / concatenation in
   `prepare()`/`exec()`. Enforced by ESLint `no-restricted-syntax` and Semgrep
   `bastion-sql-interpolation`. The only exception is `PRAGMA user_version` in `db.ts`.
2. **Every note query includes `owner_id` in the SQL itself.** Never fetch-then-check.
   Enforced by Semgrep `bastion-note-query-without-owner`. Foreign and missing notes must
   return the *same* 404. Exception: `rotateKeys()` (operator-only, annotated).
3. **All request schemas stay `.strict()`.** Unknown fields → 400.
4. **Login stays enumeration-proof:** same 401 message for unknown user / wrong password /
   locked account; unknown users still pay the scrypt cost (dummy hash).
5. **No `await` between reading and claiming a refresh token** (TOCTOU). Counters use
   atomic `UPDATE … RETURNING`.
6. **Role and token_version are read from the DB on every authenticated request**, never
   trusted from the JWT alone.
7. **Errors never leak internals**: throw `HttpError` helpers from `errors.ts`; everything
   else becomes a generic 500 with `requestId`. `DecryptionError` stays generic.
8. **Config fails closed**: never add an insecure default for a secret.
9. **No privilege escalation over HTTP**: admin promotion and key rotation are CLI-only.
10. **Audit every security-relevant event** (`AuditAction` union in `audit.ts`).
11. **Zero native dependencies / no install scripts.** Think hard before adding any
    dependency (supply-chain surface); prefer `node:` built-ins.
12. **Learning gating is server-side.** Quiz `answer` fields never leave the server (lessons
    are projected field by field); prerequisites are checked on read *and* on completion;
    progress queries include `user_id` (Semgrep `bastion-progress-query-without-user`).
    Content is never written over HTTP and never read from disk per request.

## Conventions

- TypeScript ESM (`.js` extensions in imports), strict types, no `any`, no non-null `!` in src.
- Comments explain the *threat or reason*, not the mechanics.
- Tests: add the abuse case, not only the happy path. Use `setup({ env, rateLimits })`;
  tests run with `SCRYPT_LOG_N=10` (production refuses < 17).
- Reviewed false positives: `// nosemgrep` trailing on the same line, justification on the
  line above; gitleaks exceptions go in `.gitleaks.toml` with a comment; Checkov exceptions
  as `checkov.io/skipN` annotations on the resource.
- Commits: Conventional Commits (`feat:`, `fix:`, `ci:`, `docs:`, `test:`, `build:`),
  English, body explains why.
- Docs are in English (README has a short French summary). Talk to Florent in French.
- When the attack surface changes, update `docs/threat-model.md` and
  `docs/security-controls.md` in the same change.

## CI/CD (GitHub Actions) — status on 29 Oct 2026: all 6 workflows green

| Workflow | Content |
|---|---|
| `ci.yml` | lint, typecheck, coverage tests on Node 22/24, build |
| `security.yml` | gitleaks (full history), Semgrep (registry packs + `.semgrep/`, findings emitted as annotations), npm audit + signatures, OSV-Scanner (reusable workflow), dependency review (PR), hadolint, Checkov |
| `codeql.yml` | security-extended + security-and-quality |
| `container.yml` | build → non-root / no-shell checks → restricted smoke test → Trivy (SARIF + gate) → SBOM; on main: push GHCR, cosign keyless sign, SBOM attestation, SLSA provenance, self-verify |
| `dast.yml` | ZAP API scan, authenticated, from `docs/openapi.yaml` minus session-destroying endpoints; `.zap/rules.tsv` marks injection/traversal rules as FAIL |
| `scorecard.yml` | OpenSSF Scorecard (published, badge) |

Rules: `permissions: {}` at top level, per-job least privilege; **every action pinned to a
full commit SHA** with a `# vX.Y.Z` comment (Dependabot updates them, 7-day cooldown);
`persist-credentials: false`; harden-runner in audit mode. Keep it that way.
Validate workflows locally with `actionlint` before pushing.

`Jenkinsfile` = on-prem equivalent (not executed anywhere); it documents the fixes over v1.

## Known limits / accepted risks (see docs/threat-model.md §5)

- Base images pinned by digest (tag kept alongside for readability and Dependabot).
- Trivy SARIF uses `ignore-unfixed`: unpatched base-image CVEs are an accepted risk (threat model §5).
- Dependabot ignores semver-major for `@types/node` (must match engines: Node 22) and
  `typescript` (typescript-eslint supports < 6.1 only).
- SQLite → single replica; in-memory rate limiting; HS256 (single issuer/verifier).
- Registration reveals whether an e-mail exists (409); lockout can be abused for targeted DoS.
- `node:sqlite` is flagged experimental by Node (warning silenced with `--disable-warning`).
- The Docker image was never built locally (registry access blocked during authoring);
  it is built and verified in `container.yml`.
- Commits of v2 carry a `Co-Authored-By: Claude` trailer.

## Pending manual actions (Florent, in the GitHub UI)

1. Make the GHCR package public (needed for the `cosign verify` instructions in README/SECURITY.md).
2. Branch protection on `main` with the 6 workflows as required checks (README claims gates block merges).
3. Consider renaming the repo `web-app` → `bastion` (then update URLs in README, SECURITY.md,
   package.json, Dockerfile labels, Kyverno subject, k8s image, CODEOWNERS, workflows' identity).
4. Pin the repo on the GitHub profile.

## Roadmap (suggested order, highest interview value first)

1. ~~Base images pinned by digest~~ (done 29 Oct 2026).
2. **MFA**: TOTP (RFC 6238) with encrypted secrets + recovery codes, then WebAuthn/passkeys.
   Requires threat-model + ASVS (V2.7/V2.8) updates and tests (replay of a TOTP code, brute force).
3. **External KMS for KEKs** (Vault Transit or a cloud KMS): only `wrapDek`/`unwrapDek` change;
   add a local Vault in docker-compose for demos.
4. **PostgreSQL + Redis** (rate-limit store, multiple replicas) behind the same service layer;
   use row-level security as a second IDOR barrier.
5. **Observability**: Prometheus metrics (auth failures, lockouts, reuse detections),
   alerting rules matching `docs/runbook.md`.
6. **Signed commits** (SSH/GPG) and a release workflow with semantic versioning.
7. **Fuzzing** of the HTTP layer (e.g. schemathesis against `docs/openapi.yaml`) in CI.
8. Interview prep: a mock technical interview on this repo (threat model, ADRs, auth-service).
