import { Router, type Request, type Response } from 'express';
import { rateLimit } from 'express-rate-limit';
import type { AuditLog } from '../audit.js';
import type { TokenSigner } from '../crypto/tokens.js';
import { isMfaChallenge, type AuthService, type LoginResult, type RequestContext } from '../services/auth-service.js';
import type { ChallengeService } from '../services/challenge-service.js';
import type { LabService } from '../services/lab-service.js';
import type { EnvironmentService } from '../services/environment-service.js';
import type { LearningService } from '../services/learning-service.js';
import type { MfaService } from '../services/mfa-service.js';
import type { NoteService } from '../services/note-service.js';
import type { PasskeyService } from '../services/passkey-service.js';
import { notFound, unauthorized } from '../errors.js';
import { authenticate, handler, parse, requireRole } from './middleware.js';
import { browserView, clearRefreshCookie, refreshTokenFrom, sameOriginOnly, setRefreshCookie } from './session.js';
import {
  auditQuerySchema,
  challengeIdSchema,
  changePasswordSchema,
  completeLessonSchema,
  createNoteSchema,
  credentialsSchema,
  lessonIdSchema,
  moduleChoiceSchema,
  moduleIdSchema,
  environmentIdSchema,
  emptyBodySchema,
  mfaCodeSchema,
  mfaDisableSchema,
  mfaLoginSchema,
  passkeyDeleteSchema,
  passkeyIdSchema,
  passkeyOptionsLoginSchema,
  passkeyRegisterSchema,
  passwordlessLoginSchema,
  noteIdSchema,
  paginationSchema,
  profileSchema,
  reauthSchema,
  refreshSchema,
  submitFlagSchema,
  detectSchema,
  updateNoteSchema,
} from './schemas.js';

export interface RouteDeps {
  auth: AuthService;
  notes: NoteService;
  learning: LearningService;
  challenges: ChallengeService;
  labs: LabService;
  environments: EnvironmentService;
  mfa: MfaService;
  passkeys: PasskeyService;
  audit: AuditLog;
  signer: TokenSigner;
  rateLimits: { auth: number; refresh: number; quiz: number; lab: number };
  refreshTtlSeconds: number;
}

const ctx = (req: Request): RequestContext => ({ ip: req.ip ?? null });

/** The authenticated user id. Throws (fails closed) if a route was wired without `requireAuth`. */
const uid = (req: Request): string => {
  if (!req.principal) throw unauthorized();
  return req.principal.id;
};

/** Browser variant of a login result: the refresh token goes to the HttpOnly cookie, never to the page. */
function sendBrowserLogin(res: Response, result: LoginResult, ttl: number): void {
  if (isMfaChallenge(result)) {
    res.json(result);
    return;
  }
  setRefreshCookie(res, result.refreshToken, ttl);
  res.json(browserView(result));
}

const limiter = (limit: number, name: string) =>
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    identifier: name,
    message: { error: 'rate_limited', message: 'Too many requests, slow down' },
  });

export function buildRouter(d: RouteDeps): Router {
  const r = Router();
  const authLimiter = limiter(d.rateLimits.auth, 'auth');
  const refreshLimiter = limiter(d.rateLimits.refresh, 'refresh');
  const requireAuth = authenticate(d.signer, d.auth);

  /* ---------- authentication ---------- */

  r.post(
    '/auth/register',
    authLimiter,
    handler(async (req, res) => {
      const { email, password } = parse(credentialsSchema, req.body);
      const user = await d.auth.register(email, password, ctx(req));
      res.status(201).json(user);
    }),
  );

  r.post(
    '/auth/login',
    authLimiter,
    handler(async (req, res) => {
      const { email, password } = parse(credentialsSchema, req.body);
      res.json(await d.auth.login(email, password, ctx(req)));
    }),
  );

  r.post(
    '/auth/mfa',
    authLimiter,
    handler(async (req, res) => {
      const body = parse(mfaLoginSchema, req.body);
      res.json(await d.auth.completeMfa(body.mfaToken, 'code' in body ? body.code : { passkey: body.passkey }, ctx(req)));
    }),
  );

  // Passkey challenge for a pending MFA step (ADR 0016). Same limiter: it is part of logging in.
  r.post(
    '/auth/mfa/passkey/options',
    authLimiter,
    handler((req, res) => {
      const { mfaToken } = parse(passkeyOptionsLoginSchema, req.body);
      res.json(d.auth.passkeyOptions(mfaToken));
    }),
  );

  // Passwordless login with a discoverable passkey (ADR 0017). No account is named, so
  // nothing here can tell whether an e-mail exists.
  r.post(
    '/auth/passkey/options',
    authLimiter,
    handler((req, res) => {
      parse(emptyBodySchema, req.body ?? {});
      res.json(d.auth.passwordlessOptions());
    }),
  );

  r.post(
    '/auth/passkey',
    authLimiter,
    handler(async (req, res) => {
      const { passkey } = parse(passwordlessLoginSchema, req.body);
      res.json(await d.auth.loginWithPasskey(passkey, ctx(req)));
    }),
  );

  r.post(
    '/auth/refresh',
    refreshLimiter,
    handler(async (req, res) => {
      const { refreshToken } = parse(refreshSchema, req.body);
      res.json(await d.auth.refresh(refreshToken, ctx(req)));
    }),
  );

  r.post(
    '/auth/logout',
    refreshLimiter,
    handler((req, res) => {
      const { refreshToken } = parse(refreshSchema, req.body);
      d.auth.logout(refreshToken, ctx(req));
      res.status(204).end();
    }),
  );

  /* ---------- browser sessions (refresh token in an HttpOnly cookie, ADR 0007) ---------- */

  r.post(
    '/session/login',
    sameOriginOnly,
    authLimiter,
    handler(async (req, res) => {
      const { email, password } = parse(credentialsSchema, req.body);
      sendBrowserLogin(res, await d.auth.login(email, password, ctx(req)), d.refreshTtlSeconds);
    }),
  );

  r.post(
    '/session/mfa',
    sameOriginOnly,
    authLimiter,
    handler(async (req, res) => {
      const body = parse(mfaLoginSchema, req.body);
      sendBrowserLogin(res, await d.auth.completeMfa(body.mfaToken, 'code' in body ? body.code : { passkey: body.passkey }, ctx(req)), d.refreshTtlSeconds);
    }),
  );

  r.post(
    '/session/passkey',
    sameOriginOnly,
    authLimiter,
    handler(async (req, res) => {
      const { passkey } = parse(passwordlessLoginSchema, req.body);
      sendBrowserLogin(res, await d.auth.loginWithPasskey(passkey, ctx(req)), d.refreshTtlSeconds);
    }),
  );

  r.post(
    '/session/refresh',
    sameOriginOnly,
    refreshLimiter,
    handler(async (req, res) => {
      try {
        const pair = await d.auth.refresh(refreshTokenFrom(req), ctx(req));
        setRefreshCookie(res, pair.refreshToken, d.refreshTtlSeconds);
        res.json(browserView(pair));
      } catch (err) {
        // A dead session must not leave a cookie the browser keeps replaying.
        clearRefreshCookie(res);
        throw err;
      }
    }),
  );

  r.post(
    '/session/logout',
    sameOriginOnly,
    refreshLimiter,
    handler((req, res) => {
      try {
        d.auth.logout(refreshTokenFrom(req), ctx(req));
      } catch {
        // No cookie: already logged out. Logout stays idempotent.
      }
      clearRefreshCookie(res);
      res.status(204).end();
    }),
  );

  /* ---------- current user ---------- */

  r.get(
    '/me',
    requireAuth,
    handler((req, res) => {
      res.json({ id: uid(req), role: req.principal?.role, ...d.auth.profile(uid(req)) });
    }),
  );

  r.put(
    '/me/profile',
    requireAuth,
    handler((req, res) => {
      const { displayName } = parse(profileSchema, req.body);
      res.json(d.auth.setDisplayName(uid(req), displayName, ctx(req)));
    }),
  );

  /* ---------- two-factor authentication (TOTP, RFC 6238) ---------- */

  r.post(
    '/me/mfa/setup',
    requireAuth,
    authLimiter,
    handler(async (req, res) => {
      const { password } = parse(reauthSchema, req.body);
      const { email } = await d.auth.confirmPassword(uid(req), password, ctx(req));
      res.json(d.mfa.setup(uid(req), email, ctx(req).ip));
    }),
  );

  r.post(
    '/me/mfa/enable',
    requireAuth,
    authLimiter,
    handler((req, res) => {
      const { code } = parse(mfaCodeSchema, req.body);
      res.json({ recoveryCodes: d.mfa.enable(uid(req), code, ctx(req).ip) });
    }),
  );

  r.post(
    '/me/mfa/disable',
    requireAuth,
    authLimiter,
    handler(async (req, res) => {
      const { password, code } = parse(mfaDisableSchema, req.body);
      await d.auth.confirmPassword(uid(req), password, ctx(req));
      // Both factors: a hijacked session alone, or a stolen password alone, cannot remove MFA.
      if (!d.mfa.verify(uid(req), code, ctx(req).ip)) {
        d.audit.record({ action: 'mfa.disable', outcome: 'failure', actorId: uid(req), ip: ctx(req).ip });
        throw unauthorized('Invalid verification code');
      }
      d.mfa.disable(uid(req), ctx(req).ip);
      res.status(204).end();
    }),
  );

  /* ---------- passkeys (WebAuthn, ADR 0016) ---------- */

  r.get(
    '/me/passkeys',
    requireAuth,
    handler((req, res) => {
      res.json({ items: d.passkeys.list(uid(req)) });
    }),
  );

  r.post(
    '/me/passkeys/options',
    requireAuth,
    authLimiter,
    handler(async (req, res) => {
      const { password } = parse(reauthSchema, req.body);
      const { email } = await d.auth.confirmPassword(uid(req), password, ctx(req));
      res.json(d.passkeys.registrationOptions(uid(req), email));
    }),
  );

  r.post(
    '/me/passkeys',
    requireAuth,
    authLimiter,
    handler((req, res) => {
      const { name, credential } = parse(passkeyRegisterSchema, req.body);
      const created = d.passkeys.register(uid(req), name, credential, ctx(req).ip);
      // First second factor of the account: recovery codes, shown once.
      res.status(201).json({ ...created, recoveryCodes: d.mfa.issueRecoveryCodesIfNone(uid(req)) });
    }),
  );

  r.delete(
    '/me/passkeys/:id',
    requireAuth,
    authLimiter,
    handler(async (req, res) => {
      const { id } = parse(passkeyIdSchema, req.params);
      const { password, code } = parse(passkeyDeleteSchema, req.body);
      await d.auth.confirmPassword(uid(req), password, ctx(req));
      if (!d.passkeys.isOwn(uid(req), id)) throw notFound('Passkey not found');
      // Removing the last second factor is disabling MFA: password AND a code, as for TOTP.
      const last = !d.mfa.isEnabled(uid(req)) && d.passkeys.count(uid(req)) === 1;
      if (last && (code === undefined || !d.mfa.verify(uid(req), code, ctx(req).ip))) {
        d.audit.record({ action: 'passkey.delete', outcome: 'failure', actorId: uid(req), target: id, ip: ctx(req).ip, details: { reason: 'last_factor' } });
        throw unauthorized('This is your last second factor: enter a recovery code to remove it');
      }
      d.passkeys.remove(uid(req), id, ctx(req).ip);
      d.mfa.dropIfNoFactor(uid(req));
      res.status(204).end();
    }),
  );

  r.post(
    '/me/password',
    requireAuth,
    authLimiter,
    handler(async (req, res) => {
      const { currentPassword, newPassword } = parse(changePasswordSchema, req.body);
      await d.auth.changePassword(uid(req), currentPassword, newPassword, ctx(req));
      res.status(204).end();
    }),
  );

  r.post(
    '/me/logout-all',
    requireAuth,
    handler((req, res) => {
      d.auth.logoutEverywhere(uid(req), ctx(req));
      res.status(204).end();
    }),
  );

  /* ---------- notes (owner-scoped) ---------- */

  r.get(
    '/notes',
    requireAuth,
    handler((req, res) => {
      const { limit, offset } = parse(paginationSchema, req.query);
      res.json({ ...d.notes.list(uid(req), limit, offset), limit, offset });
    }),
  );

  r.post(
    '/notes',
    requireAuth,
    handler((req, res) => {
      const note = d.notes.create(uid(req), parse(createNoteSchema, req.body), ctx(req).ip);
      res.status(201).location(`/v1/notes/${note.id}`).json(note);
    }),
  );

  r.get(
    '/notes/:id',
    requireAuth,
    handler((req, res) => {
      const { id } = parse(noteIdSchema, req.params);
      res.json(d.notes.get(uid(req), id, ctx(req).ip));
    }),
  );

  r.put(
    '/notes/:id',
    requireAuth,
    handler((req, res) => {
      const { id } = parse(noteIdSchema, req.params);
      const { version, ...content } = parse(updateNoteSchema, req.body);
      res.json(d.notes.update(uid(req), id, version, content, ctx(req).ip));
    }),
  );

  r.delete(
    '/notes/:id',
    requireAuth,
    handler((req, res) => {
      const { id } = parse(noteIdSchema, req.params);
      d.notes.delete(uid(req), id, ctx(req).ip);
      res.status(204).end();
    }),
  );

  /* ---------- learning (user-scoped) ---------- */

  // Keyed by user, not IP: guessing quiz answers is a per-account abuse, and
  // learners behind one NAT (a classroom) must not throttle each other.
  const quizLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: d.rateLimits.quiz,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    identifier: 'quiz',
    keyGenerator: (req) => uid(req),
    message: { error: 'rate_limited', message: 'Too many attempts, take a break and review the lesson' },
  });

  r.get(
    '/curriculum',
    requireAuth,
    handler((req, res) => {
      res.json(d.learning.overview(uid(req)));
    }),
  );

  r.put(
    '/me/modules/:id',
    requireAuth,
    handler((req, res) => {
      const { id } = parse(moduleIdSchema, req.params);
      const { added } = parse(moduleChoiceSchema, req.body);
      res.json(d.learning.chooseModule(uid(req), id, added, ctx(req).ip));
    }),
  );

  r.get(
    '/lessons/:id',
    requireAuth,
    handler((req, res) => {
      const { id } = parse(lessonIdSchema, req.params);
      res.json(d.learning.getLesson(uid(req), id, ctx(req).ip));
    }),
  );

  r.post(
    '/lessons/:id/complete',
    requireAuth,
    quizLimiter,
    handler((req, res) => {
      const { id } = parse(lessonIdSchema, req.params);
      const { answers } = parse(completeLessonSchema, req.body ?? {});
      res.json(d.learning.complete(uid(req), id, answers, ctx(req).ip));
    }),
  );

  /* ---------- challenges and scoreboard ---------- */

  // Same reasoning as quizzes: flag guessing is a per-account abuse.
  const flagLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: d.rateLimits.quiz,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    identifier: 'flag',
    keyGenerator: (req) => uid(req),
    message: { error: 'rate_limited', message: 'Too many attempts, take a break and look at the artifact again' },
  });

  r.get(
    '/challenges',
    requireAuth,
    handler((req, res) => {
      res.json(d.challenges.list(uid(req)));
    }),
  );

  r.get(
    '/challenges/:id',
    requireAuth,
    handler((req, res) => {
      const { id } = parse(challengeIdSchema, req.params);
      const challenge = d.challenges.get(uid(req), id, ctx(req).ip);
      res.json({ ...challenge, lab: challenge.lab === null ? null : { id: challenge.lab, ...d.labs.view(uid(req), id) } });
    }),
  );

  // Each start creates a network and a container: a per-account budget, like flags.
  const labLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: d.rateLimits.lab,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    identifier: 'lab',
    keyGenerator: (req) => uid(req),
    message: { error: 'rate_limited', message: 'Too many lab starts, keep working on the one you have' },
  });

  r.post(
    '/challenges/:id/lab',
    requireAuth,
    labLimiter,
    handler(async (req, res) => {
      const { id } = parse(challengeIdSchema, req.params);
      res.status(201).json(await d.labs.start(uid(req), id, ctx(req).ip));
    }),
  );

  r.delete(
    '/challenges/:id/lab',
    requireAuth,
    handler(async (req, res) => {
      const { id } = parse(challengeIdSchema, req.params);
      await d.labs.stop(uid(req), id, ctx(req).ip);
      res.status(204).end();
    }),
  );

  /* ---------- shared environments (ADR 0013) ---------- */

  r.get(
    '/environments',
    requireAuth,
    handler(async (req, res) => {
      res.json({ items: await d.environments.list(uid(req)) });
    }),
  );

  // Same per-account limiter as labs: starting a SIEM is the most expensive thing a learner can ask for.
  r.post(
    '/environments/:id/start',
    requireAuth,
    labLimiter,
    handler(async (req, res) => {
      const { id } = parse(environmentIdSchema, req.params);
      res.status(202).json(await d.environments.start(uid(req), id, ctx(req).ip));
    }),
  );

  r.post(
    '/environments/:id/stop',
    requireAuth,
    labLimiter,
    handler(async (req, res) => {
      const { id } = parse(environmentIdSchema, req.params);
      await d.environments.stop(uid(req), id, ctx(req).ip);
      res.status(204).end();
    }),
  );

  r.post(
    '/challenges/:id/submit',
    requireAuth,
    flagLimiter,
    handler((req, res) => {
      const { id } = parse(challengeIdSchema, req.params);
      const { flag } = parse(submitFlagSchema, req.body);
      res.json(d.challenges.submit(uid(req), id, flag, ctx(req).ip));
    }),
  );

  // Writing a rule is iterative: a larger budget than flags, still per account.
  const detectLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: d.rateLimits.quiz * 2,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    identifier: 'detect',
    keyGenerator: (req) => uid(req),
    message: { error: 'rate_limited', message: 'Too many evaluations, take a moment to read the misses and false positives' },
  });

  r.post(
    '/challenges/:id/detect',
    requireAuth,
    detectLimiter,
    handler((req, res) => {
      const { id } = parse(challengeIdSchema, req.params);
      const { rule } = parse(detectSchema, req.body);
      res.json(d.challenges.detect(uid(req), id, rule, ctx(req).ip));
    }),
  );

  r.get(
    '/scoreboard',
    requireAuth,
    handler((req, res) => {
      res.json(d.challenges.scoreboard(uid(req)));
    }),
  );

  /* ---------- administration ---------- */

  const adminOnly = [requireAuth, requireRole('admin', d.audit)];

  r.get(
    '/admin/audit',
    ...adminOnly,
    handler((req, res) => {
      const { limit, before } = parse(auditQuerySchema, req.query);
      d.audit.record({ action: 'admin.audit_read', outcome: 'success', actorId: uid(req), ip: ctx(req).ip });
      const items = d.audit.list(limit, before).map((row) => ({ ...row, details: JSON.parse(row.details) as unknown }));
      res.json({ items });
    }),
  );

  r.get(
    '/admin/audit/verify',
    ...adminOnly,
    handler((req, res) => {
      const result = d.audit.verify();
      d.audit.record({
        action: 'admin.audit_verify',
        outcome: result.valid ? 'success' : 'failure',
        actorId: uid(req),
        ip: ctx(req).ip,
        details: { checked: result.checked },
      });
      res.json(result);
    }),
  );

  return r;
}
