import express, { type Express } from 'express';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import { pinoHttp } from 'pino-http';
import type { Logger } from 'pino';
import { AuditLog } from './audit.js';
import type { Config } from './config.js';
import { createTokenSigner } from './crypto/tokens.js';
import type { Database } from './db.js';
import { errorHandler, noStore, notFoundHandler, requestId, requireJson } from './http/middleware.js';
import { buildRouter } from './http/routes.js';
import { webRouter } from './http/web.js';
import type { Curriculum } from './curriculum/catalog.js';
import { AuthService } from './services/auth-service.js';
import { ChallengeService } from './services/challenge-service.js';
import { LearningService } from './services/learning-service.js';
import { MfaService } from './services/mfa-service.js';
import { httpLabRunner, LabService, type LabRunnerClient } from './services/lab-service.js';
import { NoteService } from './services/note-service.js';

export interface AppOptions {
  config: Config;
  db: Database;
  logger: Logger;
  curriculum: Curriculum;
  /** Overridable so tests can serve a fixture front-end. */
  web?: { publicDir?: string; jsDir?: string };
  /** Overridable so tests can exercise the limiter without waiting 15 minutes. */
  rateLimits?: { global: number; auth: number; refresh: number; quiz: number; lab?: number };
  /** Overridable so tests run without Docker. Default: the configured runner, or labs off. */
  labRunner?: LabRunnerClient;
}

export interface App {
  app: Express;
  services: {
    auth: AuthService;
    notes: NoteService;
    learning: LearningService;
    challenges: ChallengeService;
    labs: LabService;
    mfa: MfaService;
    audit: AuditLog;
  };
}

export function createApp({ config, db, logger, curriculum, rateLimits, web, labRunner }: AppOptions): App {
  const limits = rateLimits ?? {
    global: config.RATE_LIMIT_GLOBAL,
    auth: config.RATE_LIMIT_AUTH,
    refresh: config.RATE_LIMIT_REFRESH,
    quiz: config.RATE_LIMIT_QUIZ,
  };

  const audit = new AuditLog(db, config.AUDIT_HMAC_KEY);
  const signer = createTokenSigner({
    secret: config.JWT_SECRET,
    issuer: config.JWT_ISSUER,
    audience: config.JWT_AUDIENCE,
    ttlSeconds: config.ACCESS_TOKEN_TTL_SECONDS,
  });
  const ring = { keys: config.ENCRYPTION_KEYS, activeKeyId: config.ACTIVE_KEY_ID };
  const mfa = new MfaService(db, ring, audit, config.MFA_ISSUER);
  const auth = new AuthService(db, config, signer, audit, mfa);
  const notes = new NoteService(db, ring, audit);
  const learning = new LearningService(db, curriculum, audit);
  const challenges = new ChallengeService(db, curriculum, learning, audit, config.FLAG_HMAC_KEY);
  const runner =
    labRunner ?? (config.LAB_RUNNER_URL && config.LAB_RUNNER_TOKEN ? httpLabRunner(config.LAB_RUNNER_URL, config.LAB_RUNNER_TOKEN) : undefined);
  const labs = new LabService(db, curriculum, challenges, learning, audit, runner, config.LAB_TTL_SECONDS, config.LAB_GATEWAY_PORT);

  const app = express();

  // Only trust X-Forwarded-For from a known number of reverse-proxy hops;
  // trusting it blindly lets any client spoof its IP and dodge rate limits.
  app.set('trust proxy', config.TRUST_PROXY);
  app.disable('x-powered-by');
  app.set('etag', false);
  app.set('query parser', 'simple'); // no nested objects in query strings (parameter pollution)

  app.use(requestId);
  app.use(
    pinoHttp({
      logger,
      genReqId: (req) => (req as unknown as { id: string }).id,
      customLogLevel: (_req, res, err) => (err || res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info'),
      autoLogging: { ignore: (req) => req.url === '/healthz' || req.url === '/readyz' },
    }),
  );

  // Pure JSON API: the strictest possible CSP — nothing may load, nothing may frame it.
  app.use(
    helmet({
      contentSecurityPolicy: { useDefaults: false, directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      strictTransportSecurity: { maxAge: 63_072_000, includeSubDomains: true, preload: true },
      referrerPolicy: { policy: 'no-referrer' },
      frameguard: { action: 'deny' },
    }),
  );
  app.use((_req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    next();
  });

  /* Probes: no auth, no rate limit, no body. */
  app.get('/healthz', (_req, res) => {
    res.json({ status: 'ok' });
  });
  app.get('/readyz', (_req, res) => {
    try {
      db.prepare('SELECT 1').get();
      res.json({ status: 'ready' });
    } catch {
      res.status(503).json({ status: 'unavailable' });
    }
  });

  /* Web front-end: static, same origin, its own CSP. Before the limiter so loading the UI never throttles the API. */
  app.use(webRouter(web));

  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000,
      limit: limits.global,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      message: { error: 'rate_limited', message: 'Too many requests, slow down' },
    }),
  );
  app.use(requireJson);
  app.use(express.json({ limit: '100kb', strict: true }));
  app.use('/v1', noStore, buildRouter({
      auth,
      notes,
      learning,
      challenges,
      labs,
      mfa,
      audit,
      signer,
      rateLimits: { auth: limits.auth, refresh: limits.refresh, quiz: limits.quiz, lab: rateLimits?.lab ?? config.RATE_LIMIT_LAB },
      refreshTtlSeconds: config.REFRESH_TOKEN_TTL_SECONDS,
    }));

  app.use(notFoundHandler);
  app.use(errorHandler(logger));

  return { app, services: { auth, notes, learning, challenges, labs, mfa, audit } };
}
