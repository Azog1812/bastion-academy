import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { createApp, type AppOptions } from '../src/app.js';
import { loadConfig, type Config } from '../src/config.js';
import { loadCurriculum, type Curriculum } from '../src/curriculum/catalog.js';
import { openDatabase, type Database } from '../src/db.js';
import { createLogger } from '../src/logger.js';

export const STRONG_PASSWORD = 'correct horse battery staple';

export function testEnv(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    DATABASE_PATH: ':memory:',
    JWT_SECRET: randomBytes(32).toString('base64'),
    AUDIT_HMAC_KEY: randomBytes(32).toString('base64'),
    FLAG_HMAC_KEY: randomBytes(32).toString('base64'),
    ENCRYPTION_KEYS: `k1:${randomBytes(32).toString('base64')}`,
    ACTIVE_KEY_ID: 'k1',
    SCRYPT_LOG_N: '10', // fast hashing in tests only; production refuses < 17
    ...overrides,
  };
}

export interface TestContext {
  config: Config;
  db: Database;
  app: ReturnType<typeof createApp>['app'];
  services: ReturnType<typeof createApp>['services'];
  metrics: ReturnType<typeof createApp>['metrics'];
  http: ReturnType<typeof request>;
}

/** The real content/ tree: tests also prove the shipped curriculum is valid. */
const realCurriculum = loadCurriculum();

export function setup(
  opts: {
    env?: Record<string, string>;
    rateLimits?: Partial<NonNullable<AppOptions['rateLimits']>>;
    curriculum?: Curriculum;
    web?: AppOptions['web'];
    labRunner?: AppOptions['labRunner'];
    environmentRunner?: AppOptions['environmentRunner'];
  } = {},
): TestContext {
  const config = loadConfig(testEnv(opts.env));
  const db = openDatabase(':memory:');
  const { app, services, metrics } = createApp({
    config,
    db,
    logger: createLogger('silent'),
    curriculum: opts.curriculum ?? realCurriculum,
    ...(opts.web ? { web: opts.web } : {}),
    ...(opts.labRunner ? { labRunner: opts.labRunner } : {}),
    ...(opts.environmentRunner ? { environmentRunner: opts.environmentRunner } : {}),
    rateLimits: { global: 10_000, auth: 10_000, refresh: 10_000, quiz: 10_000, ...opts.rateLimits },
  });
  return { config, db, app, services, metrics, http: request(app) };
}

export interface Session {
  id: string;
  email: string;
  accessToken: string;
  refreshToken: string;
  auth: { Authorization: string };
}

let counter = 0;

export async function newUser(t: TestContext, email = `user${++counter}@example.test`): Promise<Session> {
  const reg = await t.http.post('/v1/auth/register').send({ email, password: STRONG_PASSWORD }).expect(201);
  const login = await t.http.post('/v1/auth/login').send({ email, password: STRONG_PASSWORD }).expect(200);
  return {
    id: reg.body.id as string,
    email,
    accessToken: login.body.accessToken as string,
    refreshToken: login.body.refreshToken as string,
    auth: { Authorization: `Bearer ${login.body.accessToken as string}` },
  };
}

export function auditActions(t: TestContext): string[] {
  return t.services.audit
    .list(1000)
    .reverse()
    .map((r) => `${r.action}:${r.outcome}`);
}
