import { randomBytes } from 'node:crypto';
import { setImmediate as nextTurn } from 'node:timers/promises';
import request from 'supertest';
import { createApp, type AppOptions } from '../src/app.js';
import { loadConfig, type Config } from '../src/config.js';
import { loadCurriculum, type Curriculum } from '../src/curriculum/catalog.js';
import { openDatabase, type Database, type SqlValue } from '../src/db.js';
import { openPostgres } from '../src/postgres.js';
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

/**
 * The database as a remote server makes it look: every query yields to the event loop
 * first, so concurrent requests interleave between their queries. In-process SQLite
 * answers within the same turn, which hides check-then-act races that PostgreSQL
 * would expose; race tests run against this.
 */
export function withLatency(db: Database): Database {
  return {
    dialect: db.dialect,
    one: async (sql: string, ...p: SqlValue[]) => {
      await nextTurn();
      return db.one(sql, ...p);
    },
    many: async (sql: string, ...p: SqlValue[]) => {
      await nextTurn();
      return db.many(sql, ...p);
    },
    run: async (sql: string, ...p: SqlValue[]) => {
      await nextTurn();
      return db.run(sql, ...p);
    },
    transaction: async (fn, options) => {
      await nextTurn();
      return db.transaction(async (tx) => fn(withLatency(tx)), options);
    },
    close: () => db.close(),
  };
}

/**
 * A fresh, empty database. SQLite in memory by default; with TEST_DATABASE_URL set (CI's
 * PostgreSQL job), a new schema of that server, so the whole suite proves both engines.
 */
export function testDb(): Database {
  const url = process.env.TEST_DATABASE_URL;
  if (url === undefined || url === '') return openDatabase(':memory:');
  return openPostgres(url, { schema: `t_${randomBytes(8).toString('hex')}`, poolSize: 3 });
}

/** What an attacker with database access does first: remove the append-only guard. */
export async function dropAuditTrigger(db: Database, which: 'update' | 'delete'): Promise<void> {
  if (db.dialect === 'postgres') {
    await db.run(which === 'update' ? 'DROP TRIGGER audit_no_update ON audit_log' : 'DROP TRIGGER audit_no_delete ON audit_log');
  } else {
    await db.run(which === 'update' ? 'DROP TRIGGER audit_no_update' : 'DROP TRIGGER audit_no_delete');
  }
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
    kms?: AppOptions['kms'];
    /** Make the database behave like a remote one (see withLatency). */
    latency?: boolean;
  } = {},
): TestContext {
  const config = loadConfig(testEnv(opts.env));
  const fresh = testDb();
  const db = opts.latency ? withLatency(fresh) : fresh;
  const { app, services, metrics } = createApp({
    config,
    db,
    logger: createLogger('silent'),
    curriculum: opts.curriculum ?? realCurriculum,
    ...(opts.web ? { web: opts.web } : {}),
    ...(opts.labRunner ? { labRunner: opts.labRunner } : {}),
    ...(opts.environmentRunner ? { environmentRunner: opts.environmentRunner } : {}),
    ...(opts.kms ? { kms: opts.kms } : {}),
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

export async function auditActions(t: TestContext): Promise<string[]> {
  return (await t.services.audit
    .list(1000))
    .reverse()
    .map((r) => `${r.action}:${r.outcome}`);
}
