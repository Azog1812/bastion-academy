import { AsyncLocalStorage } from 'node:async_hooks';
import { randomInt } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import pg from 'pg';
import type { Db, SqlValue, TransactionOptions } from './db.js';

/**
 * PostgreSQL behind the same `Db` interface as SQLite (ADR 0021), for several replicas
 * sharing one database. Client: `pg`, pure JavaScript (pg-native, which compiles libpq,
 * is never installed: invariant 11).
 *
 * Services keep writing SQLite-compatible SQL with `?` placeholders; this adapter turns
 * them into `$1, $2…` and gives rows the shape SQLite gives them (numbers, Uint8Array).
 */

const SCHEMA: readonly string[] = [
  // The SQLite schema of db.ts (v1 to v7) in one step: PostgreSQL starts from scratch.
  // Differences, all deliberate:
  // - timestamps are milliseconds since 1970, which overflow INTEGER (int4): BIGINT;
  // - SQLite's NOCASE compares ASCII only; the ICU collation below ignores case in all of
  //   Unicode, which is stricter for unique pseudonyms (no "Ädmin" next to "ädmin");
  // - the append-only audit triggers also refuse TRUNCATE, which SQLite does not have.
  `
  CREATE COLLATION nocase (provider = icu, locale = 'und-u-ks-level2', deterministic = false);

  CREATE TABLE users (
    id             TEXT PRIMARY KEY,
    email          TEXT NOT NULL UNIQUE COLLATE nocase,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    failed_logins  INTEGER NOT NULL DEFAULT 0,
    locked_until   BIGINT NOT NULL DEFAULT 0,
    token_version  INTEGER NOT NULL DEFAULT 0,
    created_at     BIGINT NOT NULL,
    display_name   TEXT COLLATE nocase
  );
  CREATE UNIQUE INDEX users_display_name ON users(display_name) WHERE display_name IS NOT NULL;

  CREATE TABLE notes (
    id           TEXT PRIMARY KEY,
    owner_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id       TEXT NOT NULL,
    wrapped_dek  BYTEA NOT NULL,
    iv           BYTEA NOT NULL,
    tag          BYTEA NOT NULL,
    ciphertext   BYTEA NOT NULL,
    version      INTEGER NOT NULL DEFAULT 1,
    created_at   BIGINT NOT NULL,
    updated_at   BIGINT NOT NULL
  );
  CREATE INDEX notes_owner ON notes(owner_id, updated_at DESC);

  CREATE TABLE refresh_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id    TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    expires_at   BIGINT NOT NULL,
    revoked_at   BIGINT,
    replaced_by  TEXT,
    created_at   BIGINT NOT NULL
  );
  CREATE INDEX refresh_family ON refresh_tokens(family_id);
  CREATE INDEX refresh_user ON refresh_tokens(user_id);

  CREATE TABLE audit_log (
    seq        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts         BIGINT NOT NULL,
    actor_id   TEXT,
    action     TEXT NOT NULL,
    target     TEXT,
    ip         TEXT,
    outcome    TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    details    TEXT NOT NULL DEFAULT '{}',
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL UNIQUE
  );

  -- Append-only at the database level, not just by convention.
  CREATE FUNCTION audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'audit_log is append-only'; END
  $$;
  CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_append_only();
  CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_append_only();
  CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_log FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();

  CREATE TABLE lesson_progress (
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lesson_id     TEXT NOT NULL,
    completed_at  BIGINT NOT NULL,
    PRIMARY KEY (user_id, lesson_id)
  );

  CREATE TABLE challenge_solves (
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_id  TEXT NOT NULL,
    points        INTEGER NOT NULL CHECK (points > 0),
    solved_at     BIGINT NOT NULL,
    PRIMARY KEY (user_id, challenge_id)
  );
  CREATE INDEX challenge_solves_challenge ON challenge_solves(challenge_id);

  CREATE TABLE user_mfa (
    user_id     TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    key_id      TEXT NOT NULL,
    secret      BYTEA NOT NULL,
    enabled_at  BIGINT,
    last_step   BIGINT NOT NULL DEFAULT 0,
    created_at  BIGINT NOT NULL
  );

  CREATE TABLE mfa_recovery_codes (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    BIGINT,
    PRIMARY KEY (user_id, code_hash)
  );

  CREATE TABLE mfa_challenges (
    token_hash  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  BIGINT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE lab_instances (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    challenge_id  TEXT NOT NULL,
    created_at    BIGINT NOT NULL,
    expires_at    BIGINT NOT NULL
  );
  CREATE INDEX lab_instances_expiry ON lab_instances(expires_at);

  CREATE TABLE module_choices (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    module_id  TEXT NOT NULL,
    added_at   BIGINT NOT NULL,
    PRIMARY KEY (user_id, module_id)
  );

  CREATE TABLE passkeys (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id  BYTEA NOT NULL UNIQUE,
    public_key     BYTEA NOT NULL,
    alg            INTEGER NOT NULL,
    sign_count     BIGINT NOT NULL,
    name           TEXT NOT NULL,
    created_at     BIGINT NOT NULL,
    last_used_at   BIGINT
  );
  CREATE INDEX passkeys_user ON passkeys(user_id);

  CREATE TABLE webauthn_challenges (
    challenge_hash  TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose         TEXT NOT NULL CHECK (purpose IN ('register', 'login')),
    mfa_token_hash  TEXT,
    expires_at      BIGINT NOT NULL
  );

  CREATE TABLE webauthn_login_challenges (
    challenge_hash  TEXT PRIMARY KEY,
    expires_at      BIGINT NOT NULL
  );
  CREATE INDEX webauthn_login_challenges_expiry ON webauthn_login_challenges(expires_at);
  `,
  // v2: row-level security on notes (ADR 0022), a second IDOR barrier under the owner_id
  // that every note query already carries (invariant 2). The API logs in as bastion_app: it
  // owns nothing (an owner skips RLS), cannot bypass RLS, changes rows but not the schema.
  // Logs in, rather than switching to it with SET ROLE from the owner's login: PostgreSQL
  // checks SET ROLE against the login user, so injected SQL could switch back.
  `
  DO $$ BEGIN
    -- NOLOGIN until the operator gives it a password (compose: deploy/postgres/init-app-role.sh).
    CREATE ROLE bastion_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
  EXCEPTION WHEN duplicate_object THEN NULL; -- one role per cluster, shared by every schema
  END $$;
  DO $$ BEGIN EXECUTE format('GRANT USAGE ON SCHEMA %I TO bastion_app', current_schema()); END $$;
  GRANT SELECT ON schema_version TO bastion_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON users, notes, refresh_tokens, lesson_progress, challenge_solves,
    user_mfa, mfa_recovery_codes, mfa_challenges, lab_instances, module_choices, passkeys,
    webauthn_challenges, webauthn_login_challenges TO bastion_app;
  -- Append-only for the API itself, not only through the triggers it could no longer drop.
  GRANT SELECT, INSERT ON audit_log TO bastion_app;

  ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
  -- app.user_id is set per transaction (set_config(..., true)), never per connection: a pooled
  -- connection cannot carry one request's user into the next. Unset, it is NULL or '' and
  -- matches no row: a query without a user context sees nothing and writes nothing.
  CREATE POLICY notes_owner ON notes TO bastion_app
    USING (owner_id = current_setting('app.user_id', true))
    WITH CHECK (owner_id = current_setting('app.user_id', true));

  -- Whether a note exists, never what it holds: the audit log tells a probe of someone else's
  -- note from a typo (authz.denied). Runs as the owner, with the search path fixed at creation.
  CREATE FUNCTION note_exists(note_id TEXT) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path FROM CURRENT AS $$ SELECT EXISTS (SELECT 1 FROM notes WHERE id = note_id) $$;
  REVOKE EXECUTE ON FUNCTION note_exists(TEXT) FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION note_exists(TEXT) TO bastion_app;
  `,
];



/** Advisory lock keys, a closed set: the only locks the application takes. */
const LOCKS = {
  /** Serialises schema migrations when several replicas boot at once. */
  migrations: 0x0ba5_0001,
  /** Serialises audit appends: the HMAC chain has one head. */
  audit_log: 0x0ba5_0002,
} as const;

/** serialization_failure, deadlock_detected: the transaction lost a race and can run again. */
const RETRYABLE = new Set(['40001', '40P01']);
const MAX_ATTEMPTS = 5;

/** A test schema name, or a schema an operator configured: validated, because it is an identifier, never bound. */
const SCHEMA_NAME = /^[a-z_][a-z0-9_]{0,62}$/;

/**
 * Rows as SQLite returns them: BIGINT and NUMERIC (COUNT, SUM) as numbers, refusing a
 * value a JavaScript number would silently round; BYTEA as a plain Uint8Array.
 */
const builtin = pg.types.getTypeParser as (oid: number, format: 'text' | 'binary') => (text: string) => unknown;
const parsers: pg.CustomTypesConfig = {
  getTypeParser: ((oid: number, format?: 'text' | 'binary') => {
    if (oid === 20 || oid === 1700) {
      return (text: string) => {
        const n = Number(text);
        if (!Number.isSafeInteger(n) && !(oid === 1700 && Number.isFinite(n))) throw new RangeError('numeric value out of range for a JavaScript number');
        return n;
      };
    }
    if (oid === 17) {
      const bytea = builtin(17, 'text') as (text: string) => Buffer;
      return (text: string) => {
        const buf = bytea(text);
        return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
      };
    }
    return builtin(oid, format ?? 'text');
  }) as pg.CustomTypesConfig['getTypeParser'],
};

const translated = new Map<string, { text: string; count: number }>();

/**
 * `?` → `$n`, outside quoted strings and identifiers. A `$` in service SQL is refused:
 * one placeholder style only, so no query can mix bound and positional values.
 * Exported for tests.
 */
export function toPositional(sql: string): { text: string; count: number } {
  const cached = translated.get(sql);
  if (cached) return cached;
  let text = '';
  let count = 0;
  let quote: string | null = null;
  for (const c of sql) {
    if (quote !== null) {
      if (c === quote) quote = null;
      text += c;
    } else if (c === "'" || c === '"') {
      quote = c;
      text += c;
    } else if (c === '?') {
      text += `$${String(++count)}`;
    } else if (c === '$') {
      throw new Error('use ? placeholders, not $n');
    } else {
      text += c;
    }
  }
  if (quote !== null) throw new Error('unterminated quote in SQL');
  const out = { text, count };
  // SQL strings are constants in the code (lint rules ban built SQL): this stays small.
  if (translated.size < 1000) translated.set(sql, out);
  return out;
}

const bind = (sql: string, params: SqlValue[]): [string, unknown[]] => {
  const { text, count } = toPositional(sql);
  if (count !== params.length) throw new Error(`query expects ${String(count)} parameters, got ${String(params.length)}`);
  // pg sends Buffers as bytea; a Uint8Array from node:sqlite or webauthn becomes one without a copy.
  return [text, params.map((p) => (p instanceof Uint8Array && !Buffer.isBuffer(p) ? Buffer.from(p.buffer, p.byteOffset, p.byteLength) : typeof p === 'bigint' ? p.toString() : p))];
};

const codeOf = (err: unknown): string | undefined =>
  typeof err === 'object' && err !== null && 'code' in err && typeof err.code === 'string' ? err.code : undefined;

export interface PostgresOptions {
  /** Connections per replica. Every replica adds this many to the server's max_connections. */
  poolSize?: number;
  /** Tables live in this schema (tests: one per test context), created if missing. */
  schema?: string;
  /** A pooled connection failed while idle (server restart, network): logged, the pool reconnects. */
  onIdleError?: (err: Error) => void;
}

class PgDb implements Db {
  readonly dialect = 'postgres';
  private readonly inside = new AsyncLocalStorage<PgDb>();
  private readonly ready: Promise<void>;

  constructor(
    private readonly pool: pg.Pool,
    ready: Promise<void>,
  ) {
    this.ready = ready;
  }

  private async free(): Promise<void> {
    if (this.inside.getStore() === this) {
      throw new Error('database handle used inside its own transaction: use the tx argument');
    }
    await this.ready;
  }

  async one(sql: string, ...params: SqlValue[]): Promise<unknown> {
    await this.free();
    return (await this.pool.query(...bind(sql, params))).rows[0] as unknown;
  }

  async many(sql: string, ...params: SqlValue[]): Promise<unknown[]> {
    await this.free();
    return (await this.pool.query(...bind(sql, params))).rows as unknown[];
  }

  async run(sql: string, ...params: SqlValue[]): Promise<{ changes: number }> {
    await this.free();
    return { changes: (await this.pool.query(...bind(sql, params))).rowCount ?? 0 };
  }

  /**
   * SERIALIZABLE: PostgreSQL aborts one of two transactions that would not give the same
   * result run one after the other (40001), and the transaction runs again from the start,
   * so a count-then-insert stays a check-then-act on fresh data without a per-query lock.
   * The body may therefore run more than once: it must only touch the database.
   *
   * With `lock`, READ COMMITTED behind an advisory lock instead: every append to the audit
   * chain waits its turn, rather than all but one failing and retrying under load. Not
   * SERIALIZABLE there: its snapshot would be taken by the lock statement itself, before
   * the wait, and the chain head read after the wait would be stale.
   */
  async transaction<T>(fn: (tx: Db) => Promise<T>, options: TransactionOptions = {}): Promise<T> {
    await this.free();
    for (let attempt = 1; ; attempt++) {
      const client = await this.pool.connect();
      const tx = new PgTx(client);
      let broken: Error | undefined;
      try {
        if (options.lock) {
          await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
          await client.query('SELECT pg_advisory_xact_lock($1)', [LOCKS[options.lock]]);
        } else {
          await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
        }
        // Row-level security reads it (ADR 0022); `true`: it ends with the transaction.
        if (options.user !== undefined) await client.query("SELECT set_config('app.user_id', $1, true)", [options.user]);
        const result = await this.inside.run(this, () => fn(tx));
        tx.ended = true;
        await client.query('COMMIT');
        return result;
      } catch (err) {
        tx.ended = true;
        try {
          await client.query('ROLLBACK');
        } catch (rollbackErr) {
          // The connection is unusable: destroy it rather than hand it to the next request.
          broken = rollbackErr instanceof Error ? rollbackErr : new Error('rollback failed');
        }
        const code = codeOf(err);
        if (broken === undefined && code !== undefined && RETRYABLE.has(code) && attempt < MAX_ATTEMPTS) {
          // Jittered backoff, so the transactions that collided do not collide again.
          await sleep(randomInt(1, 2 ** attempt * 5));
          continue;
        }
        throw err;
      } finally {
        client.release(broken);
      }
    }
  }

  async close(): Promise<void> {
    await this.ready.catch(() => undefined);
    await this.pool.end();
  }
}

/**
 * Schema migrations, once per database: replicas that boot together wait on an advisory
 * lock, and the first one migrates. The version lives in a table (no PRAGMA here).
 */
async function migrate(pool: pg.Pool, schema: string | undefined): Promise<void> {
  const client = await pool.connect();
  try {
    if (schema !== undefined) {
      // An identifier cannot be bound; the name matched SCHEMA_NAME in openPostgres().
      // eslint-disable-next-line no-restricted-syntax -- reviewed exception, validated identifier
      await client.query(`CREATE SCHEMA IF NOT EXISTS ${schema}`); // nosemgrep: bastion-sql-interpolation
    }
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1)', [LOCKS.migrations]);
    await client.query('CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)');
    const row = (await client.query('SELECT version FROM schema_version')).rows[0] as { version: number } | undefined;
    if (row === undefined) await client.query('INSERT INTO schema_version (version) VALUES (0)');
    for (let v = row?.version ?? 0; v < SCHEMA.length; v++) {
      await client.query(SCHEMA[v] as string);
      await client.query('UPDATE schema_version SET version = $1', [v + 1]);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

/** The handle a transaction body receives: one pooled connection, unusable once the transaction ended. */
class PgTx implements Db {
  readonly dialect = 'postgres';
  ended = false;

  constructor(private readonly client: pg.PoolClient) {}

  private async query(sql: string, params: SqlValue[]): Promise<pg.QueryResult> {
    if (this.ended) throw new Error('transaction handle used after the transaction ended');
    return this.client.query(...bind(sql, params));
  }

  async one(sql: string, ...params: SqlValue[]): Promise<unknown> {
    return (await this.query(sql, params)).rows[0] as unknown;
  }

  async many(sql: string, ...params: SqlValue[]): Promise<unknown[]> {
    return (await this.query(sql, params)).rows as unknown[];
  }

  async run(sql: string, ...params: SqlValue[]): Promise<{ changes: number }> {
    return { changes: (await this.query(sql, params)).rowCount ?? 0 };
  }

  transaction<T>(): Promise<T> {
    return Promise.reject(new Error('nested transactions are not supported'));
  }

  close(): Promise<void> {
    return Promise.reject(new Error('a transaction handle cannot close the database'));
  }
}

/**
 * Opens a pool; the first query waits for `after` (tests: the owner's migration) and, with
 * `migrate`, for the schema migrations. Synchronous so callers (and the test helpers) build
 * a context without awaiting.
 */
export function openPostgres(url: string, options: PostgresOptions & { migrate?: boolean; after?: Promise<unknown> } = {}): Db {
  const { schema } = options;
  if (schema !== undefined && !SCHEMA_NAME.test(schema)) throw new Error('invalid schema name');
  const pool = new pg.Pool({
    connectionString: url,
    max: options.poolSize ?? 10,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 10_000,
    allowExitOnIdle: true,
    application_name: 'bastion',
    // A runaway statement, or a transaction left open by a bug, cannot hold locks for ever.
    statement_timeout: 5000,
    idle_in_transaction_session_timeout: 10_000,
    types: parsers,
    ...(schema !== undefined ? { options: `-c search_path=${schema}` } : {}),
  });
  pool.on('error', (err) => options.onIdleError?.(err));
  const before = Promise.resolve(options.after);
  const ready = options.migrate ? before.then(() => migrate(pool, schema)) : before.then(() => undefined);
  // Awaited by every operation; this only stops an unawaited failure from crashing the process.
  ready.catch(() => undefined);
  return new PgDb(pool, ready);
}

/**
 * Fail closed at boot (ADR 0022): the API refuses a role under which row-level security
 * would not hold, a superuser, BYPASSRLS, the tables' owner or a member of the owner's role
 * (SET ROLE back to it), and a schema the migration job has not brought up to date.
 */
export async function assertAppRole(db: Db): Promise<void> {
  const row = (await db.one(
    `SELECT r.rolsuper OR r.rolbypassrls OR pg_has_role(current_user, t.tableowner, 'MEMBER') AS privileged,
            (SELECT version FROM schema_version) AS version
       FROM pg_roles r, pg_tables t
      WHERE r.rolname = current_user AND t.tablename = 'notes' AND t.schemaname = current_schema()`,
  )) as { privileged: boolean; version: number } | undefined;
  if (row === undefined) throw new Error('database schema missing: run the migration (node dist/cli.js migrate)');
  if (row.privileged) throw new Error('DATABASE_URL logs in with a role that skips row-level security: use bastion_app, not the owner');
  if (row.version !== SCHEMA.length) throw new Error(`database schema at version ${String(row.version)}, expected ${String(SCHEMA.length)}: run the migration`);
}

/** PostgreSQL error code for unique_violation. */
export const PG_UNIQUE_VIOLATION = '23505';
export { codeOf as pgErrorCode };
