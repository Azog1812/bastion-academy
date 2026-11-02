import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { AsyncLocalStorage } from 'node:async_hooks';
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';

/**
 * Persistence uses Node's built-in SQLite driver: zero native
 * dependencies, so nothing gets compiled or downloaded at install time
 * (a classic supply-chain attack vector via install scripts).
 *
 * Every query in the codebase goes through `prepare()` with bound
 * parameters. String concatenation into SQL is banned by lint rules and
 * by a Semgrep rule in CI.
 */

const MIGRATIONS: readonly string[] = [
  // Plain SQL, no interpolation (the `{` false positive comes from the DDL text).
  // nosemgrep
  /* v1 — initial schema */ `
  CREATE TABLE users (
    id             TEXT PRIMARY KEY,
    email          TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    failed_logins  INTEGER NOT NULL DEFAULT 0,
    locked_until   INTEGER NOT NULL DEFAULT 0,
    token_version  INTEGER NOT NULL DEFAULT 0,
    created_at     INTEGER NOT NULL
  ) STRICT;

  CREATE TABLE notes (
    id           TEXT PRIMARY KEY,
    owner_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id       TEXT NOT NULL,
    wrapped_dek  BLOB NOT NULL,
    iv           BLOB NOT NULL,
    tag          BLOB NOT NULL,
    ciphertext   BLOB NOT NULL,
    version      INTEGER NOT NULL DEFAULT 1,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
  ) STRICT;
  CREATE INDEX notes_owner ON notes(owner_id, updated_at DESC);

  CREATE TABLE refresh_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id    TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    expires_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    replaced_by  TEXT,
    created_at   INTEGER NOT NULL
  ) STRICT;
  CREATE INDEX refresh_family ON refresh_tokens(family_id);

  CREATE TABLE audit_log (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    actor_id   TEXT,
    action     TEXT NOT NULL,
    target     TEXT,
    ip         TEXT,
    outcome    TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    details    TEXT NOT NULL DEFAULT '{}',
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL UNIQUE
  ) STRICT;

  -- The audit log is append-only at the database level, not just by convention.
  CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
  CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
  `,
  /* v2 — learning progress. Content itself lives in content/ (ADR 0006), only progress is stored. */ `
  CREATE TABLE lesson_progress (
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lesson_id     TEXT NOT NULL,
    completed_at  INTEGER NOT NULL,
    PRIMARY KEY (user_id, lesson_id)
  ) STRICT, WITHOUT ROWID;
  `,
  /* v3 — challenges, scoreboard, TOTP MFA */ `
  -- Public pseudonym, opt-in: a learner without one never appears on the scoreboard.
  ALTER TABLE users ADD COLUMN display_name TEXT;
  CREATE UNIQUE INDEX users_display_name ON users(display_name COLLATE NOCASE) WHERE display_name IS NOT NULL;

  CREATE TABLE challenge_solves (
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_id  TEXT NOT NULL,
    points        INTEGER NOT NULL CHECK (points > 0),
    solved_at     INTEGER NOT NULL,
    PRIMARY KEY (user_id, challenge_id)
  ) STRICT, WITHOUT ROWID;
  CREATE INDEX challenge_solves_challenge ON challenge_solves(challenge_id);

  -- TOTP seed sealed with AES-256-GCM under the KEK ring; enabled_at is NULL while enrolment is pending.
  CREATE TABLE user_mfa (
    user_id     TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    key_id      TEXT NOT NULL,
    secret      BLOB NOT NULL,
    enabled_at  INTEGER,
    last_step   INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
  ) STRICT;

  CREATE TABLE mfa_recovery_codes (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    INTEGER,
    PRIMARY KEY (user_id, code_hash)
  ) STRICT, WITHOUT ROWID;

  -- Second login step: single-use, short-lived, attempt-capped. Only the SHA-256 of the token is stored.
  CREATE TABLE mfa_challenges (
    token_hash  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0
  ) STRICT, WITHOUT ROWID;
  `,
  // v4: lab instances (ADR 0009). UNIQUE(user_id): one running lab per learner,
  // enforced by the database, so two concurrent starts cannot both win.
  `
  CREATE TABLE lab_instances (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    challenge_id  TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
  ) STRICT;
  CREATE INDEX lab_instances_expiry ON lab_instances(expires_at);
  `,
  // v5: optional modules each learner added to their training. A row means "added";
  // removing deletes it, progress in lesson_progress is kept.
  `
  CREATE TABLE module_choices (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    module_id  TEXT NOT NULL,
    added_at   INTEGER NOT NULL,
    PRIMARY KEY (user_id, module_id)
  ) STRICT, WITHOUT ROWID;
  `,
  // v6: passkeys (WebAuthn, ADR 0016). credential_id is UNIQUE across users: one
  // authenticator key cannot be enrolled twice, nor claimed by a second account.
  // Public keys only (SPKI DER): nothing here lets anyone sign.
  `
  CREATE TABLE passkeys (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id  BLOB NOT NULL UNIQUE,
    public_key     BLOB NOT NULL,
    alg            INTEGER NOT NULL,
    sign_count     INTEGER NOT NULL,
    name           TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    last_used_at   INTEGER
  ) STRICT;
  CREATE INDEX passkeys_user ON passkeys(user_id);

  -- Single-use, short-lived challenges; only their SHA-256 is stored. A login challenge
  -- is bound to the MFA step it was issued for.
  CREATE TABLE webauthn_challenges (
    challenge_hash  TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose         TEXT NOT NULL CHECK (purpose IN ('register', 'login')),
    mfa_token_hash  TEXT,
    expires_at      INTEGER NOT NULL
  ) STRICT, WITHOUT ROWID;
  `,
  // v7: passwordless passkey login (ADR 0017). The challenge is issued before anyone is
  // identified, so it has no user: a table of its own rather than a nullable user_id that
  // every query on webauthn_challenges would then have to remember to exclude.
  `
  CREATE TABLE webauthn_login_challenges (
    challenge_hash  TEXT PRIMARY KEY,
    expires_at      INTEGER NOT NULL
  ) STRICT, WITHOUT ROWID;
  CREATE INDEX webauthn_login_challenges_expiry ON webauthn_login_challenges(expires_at);
  `,
];

/** Values a query can bind. No booleans: store 0/1, as SQLite and PostgreSQL agree on integers. */
export type SqlValue = string | number | bigint | null | Uint8Array;

/**
 * The only way services reach the database (ADR 0020). Asynchronous so that a network
 * database (PostgreSQL) fits behind the same calls as the embedded one.
 *
 * Rows come back as `unknown`: the caller states the shape it selected, as before.
 * Atomicity never relies on "no await in between" any more: a check-then-act is one
 * statement (compare-and-set, `UPDATE … RETURNING`) or runs inside `transaction()`.
 */
export interface Db {
  /** First row, or undefined. */
  one(sql: string, ...params: SqlValue[]): Promise<unknown>;
  many(sql: string, ...params: SqlValue[]): Promise<unknown[]>;
  /** Write; `changes` is the number of rows the statement touched. */
  run(sql: string, ...params: SqlValue[]): Promise<{ changes: number }>;
  /**
   * Runs `fn` in a transaction, rolled back if it throws. Every query of the transaction
   * must go through `tx`: the outer handle throws inside it rather than deadlocking.
   */
  transaction<T>(fn: (tx: Db) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

export type Database = Db;

/** A UNIQUE constraint refused the write (duplicate e-mail, pseudonym, credential). */
export function isUniqueViolation(err: unknown): boolean {
  return err instanceof Error && /UNIQUE constraint failed/.test(err.message);
}

/**
 * SQLite behind the async interface. One connection, so a transaction must not let other
 * requests interleave their statements between its BEGIN and COMMIT (they would become
 * part of it, and be rolled back with it): while one is open, every other operation waits
 * for it to end. Statements themselves stay synchronous, so outside a transaction nothing
 * can interleave within one.
 */
class SqliteDb implements Db {
  private open: Promise<void> | null = null;
  private readonly inside = new AsyncLocalStorage<SqliteDb>();

  constructor(private readonly raw: DatabaseSync) {}

  /**
   * Runs `op` once no transaction is open. The last check of `open` and `op` must be in
   * the same synchronous stretch: with an await between them, a transaction could BEGIN
   * in the gap and `op` would run inside it.
   */
  private async whenFree<T>(op: () => T): Promise<T> {
    if (this.inside.getStore() === this) {
      throw new Error('database handle used inside its own transaction: use the tx argument');
    }
    while (this.open) await this.open;
    return op();
  }

  one(sql: string, ...params: SqlValue[]): Promise<unknown> {
    return this.whenFree(() => this.raw.prepare(sql).get(...(params as SQLInputValue[])));
  }

  many(sql: string, ...params: SqlValue[]): Promise<unknown[]> {
    return this.whenFree(() => this.raw.prepare(sql).all(...(params as SQLInputValue[])));
  }

  run(sql: string, ...params: SqlValue[]): Promise<{ changes: number }> {
    return this.whenFree(() => ({ changes: Number(this.raw.prepare(sql).run(...(params as SQLInputValue[])).changes) }));
  }

  async transaction<T>(fn: (tx: Db) => Promise<T>): Promise<T> {
    let done = (): void => undefined;
    const tx = new SqliteTx(this.raw);
    // Claim the connection in the same synchronous stretch as the check (see whenFree).
    await this.whenFree(() => {
      this.open = new Promise<void>((resolve) => {
        done = resolve;
      });
      this.raw.exec('BEGIN IMMEDIATE');
    });
    try {
      const result = await this.inside.run(this, () => fn(tx));
      this.raw.exec('COMMIT');
      return result;
    } catch (err) {
      this.raw.exec('ROLLBACK');
      throw err;
    } finally {
      tx.ended = true;
      this.open = null;
      done();
    }
  }

  close(): Promise<void> {
    this.raw.close();
    return Promise.resolve();
  }
}

/** Every failure (a closed handle, an SQL error) becomes a rejection, never a synchronous throw. */
const settle = <T>(op: () => T): Promise<T> =>
  new Promise<T>((resolve) => {
    resolve(op());
  });

/** The handle a transaction body receives. Unusable once the transaction ended. */
class SqliteTx implements Db {
  ended = false;

  constructor(private readonly raw: DatabaseSync) {}

  private live(): DatabaseSync {
    if (this.ended) throw new Error('transaction handle used after the transaction ended');
    return this.raw;
  }

  one(sql: string, ...params: SqlValue[]): Promise<unknown> {
    return settle(() => this.live().prepare(sql).get(...(params as SQLInputValue[])));
  }

  many(sql: string, ...params: SqlValue[]): Promise<unknown[]> {
    return settle(() => this.live().prepare(sql).all(...(params as SQLInputValue[])));
  }

  run(sql: string, ...params: SqlValue[]): Promise<{ changes: number }> {
    return settle(() => ({ changes: Number(this.live().prepare(sql).run(...(params as SQLInputValue[])).changes) }));
  }

  transaction<T>(): Promise<T> {
    return Promise.reject(new Error('nested transactions are not supported'));
  }

  close(): Promise<void> {
    return Promise.reject(new Error('a transaction handle cannot close the database'));
  }
}

export function openDatabase(path: string): Database {
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- operator-controlled config, not user input
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });

  const raw = new DatabaseSync(path);
  raw.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    PRAGMA secure_delete = ON;
    PRAGMA trusted_schema = OFF;
  `);
  migrate(raw);
  return new SqliteDb(raw);
}

function migrate(db: DatabaseSync): void {
  const row = db.prepare('PRAGMA user_version').get() as { user_version: number };
  for (let v = row.user_version; v < MIGRATIONS.length; v++) {
    db.exec('BEGIN IMMEDIATE');
    try {
      db.exec(MIGRATIONS[v] as string);
      // PRAGMA cannot take bound parameters; the value is a loop counter, never external input.
      // eslint-disable-next-line no-restricted-syntax -- reviewed exception
      db.exec(`PRAGMA user_version = ${String(v + 1)}`); // nosemgrep: bastion-sql-interpolation
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  }
}
