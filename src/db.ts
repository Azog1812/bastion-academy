import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

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
];

export type Database = DatabaseSync;

export function openDatabase(path: string): Database {
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- operator-controlled config, not user input
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });

  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    PRAGMA secure_delete = ON;
    PRAGMA trusted_schema = OFF;
  `);
  migrate(db);
  return db;
}

function migrate(db: Database): void {
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

/** Runs `fn` inside a transaction; rolls back on any thrown error. */
export function transaction<T>(db: Database, fn: () => T): T {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}
