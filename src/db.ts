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
