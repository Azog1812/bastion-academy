import { randomUUID } from 'node:crypto';
import type { AuditLog } from '../audit.js';
import type { Config } from '../config.js';
import { createDummyHash, hashPassword, needsRehash, verifyPassword } from '../crypto/password.js';
import { generateRefreshToken, hashRefreshToken, type Role, type TokenSigner } from '../crypto/tokens.js';
import { transaction, type Database } from '../db.js';
import { badRequest, conflict, unauthorized } from '../errors.js';
import { passwordProblem } from '../security/password-policy.js';

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  role: Role;
  failed_logins: number;
  locked_until: number;
  token_version: number;
}

interface RefreshRow {
  id: string;
  user_id: string;
  family_id: string;
  expires_at: number;
  revoked_at: number | null;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
}

export interface RequestContext {
  ip: string | null;
}

/** Same message for "unknown e-mail", "wrong password" and "account locked": no account enumeration. */
const INVALID_CREDENTIALS = 'Invalid e-mail or password';

export class AuthService {
  private dummyHash: Promise<string>;

  constructor(
    private readonly db: Database,
    private readonly cfg: Config,
    private readonly signer: TokenSigner,
    private readonly audit: AuditLog,
  ) {
    this.dummyHash = createDummyHash(cfg.SCRYPT_LOG_N);
  }

  async register(email: string, password: string, ctx: RequestContext): Promise<{ id: string; email: string }> {
    const problem = passwordProblem(password, email);
    if (problem) throw badRequest(`Password ${problem}`);

    const hash = await hashPassword(password, this.cfg.SCRYPT_LOG_N);
    const id = randomUUID();
    try {
      this.db
        .prepare('INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)')
        .run(id, email, hash, Date.now());
    } catch (err) {
      if (err instanceof Error && /UNIQUE/.test(err.message)) {
        this.audit.record({ action: 'auth.register', outcome: 'failure', ip: ctx.ip, details: { reason: 'duplicate' } });
        throw conflict('An account with this e-mail already exists');
      }
      throw err;
    }
    this.audit.record({ action: 'auth.register', outcome: 'success', actorId: id, target: id, ip: ctx.ip });
    return { id, email };
  }

  async login(email: string, password: string, ctx: RequestContext): Promise<TokenPair> {
    const user = this.db.prepare('SELECT * FROM users WHERE email = ?').get(email) as UserRow | undefined;

    // Always pay the scrypt cost, even for unknown users (timing side channel).
    const ok = await verifyPassword(password, user?.password_hash ?? (await this.dummyHash));

    if (!user) {
      this.audit.record({ action: 'auth.login', outcome: 'failure', ip: ctx.ip, details: { reason: 'unknown_user' } });
      throw unauthorized(INVALID_CREDENTIALS);
    }

    // Re-read lock state *after* the slow hash: another request may have locked
    // the account meanwhile, and the copy read before the await is stale.
    const { locked_until: lockedUntil } = this.db.prepare('SELECT locked_until FROM users WHERE id = ?').get(user.id) as {
      locked_until: number;
    };
    if (lockedUntil > Date.now()) {
      this.audit.record({ action: 'auth.login', outcome: 'denied', actorId: user.id, ip: ctx.ip, details: { reason: 'locked' } });
      throw unauthorized(INVALID_CREDENTIALS);
    }

    if (!ok) {
      this.registerFailure(user, ctx);
      throw unauthorized(INVALID_CREDENTIALS);
    }

    this.db.prepare('UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?').run(user.id);

    // Transparent upgrade when the cost factor is raised in configuration.
    if (needsRehash(user.password_hash, this.cfg.SCRYPT_LOG_N)) {
      const upgraded = await hashPassword(password, this.cfg.SCRYPT_LOG_N);
      this.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(upgraded, user.id);
    }

    this.audit.record({ action: 'auth.login', outcome: 'success', actorId: user.id, ip: ctx.ip });
    return this.issue(user, randomUUID());
  }

  private registerFailure(user: UserRow, ctx: RequestContext): void {
    // Atomic increment: concurrent wrong guesses cannot under-count (no read-modify-write race).
    const { failed_logins: failures } = this.db
      .prepare('UPDATE users SET failed_logins = failed_logins + 1 WHERE id = ? RETURNING failed_logins')
      .get(user.id) as { failed_logins: number };

    if (failures >= this.cfg.MAX_FAILED_LOGINS) {
      // Progressive lockout: doubles with every extra series of failures, capped at 24 h.
      const series = Math.floor(failures / this.cfg.MAX_FAILED_LOGINS);
      const seconds = Math.min(this.cfg.LOCKOUT_SECONDS * 2 ** (series - 1), 86_400);
      this.db.prepare('UPDATE users SET locked_until = ? WHERE id = ?').run(Date.now() + seconds * 1000, user.id);
      this.audit.record({ action: 'auth.lockout', outcome: 'denied', actorId: user.id, ip: ctx.ip, details: { failures, seconds } });
    }
    this.audit.record({ action: 'auth.login', outcome: 'failure', actorId: user.id, ip: ctx.ip, details: { reason: 'bad_password' } });
  }

  /**
   * Refresh-token rotation with reuse detection (OAuth 2.0 Security BCP, RFC 9700 §4.14).
   * Each refresh token is single-use. Presenting an already-used token means it
   * was stolen (either the thief or the legitimate client used it first), so the
   * whole token family is revoked and every live access token is invalidated.
   */
  async refresh(token: string, ctx: RequestContext): Promise<TokenPair> {
    const row = this.db
      .prepare('SELECT id, user_id, family_id, expires_at, revoked_at FROM refresh_tokens WHERE token_hash = ?')
      .get(hashRefreshToken(token)) as RefreshRow | undefined;

    if (!row) throw unauthorized('Invalid refresh token');

    const reuse = () => {
      transaction(this.db, () => {
        this.revokeFamily(row.family_id);
        this.db.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ?').run(row.user_id);
      });
      this.audit.record({
        action: 'auth.refresh_reuse_detected',
        outcome: 'denied',
        actorId: row.user_id,
        ip: ctx.ip,
        details: { family: row.family_id },
      });
      return unauthorized('Invalid refresh token');
    };

    if (row.revoked_at !== null) throw reuse();
    if (row.expires_at <= Date.now()) throw unauthorized('Refresh token expired');

    const user = this.db.prepare('SELECT * FROM users WHERE id = ?').get(row.user_id) as UserRow | undefined;
    if (!user) throw unauthorized('Invalid refresh token');

    // Atomically claim the token *before* any await. Two concurrent requests
    // with the same token cannot both succeed: the loser sees 0 changed rows
    // and is treated as a replay (TOCTOU-safe).
    const claimed = this.db
      .prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL')
      .run(Date.now(), row.id);
    if (Number(claimed.changes) !== 1) throw reuse();

    const pair = await this.issue(user, row.family_id, row.id);
    this.audit.record({ action: 'auth.refresh', outcome: 'success', actorId: user.id, ip: ctx.ip });
    return pair;
  }

  logout(token: string, ctx: RequestContext): void {
    const row = this.db
      .prepare('SELECT user_id, family_id FROM refresh_tokens WHERE token_hash = ?')
      .get(hashRefreshToken(token)) as { user_id: string; family_id: string } | undefined;
    if (row) {
      this.revokeFamily(row.family_id);
      this.audit.record({ action: 'auth.logout', outcome: 'success', actorId: row.user_id, ip: ctx.ip });
    }
    // Unknown token: succeed silently, logout must be idempotent and leak nothing.
  }

  logoutEverywhere(userId: string, ctx: RequestContext): void {
    this.revokeAllForUser(userId);
    this.audit.record({ action: 'auth.logout_all', outcome: 'success', actorId: userId, ip: ctx.ip });
  }

  async changePassword(userId: string, current: string, next: string, ctx: RequestContext): Promise<void> {
    const user = this.db.prepare('SELECT * FROM users WHERE id = ?').get(userId) as UserRow | undefined;
    if (!user || !(await verifyPassword(current, user.password_hash))) {
      this.audit.record({ action: 'auth.password_change', outcome: 'failure', actorId: userId, ip: ctx.ip });
      throw unauthorized('Current password is incorrect');
    }
    const problem = passwordProblem(next, user.email);
    if (problem) throw badRequest(`Password ${problem}`);
    if (await verifyPassword(next, user.password_hash)) throw badRequest('New password must differ from the current one');

    const hash = await hashPassword(next, this.cfg.SCRYPT_LOG_N);
    transaction(this.db, () => {
      this.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, userId);
      this.revokeAllForUser(userId);
    });
    this.audit.record({ action: 'auth.password_change', outcome: 'success', actorId: userId, ip: ctx.ip });
  }

  /** Current role and token version: checked on every request so revocation is immediate. */
  sessionState(userId: string): { role: Role; tokenVersion: number } | null {
    const row = this.db.prepare('SELECT role, token_version FROM users WHERE id = ?').get(userId) as
      | { role: Role; token_version: number }
      | undefined;
    return row ? { role: row.role, tokenVersion: row.token_version } : null;
  }

  private revokeAllForUser(userId: string): void {
    const now = Date.now();
    this.db.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ?').run(userId);
    this.db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').run(now, userId);
  }

  private revokeFamily(familyId: string): void {
    this.db
      .prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL')
      .run(Date.now(), familyId);
  }

  private async issue(user: UserRow, familyId: string, replacing?: string): Promise<TokenPair> {
    const current = this.sessionState(user.id) ?? { role: user.role, tokenVersion: user.token_version };
    const accessToken = await this.signer.sign({ sub: user.id, role: current.role, tv: current.tokenVersion });
    const { token, hash } = generateRefreshToken();
    const id = randomUUID();
    const now = Date.now();

    transaction(this.db, () => {
      this.db
        .prepare(
          `INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(id, user.id, familyId, hash, now + this.cfg.REFRESH_TOKEN_TTL_SECONDS * 1000, now);
      if (replacing) this.db.prepare('UPDATE refresh_tokens SET replaced_by = ? WHERE id = ?').run(id, replacing);
    });

    return { accessToken, refreshToken: token, tokenType: 'Bearer', expiresIn: this.cfg.ACCESS_TOKEN_TTL_SECONDS };
  }
}
