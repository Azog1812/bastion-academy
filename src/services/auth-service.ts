import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { AuditLog } from '../audit.js';
import type { Config } from '../config.js';
import { createDummyHash, hashPassword, needsRehash, verifyPassword } from '../crypto/password.js';
import { generateRefreshToken, hashRefreshToken, type Role, type TokenSigner } from '../crypto/tokens.js';
import { transaction, type Database } from '../db.js';
import { badRequest, conflict, unauthorized } from '../errors.js';
import { passwordProblem } from '../security/password-policy.js';
import type { MfaService, SecondFactor } from './mfa-service.js';
import type { AssertionResponse, DiscoverableAssertionResponse, PasskeyService } from './passkey-service.js';

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

/** Password accepted, second factor still required. The token is opaque, single-use and short-lived. */
export interface MfaChallenge {
  mfaRequired: true;
  mfaToken: string;
  expiresIn: number;
}

export type LoginResult = TokenPair | MfaChallenge;

export const isMfaChallenge = (r: LoginResult): r is MfaChallenge => 'mfaRequired' in r;

export interface RequestContext {
  ip: string | null;
}

/** Same message for "unknown e-mail", "wrong password" and "account locked": no account enumeration. */
const INVALID_CREDENTIALS = 'Invalid e-mail or password';
const INVALID_MFA = 'Invalid or expired verification code';
/** One message for every passwordless failure: which check failed is audited, not told. */
const INVALID_PASSKEY = 'Passkey not recognised';

const MFA_CHALLENGE_TTL_MS = 5 * 60 * 1000;
/** Per challenge. With ±1 step, 5 tries give a 1.5e-5 chance of guessing a 6-digit code; then the password is needed again. */
const MFA_MAX_ATTEMPTS = 5;

const sha256 = (v: string) => createHash('sha256').update(v).digest('hex');

export class AuthService {
  private dummyHash: Promise<string>;

  constructor(
    private readonly db: Database,
    private readonly cfg: Config,
    private readonly signer: TokenSigner,
    private readonly audit: AuditLog,
    private readonly mfa: MfaService,
    private readonly passkeys: PasskeyService,
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

  async login(email: string, password: string, ctx: RequestContext): Promise<LoginResult> {
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

    // Transparent upgrade when the cost factor is raised in configuration.
    if (needsRehash(user.password_hash, this.cfg.SCRYPT_LOG_N)) {
      const upgraded = await hashPassword(password, this.cfg.SCRYPT_LOG_N);
      this.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(upgraded, user.id);
    }

    if (this.mfa.hasAnyFactor(user.id)) {
      // The failed-login counter is only reset once the second factor passes:
      // a stolen password must not buy unlimited code guesses.
      this.audit.record({ action: 'auth.login', outcome: 'success', actorId: user.id, ip: ctx.ip, details: { mfa: 'pending' } });
      return this.mfaChallenge(user.id);
    }

    this.db.prepare('UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?').run(user.id);
    this.audit.record({ action: 'auth.login', outcome: 'success', actorId: user.id, ip: ctx.ip });
    return this.issue(user, randomUUID());
  }

  private mfaChallenge(userId: string): MfaChallenge {
    const token = randomBytes(32).toString('base64url');
    const now = Date.now();
    this.db.prepare('DELETE FROM mfa_challenges WHERE expires_at <= ?').run(now);
    this.db
      .prepare('INSERT INTO mfa_challenges (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
      .run(sha256(token), userId, now + MFA_CHALLENGE_TTL_MS);
    return { mfaRequired: true, mfaToken: token, expiresIn: MFA_CHALLENGE_TTL_MS / 1000 };
  }

  /** Passkey options for a pending MFA step. Does not spend an attempt: it proves nothing yet. */
  passkeyOptions(mfaToken: string) {
    const row = this.db
      .prepare('SELECT user_id FROM mfa_challenges WHERE token_hash = ? AND expires_at > ? AND attempts < ?')
      .get(sha256(mfaToken), Date.now(), MFA_MAX_ATTEMPTS) as { user_id: string } | undefined;
    if (!row) throw unauthorized(INVALID_MFA);
    return this.passkeys.loginOptions(row.user_id, sha256(mfaToken));
  }

  /** Second login step: a TOTP code, a recovery code or a passkey assertion against a pending challenge. */
  async completeMfa(mfaToken: string, proof: string | { passkey: AssertionResponse }, ctx: RequestContext): Promise<TokenPair> {
    const hash = sha256(mfaToken);
    // Atomic attempt counter (invariant 5): concurrent guesses cannot exceed the cap.
    const row = this.db
      .prepare(
        `UPDATE mfa_challenges SET attempts = attempts + 1
         WHERE token_hash = ? AND expires_at > ? AND attempts < ?
         RETURNING user_id`,
      )
      .get(hash, Date.now(), MFA_MAX_ATTEMPTS) as { user_id: string } | undefined;
    if (!row) {
      this.db.prepare('DELETE FROM mfa_challenges WHERE token_hash = ?').run(hash);
      this.audit.record({ action: 'auth.mfa', outcome: 'failure', ip: ctx.ip, details: { reason: 'invalid_challenge' } });
      throw unauthorized(INVALID_MFA);
    }

    const user = this.db.prepare('SELECT * FROM users WHERE id = ?').get(row.user_id) as UserRow | undefined;
    if (!user) throw unauthorized(INVALID_MFA);
    if (user.locked_until > Date.now()) {
      this.audit.record({ action: 'auth.mfa', outcome: 'denied', actorId: user.id, ip: ctx.ip, details: { reason: 'locked' } });
      throw unauthorized(INVALID_MFA);
    }

    const factor: SecondFactor | null =
      typeof proof === 'string' ? this.mfa.verify(user.id, proof, ctx.ip) : this.passkeys.verifyLogin(user.id, hash, proof.passkey, ctx.ip) ? 'passkey' : null;
    if (!factor) {
      // Wrong codes feed the same progressive lockout as wrong passwords.
      this.registerFailure(user, ctx, 'auth.mfa');
      throw unauthorized(INVALID_MFA);
    }

    // Single use: the challenge is gone whatever happens next.
    this.db.prepare('DELETE FROM mfa_challenges WHERE token_hash = ?').run(hash);
    this.db.prepare('UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?').run(user.id);
    this.audit.record({ action: 'auth.mfa', outcome: 'success', actorId: user.id, ip: ctx.ip, details: { factor } });
    return this.issue(user, randomUUID());
  }

  /** Challenge for a passwordless login (ADR 0017). */
  passwordlessOptions() {
    return this.passkeys.passwordlessOptions();
  }

  /**
   * Passwordless login (ADR 0017): one user-verified passkey assertion replaces password
   * *and* second factor. The passkey is itself multi-factor (the device it is on, plus the
   * PIN or biometric the authenticator checked), NIST SP 800-63B "multi-factor
   * cryptographic authenticator", AAL2 and phishing-resistant.
   *
   * The password lockout does not apply, on purpose: it exists to stop online guessing of
   * a password or a code, and a signature cannot be guessed. A learner whose account is
   * locked by someone hammering their password still gets in with their passkey (this
   * shrinks the "lockout as targeted DoS" accepted risk), and the lock is neither lifted
   * nor reset: the attacker stays locked out. For the same reason a failed assertion does
   * not count as a failed login: the user handle comes from the request, so counting
   * would hand anyone a way to lock any account.
   */
  async loginWithPasskey(cred: DiscoverableAssertionResponse, ctx: RequestContext): Promise<TokenPair> {
    const result = this.passkeys.verifyPasswordless(cred);
    if ('reason' in result) {
      if (result.reason === 'clone') {
        this.audit.record({ action: 'passkey.clone_detected', outcome: 'denied', actorId: result.userId ?? null, target: result.passkeyId ?? null, ip: ctx.ip });
      }
      // actorId only once a real credential of that account was found: a forged handle names nobody.
      this.audit.record({
        action: 'auth.login',
        outcome: 'failure',
        actorId: result.passkeyId === undefined ? null : (result.userId ?? null),
        ip: ctx.ip,
        details: { method: 'passkey', reason: result.reason },
      });
      throw unauthorized(INVALID_PASSKEY);
    }
    const user = this.db.prepare('SELECT * FROM users WHERE id = ?').get(result.userId) as UserRow | undefined;
    if (!user) throw unauthorized(INVALID_PASSKEY);
    this.audit.record({ action: 'auth.login', outcome: 'success', actorId: user.id, ip: ctx.ip, details: { method: 'passkey' } });
    return this.issue(user, randomUUID());
  }

  /** Re-authentication before a sensitive change (enabling or disabling MFA). */
  async confirmPassword(userId: string, password: string, ctx: RequestContext): Promise<{ email: string }> {
    const user = this.db.prepare('SELECT * FROM users WHERE id = ?').get(userId) as UserRow | undefined;
    if (!user || !(await verifyPassword(password, user.password_hash))) {
      this.audit.record({ action: 'auth.reauth', outcome: 'failure', actorId: userId, ip: ctx.ip });
      throw unauthorized('Current password is incorrect');
    }
    return { email: user.email };
  }

  profile(userId: string): { displayName: string | null; mfaEnabled: boolean; totpEnabled: boolean; passkeys: number } {
    const row = this.db.prepare('SELECT display_name FROM users WHERE id = ?').get(userId) as
      | { display_name: string | null }
      | undefined;
    return {
      displayName: row?.display_name ?? null,
      mfaEnabled: this.mfa.hasAnyFactor(userId),
      totpEnabled: this.mfa.isEnabled(userId),
      passkeys: this.passkeys.count(userId),
    };
  }

  /** Opt-in scoreboard pseudonym; null takes the user off the scoreboard. */
  setDisplayName(userId: string, displayName: string | null, ctx: RequestContext): { displayName: string | null } {
    try {
      this.db.prepare('UPDATE users SET display_name = ? WHERE id = ?').run(displayName, userId);
    } catch (err) {
      if (err instanceof Error && /UNIQUE/.test(err.message)) throw conflict('This display name is already taken');
      throw err;
    }
    this.audit.record({ action: 'profile.update', outcome: 'success', actorId: userId, ip: ctx.ip, details: { public: displayName !== null } });
    return { displayName };
  }

  private registerFailure(user: UserRow, ctx: RequestContext, action: 'auth.login' | 'auth.mfa' = 'auth.login'): void {
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
    const reason = action === 'auth.login' ? 'bad_password' : 'bad_code';
    this.audit.record({ action, outcome: 'failure', actorId: user.id, ip: ctx.ip, details: { reason } });
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
