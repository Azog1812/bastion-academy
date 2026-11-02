import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { AuditLog } from '../audit.js';
import type { Config } from '../config.js';
import { createDummyHash, hashPassword, needsRehash, verifyPassword } from '../crypto/password.js';
import { generateRefreshToken, hashRefreshToken, type Role, type TokenSigner } from '../crypto/tokens.js';
import { isUniqueViolation, type Database } from '../db.js';
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
      await this.db.run('INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)', id, email, hash, Date.now());
    } catch (err) {
      if (isUniqueViolation(err)) {
        await this.audit.record({ action: 'auth.register', outcome: 'failure', ip: ctx.ip, details: { reason: 'duplicate' } });
        throw conflict('An account with this e-mail already exists');
      }
      throw err;
    }
    await this.audit.record({ action: 'auth.register', outcome: 'success', actorId: id, target: id, ip: ctx.ip });
    return { id, email };
  }

  async login(email: string, password: string, ctx: RequestContext): Promise<LoginResult> {
    const user = await this.db.one('SELECT * FROM users WHERE email = ?', email) as UserRow | undefined;

    // Always pay the scrypt cost, even for unknown users (timing side channel).
    const ok = await verifyPassword(password, user?.password_hash ?? (await this.dummyHash));

    if (!user) {
      await this.audit.record({ action: 'auth.login', outcome: 'failure', ip: ctx.ip, details: { reason: 'unknown_user' } });
      throw unauthorized(INVALID_CREDENTIALS);
    }

    // Re-read lock state *after* the slow hash: another request may have locked
    // the account meanwhile, and the copy read before the await is stale.
    const { locked_until: lockedUntil } = await this.db.one('SELECT locked_until FROM users WHERE id = ?', user.id) as {
      locked_until: number;
    };
    if (lockedUntil > Date.now()) {
      await this.audit.record({ action: 'auth.login', outcome: 'denied', actorId: user.id, ip: ctx.ip, details: { reason: 'locked' } });
      throw unauthorized(INVALID_CREDENTIALS);
    }

    if (!ok) {
      await this.registerFailure(user, ctx);
      throw unauthorized(INVALID_CREDENTIALS);
    }

    // Transparent upgrade when the cost factor is raised in configuration.
    if (needsRehash(user.password_hash, this.cfg.SCRYPT_LOG_N)) {
      const upgraded = await hashPassword(password, this.cfg.SCRYPT_LOG_N);
      await this.db.run('UPDATE users SET password_hash = ? WHERE id = ?', upgraded, user.id);
    }

    if (await this.mfa.hasAnyFactor(user.id)) {
      // The failed-login counter is only reset once the second factor passes:
      // a stolen password must not buy unlimited code guesses.
      await this.audit.record({ action: 'auth.login', outcome: 'success', actorId: user.id, ip: ctx.ip, details: { mfa: 'pending' } });
      return this.mfaChallenge(user.id);
    }

    // Compare-and-set on the lock: the right password, checked while concurrent wrong
    // guesses locked the account, is refused like any attempt on a locked account.
    const reset = await this.db.run('UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ? AND locked_until <= ?', user.id, Date.now());
    if (reset.changes !== 1) {
      await this.audit.record({ action: 'auth.login', outcome: 'denied', actorId: user.id, ip: ctx.ip, details: { reason: 'locked' } });
      throw unauthorized(INVALID_CREDENTIALS);
    }
    await this.audit.record({ action: 'auth.login', outcome: 'success', actorId: user.id, ip: ctx.ip });
    return this.issue(user, randomUUID());
  }

  private async mfaChallenge(userId: string): Promise<MfaChallenge> {
    const token = randomBytes(32).toString('base64url');
    const now = Date.now();
    await this.db.run('DELETE FROM mfa_challenges WHERE expires_at <= ?', now);
    await this.db.run('INSERT INTO mfa_challenges (token_hash, user_id, expires_at) VALUES (?, ?, ?)', sha256(token), userId, now + MFA_CHALLENGE_TTL_MS);
    return { mfaRequired: true, mfaToken: token, expiresIn: MFA_CHALLENGE_TTL_MS / 1000 };
  }

  /** Passkey options for a pending MFA step. Does not spend an attempt: it proves nothing yet. */
  async passkeyOptions(mfaToken: string) {
    const row = await this.db.one('SELECT user_id FROM mfa_challenges WHERE token_hash = ? AND expires_at > ? AND attempts < ?', sha256(mfaToken), Date.now(), MFA_MAX_ATTEMPTS) as { user_id: string } | undefined;
    if (!row) throw unauthorized(INVALID_MFA);
    return this.passkeys.loginOptions(row.user_id, sha256(mfaToken));
  }

  /** Second login step: a TOTP code, a recovery code or a passkey assertion against a pending challenge. */
  async completeMfa(mfaToken: string, proof: string | { passkey: AssertionResponse }, ctx: RequestContext): Promise<TokenPair> {
    const hash = sha256(mfaToken);
    // Atomic attempt counter (invariant 5): concurrent guesses cannot exceed the cap.
    const row = await this.db.one(`UPDATE mfa_challenges SET attempts = attempts + 1
         WHERE token_hash = ? AND expires_at > ? AND attempts < ?
         RETURNING user_id`, hash, Date.now(), MFA_MAX_ATTEMPTS) as { user_id: string } | undefined;
    if (!row) {
      await this.db.run('DELETE FROM mfa_challenges WHERE token_hash = ?', hash);
      await this.audit.record({ action: 'auth.mfa', outcome: 'failure', ip: ctx.ip, details: { reason: 'invalid_challenge' } });
      throw unauthorized(INVALID_MFA);
    }

    const user = await this.db.one('SELECT * FROM users WHERE id = ?', row.user_id) as UserRow | undefined;
    if (!user) throw unauthorized(INVALID_MFA);
    if (user.locked_until > Date.now()) {
      await this.audit.record({ action: 'auth.mfa', outcome: 'denied', actorId: user.id, ip: ctx.ip, details: { reason: 'locked' } });
      throw unauthorized(INVALID_MFA);
    }

    const factor: SecondFactor | null =
      typeof proof === 'string' ? await this.mfa.verify(user.id, proof, ctx.ip) : await this.passkeys.verifyLogin(user.id, hash, proof.passkey, ctx.ip) ? 'passkey' : null;
    if (!factor) {
      // Wrong codes feed the same progressive lockout as wrong passwords.
      await this.registerFailure(user, ctx, 'auth.mfa');
      throw unauthorized(INVALID_MFA);
    }

    // Single use: the challenge is gone whatever happens next.
    await this.db.run('DELETE FROM mfa_challenges WHERE token_hash = ?', hash);
    await this.db.run('UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?', user.id);
    await this.audit.record({ action: 'auth.mfa', outcome: 'success', actorId: user.id, ip: ctx.ip, details: { factor } });
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
    const result = await this.passkeys.verifyPasswordless(cred);
    if ('reason' in result) {
      if (result.reason === 'clone') {
        await this.audit.record({ action: 'passkey.clone_detected', outcome: 'denied', actorId: result.userId ?? null, target: result.passkeyId ?? null, ip: ctx.ip });
      }
      // actorId only once a real credential of that account was found: a forged handle names nobody.
      await this.audit.record({
        action: 'auth.login',
        outcome: 'failure',
        actorId: result.passkeyId === undefined ? null : (result.userId ?? null),
        ip: ctx.ip,
        details: { method: 'passkey', reason: result.reason },
      });
      throw unauthorized(INVALID_PASSKEY);
    }
    const user = await this.db.one('SELECT * FROM users WHERE id = ?', result.userId) as UserRow | undefined;
    if (!user) throw unauthorized(INVALID_PASSKEY);
    await this.audit.record({ action: 'auth.login', outcome: 'success', actorId: user.id, ip: ctx.ip, details: { method: 'passkey' } });
    return this.issue(user, randomUUID());
  }

  /** Re-authentication before a sensitive change (enabling or disabling MFA). */
  async confirmPassword(userId: string, password: string, ctx: RequestContext): Promise<{ email: string }> {
    const user = await this.db.one('SELECT * FROM users WHERE id = ?', userId) as UserRow | undefined;
    if (!user || !(await verifyPassword(password, user.password_hash))) {
      await this.audit.record({ action: 'auth.reauth', outcome: 'failure', actorId: userId, ip: ctx.ip });
      throw unauthorized('Current password is incorrect');
    }
    return { email: user.email };
  }

  async profile(userId: string): Promise<{ displayName: string | null; mfaEnabled: boolean; totpEnabled: boolean; passkeys: number }> {
    const row = await this.db.one('SELECT display_name FROM users WHERE id = ?', userId) as
      | { display_name: string | null }
      | undefined;
    return {
      displayName: row?.display_name ?? null,
      mfaEnabled: await this.mfa.hasAnyFactor(userId),
      totpEnabled: await this.mfa.isEnabled(userId),
      passkeys: await this.passkeys.count(userId),
    };
  }

  /** Opt-in scoreboard pseudonym; null takes the user off the scoreboard. */
  async setDisplayName(userId: string, displayName: string | null, ctx: RequestContext): Promise<{ displayName: string | null }> {
    try {
      await this.db.run('UPDATE users SET display_name = ? WHERE id = ?', displayName, userId);
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict('This display name is already taken');
      throw err;
    }
    await this.audit.record({ action: 'profile.update', outcome: 'success', actorId: userId, ip: ctx.ip, details: { public: displayName !== null } });
    return { displayName };
  }

  private async registerFailure(user: UserRow, ctx: RequestContext, action: 'auth.login' | 'auth.mfa' = 'auth.login'): Promise<void> {
    const now = Date.now();
    const max = this.cfg.MAX_FAILED_LOGINS;
    // "Locked already?", the count and the lock in one transaction. With the lock set by a
    // second statement, guesses landing between the count reaching the threshold and the
    // lock were counted on top of it, and each of them was a free guess (invariant 5).
    const counted = await this.db.transaction(async (tx) => {
      const row = (await tx.one('SELECT failed_logins, locked_until FROM users WHERE id = ?', user.id)) as { failed_logins: number; locked_until: number } | undefined;
      if (!row || row.locked_until > now) return null;
      const failures = row.failed_logins + 1;
      // Progressive lockout: doubles with every extra series of failures, capped at 24 h.
      const seconds = failures >= max ? Math.min(this.cfg.LOCKOUT_SECONDS * 2 ** (Math.floor(failures / max) - 1), 86_400) : 0;
      await tx.run('UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?', failures, seconds > 0 ? now + seconds * 1000 : row.locked_until, user.id);
      return { failures, seconds };
    });

    if (counted === null) {
      // Locked by a concurrent guess while this one was being checked: refused, not counted.
      await this.audit.record({ action, outcome: 'denied', actorId: user.id, ip: ctx.ip, details: { reason: 'locked' } });
      return;
    }
    if (counted.seconds > 0) {
      await this.audit.record({ action: 'auth.lockout', outcome: 'denied', actorId: user.id, ip: ctx.ip, details: { failures: counted.failures, seconds: counted.seconds } });
    }
    const reason = action === 'auth.login' ? 'bad_password' : 'bad_code';
    await this.audit.record({ action, outcome: 'failure', actorId: user.id, ip: ctx.ip, details: { reason } });
  }

  /**
   * Refresh-token rotation with reuse detection (OAuth 2.0 Security BCP, RFC 9700 §4.14).
   * Each refresh token is single-use. Presenting an already-used token means it
   * was stolen (either the thief or the legitimate client used it first), so the
   * whole token family is revoked and every live access token is invalidated.
   */
  async refresh(token: string, ctx: RequestContext): Promise<TokenPair> {
    const row = await this.db.one('SELECT id, user_id, family_id, expires_at, revoked_at FROM refresh_tokens WHERE token_hash = ?', hashRefreshToken(token)) as RefreshRow | undefined;

    if (!row) throw unauthorized('Invalid refresh token');

    const reuse = async () => {
      await this.db.transaction(async (tx) => {
        await this.revokeFamily(row.family_id, tx);
        await tx.run('UPDATE users SET token_version = token_version + 1 WHERE id = ?', row.user_id);
      });
      await this.audit.record({
        action: 'auth.refresh_reuse_detected',
        outcome: 'denied',
        actorId: row.user_id,
        ip: ctx.ip,
        details: { family: row.family_id },
      });
      return unauthorized('Invalid refresh token');
    };

    if (row.revoked_at !== null) throw await reuse();
    if (row.expires_at <= Date.now()) throw unauthorized('Refresh token expired');

    const user = await this.db.one('SELECT * FROM users WHERE id = ?', row.user_id) as UserRow | undefined;
    if (!user) throw unauthorized('Invalid refresh token');

    // Claim the token with one compare-and-set statement: the database, not the event
    // loop, makes it atomic. Two concurrent requests with the same token cannot both
    // succeed: the loser sees 0 changed rows and is treated as a replay (TOCTOU-safe).
    const claimed = await this.db.run('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL', Date.now(), row.id);
    if (claimed.changes !== 1) throw await reuse();

    const pair = await this.issue(user, row.family_id, row.id);
    await this.audit.record({ action: 'auth.refresh', outcome: 'success', actorId: user.id, ip: ctx.ip });
    return pair;
  }

  async logout(token: string, ctx: RequestContext): Promise<void> {
    const row = await this.db.one('SELECT user_id, family_id FROM refresh_tokens WHERE token_hash = ?', hashRefreshToken(token)) as { user_id: string; family_id: string } | undefined;
    if (row) {
      await this.revokeFamily(row.family_id);
      await this.audit.record({ action: 'auth.logout', outcome: 'success', actorId: row.user_id, ip: ctx.ip });
    }
    // Unknown token: succeed silently, logout must be idempotent and leak nothing.
  }

  async logoutEverywhere(userId: string, ctx: RequestContext): Promise<void> {
    await this.revokeAllForUser(userId);
    await this.audit.record({ action: 'auth.logout_all', outcome: 'success', actorId: userId, ip: ctx.ip });
  }

  async changePassword(userId: string, current: string, next: string, ctx: RequestContext): Promise<void> {
    const user = await this.db.one('SELECT * FROM users WHERE id = ?', userId) as UserRow | undefined;
    if (!user || !(await verifyPassword(current, user.password_hash))) {
      await this.audit.record({ action: 'auth.password_change', outcome: 'failure', actorId: userId, ip: ctx.ip });
      throw unauthorized('Current password is incorrect');
    }
    const problem = passwordProblem(next, user.email);
    if (problem) throw badRequest(`Password ${problem}`);
    if (await verifyPassword(next, user.password_hash)) throw badRequest('New password must differ from the current one');

    const hash = await hashPassword(next, this.cfg.SCRYPT_LOG_N);
    await this.db.transaction(async (tx) => {
      await tx.run('UPDATE users SET password_hash = ? WHERE id = ?', hash, userId);
      await this.revokeAllForUser(userId, tx);
    });
    await this.audit.record({ action: 'auth.password_change', outcome: 'success', actorId: userId, ip: ctx.ip });
  }

  /** Current role and token version: checked on every request so revocation is immediate. */
  async sessionState(userId: string): Promise<{ role: Role; tokenVersion: number } | null> {
    const row = await this.db.one('SELECT role, token_version FROM users WHERE id = ?', userId) as
      | { role: Role; token_version: number }
      | undefined;
    return row ? { role: row.role, tokenVersion: row.token_version } : null;
  }

  private async revokeAllForUser(userId: string, db: Database = this.db): Promise<void> {
    const now = Date.now();
    await db.run('UPDATE users SET token_version = token_version + 1 WHERE id = ?', userId);
    await db.run('UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL', now, userId);
  }

  private async revokeFamily(familyId: string, db: Database = this.db): Promise<void> {
    await db.run('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL', Date.now(), familyId);
  }

  private async issue(user: UserRow, familyId: string, replacing?: string): Promise<TokenPair> {
    const current = await this.sessionState(user.id) ?? { role: user.role, tokenVersion: user.token_version };
    const accessToken = await this.signer.sign({ sub: user.id, role: current.role, tv: current.tokenVersion });
    const { token, hash } = generateRefreshToken();
    const id = randomUUID();
    const now = Date.now();

    await this.db.transaction(async (tx) => {
      await tx.run(
        `INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        id,
        user.id,
        familyId,
        hash,
        now + this.cfg.REFRESH_TOKEN_TTL_SECONDS * 1000,
        now,
      );
      if (replacing) await tx.run('UPDATE refresh_tokens SET replaced_by = ? WHERE id = ?', id, replacing);
    });

    return { accessToken, refreshToken: token, tokenType: 'Bearer', expiresIn: this.cfg.ACCESS_TOKEN_TTL_SECONDS };
  }
}
