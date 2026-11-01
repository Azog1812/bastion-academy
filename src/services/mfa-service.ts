import type { AuditLog } from '../audit.js';
import { openSecret, rewrapSecret, sealSecret, type Kms } from '../crypto/envelope.js';
import {
  base32Encode,
  generateRecoveryCodes,
  generateTotpSecret,
  hashRecoveryCode,
  isRecoveryCodeFormat,
  otpauthUri,
  verifyTotp,
} from '../crypto/totp.js';
import { transaction, type Database } from '../db.js';
import { badRequest, conflict } from '../errors.js';

interface MfaRow {
  key_id: string;
  secret: Uint8Array;
  enabled_at: number | null;
  last_step: number;
}

export type SecondFactor = 'totp' | 'recovery' | 'passkey';

const aad = (userId: string) => `bastion:totp-secret:v1:${userId}`;

/**
 * TOTP second factor (RFC 6238) with single-use recovery codes.
 *
 * - The seed is sealed under the KEK ring (envelope.ts): a database dump alone
 *   does not let anyone generate codes.
 * - Enrolment is two-step (setup, then enable with a valid code), so a user
 *   cannot lock themselves out with a mistyped seed.
 * - A code is accepted at most once (last_step), and claiming it is an atomic
 *   UPDATE: two concurrent requests with the same code cannot both pass.
 *
 * Password re-authentication for setup/disable is done by the caller
 * (AuthService owns passwords).
 */
export class MfaService {
  constructor(
    private readonly db: Database,
    private readonly kms: Kms,
    private readonly audit: AuditLog,
    private readonly issuer: string,
    private readonly now: () => number = Date.now,
  ) {}

  private row(userId: string): MfaRow | undefined {
    return this.db.prepare('SELECT key_id, secret, enabled_at, last_step FROM user_mfa WHERE user_id = ?').get(userId) as
      | MfaRow
      | undefined;
  }

  /** TOTP enrolled and confirmed. */
  isEnabled(userId: string): boolean {
    return this.row(userId)?.enabled_at != null;
  }

  private passkeys(userId: string): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?').get(userId) as { n: number }).n;
  }

  /** Any second factor: TOTP or at least one passkey (ADR 0016). Login asks for it when true. */
  hasAnyFactor(userId: string): boolean {
    return this.isEnabled(userId) || this.passkeys(userId) > 0;
  }

  /**
   * Recovery codes for the first second factor of an account (a passkey enrolled before
   * any TOTP): shown once, like at TOTP enrolment. Null when the account already has some.
   */
  issueRecoveryCodesIfNone(userId: string): string[] | null {
    const { n } = this.db.prepare('SELECT COUNT(*) AS n FROM mfa_recovery_codes WHERE user_id = ?').get(userId) as { n: number };
    if (n > 0) return null;
    const { codes, hashes } = generateRecoveryCodes();
    transaction(this.db, () => {
      const insert = this.db.prepare('INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES (?, ?)');
      for (const h of hashes) insert.run(userId, h);
    });
    return codes;
  }

  /** Called when a factor goes away: with none left, recovery codes and pending MFA steps go too. */
  dropIfNoFactor(userId: string): void {
    if (this.hasAnyFactor(userId)) return;
    transaction(this.db, () => {
      this.db.prepare('DELETE FROM mfa_recovery_codes WHERE user_id = ?').run(userId);
      this.db.prepare('DELETE FROM mfa_challenges WHERE user_id = ?').run(userId);
    });
  }

  /** Starts (or restarts) enrolment. The seed is returned once, for the authenticator app. */
  async setup(userId: string, account: string, ip: string | null): Promise<{ secret: string; otpauthUri: string }> {
    if (this.isEnabled(userId)) throw conflict('Two-factor authentication is already enabled');
    const secret = generateTotpSecret();
    try {
      const { keyId, blob } = await sealSecret(this.kms, secret, aad(userId));
      this.db
        .prepare(
          `INSERT INTO user_mfa (user_id, key_id, secret, enabled_at, last_step, created_at) VALUES (?, ?, ?, NULL, 0, ?)
           ON CONFLICT (user_id) DO UPDATE SET key_id = excluded.key_id, secret = excluded.secret, last_step = 0, created_at = excluded.created_at`,
        )
        .run(userId, keyId, blob, this.now());
      this.audit.record({ action: 'mfa.setup', outcome: 'success', actorId: userId, ip });
      return { secret: base32Encode(secret), otpauthUri: otpauthUri(secret, account, this.issuer) };
    } finally {
      secret.fill(0);
    }
  }

  /** Confirms enrolment with a first valid code and returns the recovery codes (shown once). */
  async enable(userId: string, code: string, ip: string | null): Promise<string[]> {
    const row = this.row(userId);
    if (!row) throw badRequest('Start the two-factor setup first');
    if (row.enabled_at !== null) throw conflict('Two-factor authentication is already enabled');
    if ((await this.claimTotp(userId, row, code)) === null) {
      this.audit.record({ action: 'mfa.enable', outcome: 'failure', actorId: userId, ip });
      throw badRequest('Invalid code: check the time on your phone and try the next code');
    }
    const { codes, hashes } = generateRecoveryCodes();
    transaction(this.db, () => {
      this.db.prepare('UPDATE user_mfa SET enabled_at = ? WHERE user_id = ?').run(this.now(), userId);
      this.db.prepare('DELETE FROM mfa_recovery_codes WHERE user_id = ?').run(userId);
      const insert = this.db.prepare('INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES (?, ?)');
      for (const h of hashes) insert.run(userId, h);
    });
    this.audit.record({ action: 'mfa.enable', outcome: 'success', actorId: userId, ip });
    return codes;
  }

  /** Checks a TOTP code or a recovery code, and consumes it. Recovery codes also stand in for passkeys. */
  async verify(userId: string, code: string, ip: string | null): Promise<SecondFactor | null> {
    const row = this.row(userId);
    const trimmed = code.trim();
    if (/^\d{6}$/.test(trimmed)) return row && row.enabled_at !== null && (await this.claimTotp(userId, row, trimmed)) !== null ? 'totp' : null;
    if (!isRecoveryCodeFormat(trimmed) || !this.hasAnyFactor(userId)) return null;

    const used = this.db
      .prepare('UPDATE mfa_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL')
      .run(this.now(), userId, hashRecoveryCode(trimmed));
    if (Number(used.changes) !== 1) return null;
    const { left } = this.db
      .prepare('SELECT COUNT(*) AS left FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL')
      .get(userId) as { left: number };
    this.audit.record({ action: 'mfa.recovery_code_used', outcome: 'success', actorId: userId, ip, details: { left } });
    return 'recovery';
  }

  /** Removes TOTP. Recovery codes stay while a passkey remains (ADR 0016). */
  disable(userId: string, ip: string | null): void {
    this.db.prepare('DELETE FROM user_mfa WHERE user_id = ?').run(userId);
    this.dropIfNoFactor(userId);
    this.audit.record({ action: 'mfa.disable', outcome: 'success', actorId: userId, ip });
  }

  /** Operator key rotation: re-wrap every seed under the active KEK (inside Vault when it is Vault). */
  async rotateKeys(): Promise<number> {
    const rows = this.db.prepare('SELECT user_id, key_id, secret FROM user_mfa WHERE key_id != ?').all(await this.kms.activeKeyId()) as {
      user_id: string;
      key_id: string;
      secret: Uint8Array;
    }[];
    let resealed = 0;
    for (const r of rows) {
      const { keyId, wrapped } = await rewrapSecret(this.kms, r.key_id, Buffer.from(r.secret), aad(r.user_id));
      // Compare-and-set: a seed replaced by a new setup during the rotation is left alone.
      const updated = this.db.prepare('UPDATE user_mfa SET key_id = ?, secret = ? WHERE user_id = ? AND secret = ?').run(keyId, wrapped, r.user_id, r.secret);
      resealed += Number(updated.changes);
    }
    return resealed;
  }

  private async claimTotp(userId: string, row: MfaRow, code: string): Promise<number | null> {
    const secret = await openSecret(this.kms, row.key_id, Buffer.from(row.secret), aad(userId));
    try {
      const step = verifyTotp(secret, code, this.now(), row.last_step);
      if (step === null) return null;
      // Compare-and-set (invariant 5): if another request consumed this step (or a later one)
      // first, this one loses. The seed is compared too: the KMS call above is an await, and a
      // new setup in the meantime must not let a code of the old seed confirm the new one.
      const claimed = this.db
        .prepare('UPDATE user_mfa SET last_step = ? WHERE user_id = ? AND last_step < ? AND secret = ?')
        .run(step, userId, step, row.secret);
      return Number(claimed.changes) === 1 ? step : null;
    } finally {
      secret.fill(0);
    }
  }
}
