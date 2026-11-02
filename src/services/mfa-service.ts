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
import type { Database } from '../db.js';
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

  private async row(userId: string, db: Database = this.db): Promise<MfaRow | undefined> {
    return (await db.one('SELECT key_id, secret, enabled_at, last_step FROM user_mfa WHERE user_id = ?', userId)) as MfaRow | undefined;
  }

  /** TOTP enrolled and confirmed. */
  async isEnabled(userId: string, db: Database = this.db): Promise<boolean> {
    return (await this.row(userId, db))?.enabled_at != null;
  }

  private async passkeys(userId: string, db: Database): Promise<number> {
    return ((await db.one('SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?', userId)) as { n: number }).n;
  }

  /** Any second factor: TOTP or at least one passkey (ADR 0016). Login asks for it when true. */
  async hasAnyFactor(userId: string, db: Database = this.db): Promise<boolean> {
    return (await this.isEnabled(userId, db)) || (await this.passkeys(userId, db)) > 0;
  }

  /**
   * Recovery codes for the first second factor of an account (a passkey enrolled before
   * any TOTP): shown once, like at TOTP enrolment. Null when the account already has some.
   */
  async issueRecoveryCodesIfNone(userId: string): Promise<string[] | null> {
    const { codes, hashes } = generateRecoveryCodes();
    // Check and insert in one transaction: two concurrent first enrolments must not
    // both see "none" and hand out two valid sets.
    return this.db.transaction(async (tx) => {
      const { n } = (await tx.one('SELECT COUNT(*) AS n FROM mfa_recovery_codes WHERE user_id = ?', userId)) as { n: number };
      if (n > 0) return null;
      for (const h of hashes) await tx.run('INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES (?, ?)', userId, h);
      return codes;
    });
  }

  /** Called when a factor goes away: with none left, recovery codes and pending MFA steps go too. */
  async dropIfNoFactor(userId: string): Promise<void> {
    await this.db.transaction(async (tx) => {
      if (await this.hasAnyFactor(userId, tx)) return;
      await tx.run('DELETE FROM mfa_recovery_codes WHERE user_id = ?', userId);
      await tx.run('DELETE FROM mfa_challenges WHERE user_id = ?', userId);
    });
  }

  /** Starts (or restarts) enrolment. The seed is returned once, for the authenticator app. */
  async setup(userId: string, account: string, ip: string | null): Promise<{ secret: string; otpauthUri: string }> {
    if (await this.isEnabled(userId)) throw conflict('Two-factor authentication is already enabled');
    const secret = generateTotpSecret();
    try {
      const { keyId, blob } = await sealSecret(this.kms, secret, aad(userId));
      await this.db.run(`INSERT INTO user_mfa (user_id, key_id, secret, enabled_at, last_step, created_at) VALUES (?, ?, ?, NULL, 0, ?)
           ON CONFLICT (user_id) DO UPDATE SET key_id = excluded.key_id, secret = excluded.secret, last_step = 0, created_at = excluded.created_at`, userId, keyId, blob, this.now());
      await this.audit.record({ action: 'mfa.setup', outcome: 'success', actorId: userId, ip });
      return { secret: base32Encode(secret), otpauthUri: otpauthUri(secret, account, this.issuer) };
    } finally {
      secret.fill(0);
    }
  }

  /** Confirms enrolment with a first valid code and returns the recovery codes (shown once). */
  async enable(userId: string, code: string, ip: string | null): Promise<string[]> {
    const row = await this.row(userId);
    if (!row) throw badRequest('Start the two-factor setup first');
    if (row.enabled_at !== null) throw conflict('Two-factor authentication is already enabled');
    if ((await this.claimTotp(userId, row, code)) === null) {
      await this.audit.record({ action: 'mfa.enable', outcome: 'failure', actorId: userId, ip });
      throw badRequest('Invalid code: check the time on your phone and try the next code');
    }
    const { codes, hashes } = generateRecoveryCodes();
    await this.db.transaction(async (tx) => {
      await tx.run('UPDATE user_mfa SET enabled_at = ? WHERE user_id = ?', this.now(), userId);
      await tx.run('DELETE FROM mfa_recovery_codes WHERE user_id = ?', userId);
      for (const h of hashes) await tx.run('INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES (?, ?)', userId, h);
    });
    await this.audit.record({ action: 'mfa.enable', outcome: 'success', actorId: userId, ip });
    return codes;
  }

  /** Checks a TOTP code or a recovery code, and consumes it. Recovery codes also stand in for passkeys. */
  async verify(userId: string, code: string, ip: string | null): Promise<SecondFactor | null> {
    const row = await this.row(userId);
    const trimmed = code.trim();
    if (/^\d{6}$/.test(trimmed)) return row && row.enabled_at !== null && (await this.claimTotp(userId, row, trimmed)) !== null ? 'totp' : null;
    if (!isRecoveryCodeFormat(trimmed) || !await this.hasAnyFactor(userId)) return null;

    const used = await this.db.run('UPDATE mfa_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL', this.now(), userId, hashRecoveryCode(trimmed));
    if (used.changes !== 1) return null;
    const { left } = await this.db.one('SELECT COUNT(*) AS left FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL', userId) as { left: number };
    await this.audit.record({ action: 'mfa.recovery_code_used', outcome: 'success', actorId: userId, ip, details: { left } });
    return 'recovery';
  }

  /** Removes TOTP. Recovery codes stay while a passkey remains (ADR 0016). */
  async disable(userId: string, ip: string | null): Promise<void> {
    await this.db.run('DELETE FROM user_mfa WHERE user_id = ?', userId);
    await this.dropIfNoFactor(userId);
    await this.audit.record({ action: 'mfa.disable', outcome: 'success', actorId: userId, ip });
  }

  /** Operator key rotation: re-wrap every seed under the active KEK (inside Vault when it is Vault). */
  async rotateKeys(): Promise<number> {
    const rows = await this.db.many('SELECT user_id, key_id, secret FROM user_mfa WHERE key_id != ?', await this.kms.activeKeyId()) as {
      user_id: string;
      key_id: string;
      secret: Uint8Array;
    }[];
    let resealed = 0;
    for (const r of rows) {
      const { keyId, wrapped } = await rewrapSecret(this.kms, r.key_id, Buffer.from(r.secret), aad(r.user_id));
      // Compare-and-set: a seed replaced by a new setup during the rotation is left alone.
      const updated = await this.db.run('UPDATE user_mfa SET key_id = ?, secret = ? WHERE user_id = ? AND secret = ?', keyId, wrapped, r.user_id, r.secret);
      resealed += updated.changes;
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
      const claimed = await this.db.run('UPDATE user_mfa SET last_step = ? WHERE user_id = ? AND last_step < ? AND secret = ?', step, userId, step, row.secret);
      return claimed.changes === 1 ? step : null;
    } finally {
      secret.fill(0);
    }
  }
}
