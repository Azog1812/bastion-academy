import { randomBytes } from 'node:crypto';
import type { AuditLog } from '../audit.js';
import { hashPassword } from '../crypto/password.js';
import { transaction, type Database } from '../db.js';

/**
 * Last-resort account recovery (ADR 0017), for a learner who lost the password *and*
 * every second factor. Operator CLI only, never HTTP (invariant 9): over HTTP it would be
 * the weakest door of every account, the one an attacker always picks. On the host it
 * needs shell access, a stronger boundary than any factor the account had.
 *
 * Everything that proved the old identity goes: password, TOTP seed, recovery codes,
 * passkeys, pending challenges, sessions. A random password is printed once; the learner
 * logs in with it, changes it and enrols factors again. Nothing is kept "just in case":
 * a recovery that left an old passkey behind would leave the attacker's one too.
 */
export async function recoverAccount(db: Database, audit: AuditLog, email: string, scryptLogN: number): Promise<{ temporaryPassword: string }> {
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: string } | undefined;
  if (!user) throw new Error('no such user');
  // ~120 bits: the learner replaces it at first login.
  const temporaryPassword = randomBytes(15).toString('base64url');
  const hash = await hashPassword(temporaryPassword, scryptLogN);
  const counts = transaction(db, () => {
    const removed = (sql: string) => Number(db.prepare(sql).run(user.id).changes);
    const out = {
      passkeys: removed('DELETE FROM passkeys WHERE user_id = ?'),
      totp: removed('DELETE FROM user_mfa WHERE user_id = ?'),
      recoveryCodes: removed('DELETE FROM mfa_recovery_codes WHERE user_id = ?'),
    };
    removed('DELETE FROM webauthn_challenges WHERE user_id = ?');
    removed('DELETE FROM mfa_challenges WHERE user_id = ?');
    db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').run(Date.now(), user.id);
    db.prepare('UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = 0, token_version = token_version + 1 WHERE id = ?').run(hash, user.id);
    return out;
  });
  audit.record({ action: 'admin.account_recovery', outcome: 'success', target: user.id, details: { via: 'cli', ...counts } });
  return { temporaryPassword };
}
