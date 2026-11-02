import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { AuditLog } from '../audit.js';
import {
  CloneWarning,
  COSE_ALGS,
  UserVerificationRequired,
  verifyAssertion,
  verifyRegistration,
  WebAuthnError,
  type CoseAlg,
  type RelyingParty,
} from '../crypto/webauthn.js';
import type { Database } from '../db.js';
import { badRequest, conflict, notFound, unauthorized, unavailable } from '../errors.js';

/** What the page passes back from navigator.credentials.create() / .get(), base64url-encoded. */
export interface RegistrationResponse {
  id: string;
  response: { clientDataJSON: string; attestationObject: string };
}
export interface AssertionResponse {
  id: string;
  response: { clientDataJSON: string; authenticatorData: string; signature: string };
}
/** Passwordless login: the authenticator also says whose credential it is (the user handle). */
export interface DiscoverableAssertionResponse {
  id: string;
  response: AssertionResponse['response'] & { userHandle: string };
}

/** Why a passwordless login failed: audited, never shown (the client gets one message). */
export type PasswordlessFailure = 'challenge' | 'user_handle' | 'unknown_credential' | 'user_verification' | 'assertion' | 'clone' | 'race';

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const MAX_PASSKEYS = 10;
/** Removing the last second factor is disabling MFA: password AND a code, as for TOTP. */
export const LAST_FACTOR = 'This is your last second factor: enter a recovery code to remove it';
/**
 * Passwordless challenges are handed out before anyone is identified, so the per-address
 * rate limit is the only per-client brake. This global cap bounds what a botnet spread
 * over many addresses can make the database hold (5 minutes of challenges).
 */
const MAX_PENDING_LOGIN_CHALLENGES = 10_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const sha256 = (data: Uint8Array | string) => createHash('sha256').update(data).digest('hex');
const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const fromB64u = (s: string) => Buffer.from(s, 'base64url');

/** The challenge a response claims to answer, read before anything is trusted (it is checked again by verify*). */
function claimedChallenge(clientDataJSON: Buffer): Buffer {
  try {
    const c = (JSON.parse(clientDataJSON.toString('utf8')) as { challenge?: unknown }).challenge;
    if (typeof c === 'string' && c.length <= 128) return fromB64u(c);
  } catch {
    // fall through
  }
  throw badRequest('Malformed passkey response');
}

interface PasskeyRow {
  id: string;
  public_key: Uint8Array;
  alg: number;
  sign_count: number;
}

/**
 * Passkeys as a second factor (WebAuthn, ADR 0016).
 *
 * - Challenges are random, single use (deleted when presented, whatever the outcome),
 *   short-lived, stored as SHA-256, and bound to their user, their purpose and, for a
 *   login, to the MFA step that asked for them.
 * - Every query is scoped by user_id (Semgrep rule): a credential id of another account,
 *   or a passkey id in a URL, answers like a missing one.
 * - The signature counter is updated with compare-and-set: two concurrent assertions
 *   with the same counter cannot both pass.
 */
export class PasskeyService {
  constructor(
    private readonly db: Database,
    private readonly audit: AuditLog,
    private readonly rp: RelyingParty & { name: string },
    private readonly now: () => number = Date.now,
  ) {}

  async count(userId: string, db: Database = this.db): Promise<number> {
    return ((await db.one('SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?', userId)) as { n: number }).n;
  }

  async list(userId: string) {
    const rows = await this.db.many('SELECT id, name, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY created_at', userId) as { id: string; name: string; created_at: number; last_used_at: number | null }[];
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      createdAt: new Date(r.created_at).toISOString(),
      lastUsedAt: r.last_used_at === null ? null : new Date(r.last_used_at).toISOString(),
    }));
  }

  private async newChallenge(userId: string, purpose: 'register' | 'login', mfaTokenHash: string | null): Promise<string> {
    const challenge = randomBytes(32);
    await this.db.run('DELETE FROM webauthn_challenges WHERE user_id = ? AND expires_at <= ?', userId, this.now());
    await this.db.run('INSERT INTO webauthn_challenges (challenge_hash, user_id, purpose, mfa_token_hash, expires_at) VALUES (?, ?, ?, ?, ?)', sha256(challenge), userId, purpose, mfaTokenHash, this.now() + CHALLENGE_TTL_MS);
    return b64u(challenge);
  }

  /** Consumes a challenge: found or not, valid or not, it can never be presented again. */
  private async takeChallenge(userId: string, challenge: Buffer, purpose: 'register' | 'login', mfaTokenHash: string | null): Promise<boolean> {
    // The MFA-step binding is compared by SQLite (IS: equal, or both NULL), never in JS with ===.
    const row = await this.db.one('DELETE FROM webauthn_challenges WHERE challenge_hash = ? AND user_id = ? RETURNING purpose, (mfa_token_hash IS ?) AS same_step, expires_at', sha256(challenge), userId, mfaTokenHash) as { purpose: string; same_step: number; expires_at: number } | undefined;
    return row !== undefined && row.purpose === purpose && row.same_step === 1 && row.expires_at > this.now();
  }

  private async credentialIds(userId: string): Promise<string[]> {
    const rows = await this.db.many('SELECT credential_id FROM passkeys WHERE user_id = ?', userId) as { credential_id: Uint8Array }[];
    return rows.map((r) => b64u(r.credential_id));
  }

  /** Options for navigator.credentials.create(). The caller has re-checked the password. */
  async registrationOptions(userId: string, account: string) {
    if (await this.count(userId) >= MAX_PASSKEYS) throw conflict(`At most ${String(MAX_PASSKEYS)} passkeys per account`);
    return {
      challenge: await this.newChallenge(userId, 'register', null),
      rp: { id: this.rp.id, name: this.rp.name },
      // The user handle is the account id: no e-mail stored on the authenticator.
      user: { id: b64u(Buffer.from(userId)), name: account, displayName: account },
      pubKeyCredParams: COSE_ALGS.map((alg) => ({ type: 'public-key', alg })),
      timeout: CHALLENGE_TTL_MS,
      attestation: 'none',
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      excludeCredentials: (await this.credentialIds(userId)).map((id) => ({ type: 'public-key', id })),
    };
  }

  async register(userId: string, name: string, cred: RegistrationResponse, ip: string | null) {
    const clientDataJSON = fromB64u(cred.response.clientDataJSON);
    if (!await this.takeChallenge(userId, claimedChallenge(clientDataJSON), 'register', null)) {
      await this.audit.record({ action: 'passkey.register', outcome: 'failure', actorId: userId, ip, details: { reason: 'challenge' } });
      throw badRequest('This passkey request has expired: start again');
    }
    let reg;
    try {
      reg = verifyRegistration(this.rp, claimedChallenge(clientDataJSON), clientDataJSON, fromB64u(cred.response.attestationObject));
    } catch (err) {
      if (!(err instanceof WebAuthnError)) throw err;
      await this.audit.record({ action: 'passkey.register', outcome: 'failure', actorId: userId, ip, details: { reason: err.message.slice(0, 80) } });
      throw badRequest(`Passkey refused: ${err.message}`);
    }
    const id = randomUUID();
    // Cap and insert in one transaction, or concurrent enrolments could all pass the count.
    const outcome = await this.db.transaction(async (tx) => {
      if ((await this.count(userId, tx)) >= MAX_PASSKEYS) return 'full';
      const inserted = await tx.run(
        `INSERT INTO passkeys (id, user_id, credential_id, public_key, alg, sign_count, name, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (credential_id) DO NOTHING`,
        id,
        userId,
        reg.credentialId,
        reg.publicKey,
        reg.alg,
        reg.signCount,
        name,
        this.now(),
      );
      return inserted.changes === 1 ? 'added' : 'duplicate';
    });
    if (outcome === 'full') throw conflict(`At most ${String(MAX_PASSKEYS)} passkeys per account`);
    // The same authenticator key, already enrolled (here or on another account).
    if (outcome === 'duplicate') throw conflict('This passkey is already registered');
    await this.audit.record({ action: 'passkey.register', outcome: 'success', actorId: userId, target: id, ip, details: { alg: reg.alg } });
    return { id, name };
  }

  /** Options for navigator.credentials.get() during the MFA step identified by its token hash. */
  async loginOptions(userId: string, mfaTokenHash: string) {
    const allow = await this.credentialIds(userId);
    if (allow.length === 0) throw badRequest('No passkey on this account: use your authenticator code');
    return {
      challenge: await this.newChallenge(userId, 'login', mfaTokenHash),
      rpId: this.rp.id,
      timeout: CHALLENGE_TTL_MS,
      userVerification: 'preferred',
      allowCredentials: allow.map((id) => ({ type: 'public-key', id })),
    };
  }

  /** Verifies an assertion for this MFA step. True only for a fresh, valid signature by one of the user's keys. */
  async verifyLogin(userId: string, mfaTokenHash: string, cred: AssertionResponse, ip: string | null): Promise<boolean> {
    const clientDataJSON = fromB64u(cred.response.clientDataJSON);
    const challenge = claimedChallenge(clientDataJSON);
    if (!await this.takeChallenge(userId, challenge, 'login', mfaTokenHash)) return false;
    const row = await this.db.one('SELECT id, public_key, alg, sign_count FROM passkeys WHERE user_id = ? AND credential_id = ?', userId, fromB64u(cred.id)) as PasskeyRow | undefined;
    if (!row || !(COSE_ALGS as readonly number[]).includes(row.alg)) return false;
    try {
      const { signCount } = verifyAssertion(
        this.rp,
        challenge,
        { publicKey: row.public_key, alg: row.alg as CoseAlg, signCount: row.sign_count },
        clientDataJSON,
        fromB64u(cred.response.authenticatorData),
        fromB64u(cred.response.signature),
      );
      // Compare-and-set on the counter read above (invariant 5).
      const updated = await this.db.run('UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ? AND user_id = ? AND sign_count = ?', signCount, this.now(), row.id, userId, row.sign_count);
      return updated.changes === 1;
    } catch (err) {
      if (err instanceof CloneWarning) {
        await this.audit.record({ action: 'passkey.clone_detected', outcome: 'denied', actorId: userId, target: row.id, ip, details: { stored: row.sign_count } });
        return false;
      }
      if (err instanceof WebAuthnError) return false;
      throw err;
    }
  }

  /**
   * Options for a passwordless login (ADR 0017): no account is named, so allowCredentials
   * is empty and the authenticator offers the discoverable passkeys it holds for this RP
   * ID. Nothing here depends on an e-mail address: there is nothing to enumerate.
   */
  async passwordlessOptions() {
    const now = this.now();
    const challenge = randomBytes(32);
    // Purge, count and insert as one step: the cap must hold under a burst of concurrent requests.
    const issued = await this.db.transaction(async (tx) => {
      await tx.run('DELETE FROM webauthn_login_challenges WHERE expires_at <= ?', now);
      const { n } = (await tx.one('SELECT COUNT(*) AS n FROM webauthn_login_challenges')) as { n: number };
      if (n >= MAX_PENDING_LOGIN_CHALLENGES) return false;
      await tx.run('INSERT INTO webauthn_login_challenges (challenge_hash, expires_at) VALUES (?, ?)', sha256(challenge), now + CHALLENGE_TTL_MS);
      return true;
    });
    if (!issued) throw unavailable('Too many passkey sign-ins in progress, try again in a minute');
    return { challenge: b64u(challenge), rpId: this.rp.id, timeout: CHALLENGE_TTL_MS, userVerification: 'required', allowCredentials: [] };
  }

  /**
   * Verifies a passwordless assertion. The user handle names the account (W3C §7.2: the
   * credential must belong to it), and the lookup is scoped by that user id, so a valid
   * key of account A presented with B's handle finds nothing. User verification is
   * required: the passkey is the only factor here.
   */
  async verifyPasswordless(cred: DiscoverableAssertionResponse): Promise<{ userId: string } | { reason: PasswordlessFailure; userId?: string; passkeyId?: string }> {
    const clientDataJSON = fromB64u(cred.response.clientDataJSON);
    const challenge = claimedChallenge(clientDataJSON);
    // Consumed whatever happens next: a challenge never answers twice.
    const taken = await this.db.one('DELETE FROM webauthn_login_challenges WHERE challenge_hash = ? RETURNING expires_at', sha256(challenge)) as { expires_at: number } | undefined;
    if (!taken || taken.expires_at <= this.now()) return { reason: 'challenge' };

    const userId = fromB64u(cred.response.userHandle).toString('utf8');
    if (!UUID.test(userId)) return { reason: 'user_handle' };
    const row = await this.db.one('SELECT id, public_key, alg, sign_count FROM passkeys WHERE user_id = ? AND credential_id = ?', userId, fromB64u(cred.id)) as PasskeyRow | undefined;
    if (!row || !(COSE_ALGS as readonly number[]).includes(row.alg)) return { reason: 'unknown_credential' };
    try {
      const { signCount } = verifyAssertion(
        this.rp,
        challenge,
        { publicKey: row.public_key, alg: row.alg as CoseAlg, signCount: row.sign_count },
        clientDataJSON,
        fromB64u(cred.response.authenticatorData),
        fromB64u(cred.response.signature),
        true,
      );
      const updated = await this.db.run('UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ? AND user_id = ? AND sign_count = ?', signCount, this.now(), row.id, userId, row.sign_count);
      return updated.changes === 1 ? { userId } : { reason: 'race', userId, passkeyId: row.id };
    } catch (err) {
      if (err instanceof CloneWarning) return { reason: 'clone', userId, passkeyId: row.id };
      if (err instanceof UserVerificationRequired) return { reason: 'user_verification', userId, passkeyId: row.id };
      if (err instanceof WebAuthnError) return { reason: 'assertion', userId, passkeyId: row.id };
      throw err;
    }
  }

  /**
   * Deletes a passkey. Unless `lastAllowed` (the caller checked password *and* a code),
   * the account's last second factor is refused. The check and the delete are one
   * transaction: two concurrent deletions of an account's two passkeys must not both see
   * "another factor remains" and leave it with none, no code ever asked.
   */
  async remove(userId: string, passkeyId: string, ip: string | null, lastAllowed: boolean): Promise<void> {
    const outcome = await this.db.transaction(async (tx) => {
      const totp = await tx.one('SELECT 1 FROM user_mfa WHERE user_id = ? AND enabled_at IS NOT NULL', userId);
      const { n } = (await tx.one('SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?', userId)) as { n: number };
      if (!lastAllowed && totp === undefined && n <= 1) return 'last';
      const deleted = await tx.run('DELETE FROM passkeys WHERE id = ? AND user_id = ?', passkeyId, userId);
      return deleted.changes === 1 ? 'deleted' : 'missing';
    });
    if (outcome === 'missing') throw notFound('Passkey not found');
    if (outcome === 'last') {
      await this.audit.record({ action: 'passkey.delete', outcome: 'failure', actorId: userId, target: passkeyId, ip, details: { reason: 'last_factor' } });
      throw unauthorized(LAST_FACTOR);
    }
    await this.audit.record({ action: 'passkey.delete', outcome: 'success', actorId: userId, target: passkeyId, ip });
  }

  async isOwn(userId: string, passkeyId: string): Promise<boolean> {
    return await this.db.one('SELECT 1 FROM passkeys WHERE id = ? AND user_id = ?', passkeyId, userId) !== undefined;
  }
}
