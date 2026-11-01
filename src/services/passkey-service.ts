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
import { badRequest, conflict, notFound, unavailable } from '../errors.js';

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

  count(userId: string): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?').get(userId) as { n: number }).n;
  }

  list(userId: string) {
    const rows = this.db
      .prepare('SELECT id, name, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY created_at')
      .all(userId) as { id: string; name: string; created_at: number; last_used_at: number | null }[];
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      createdAt: new Date(r.created_at).toISOString(),
      lastUsedAt: r.last_used_at === null ? null : new Date(r.last_used_at).toISOString(),
    }));
  }

  private newChallenge(userId: string, purpose: 'register' | 'login', mfaTokenHash: string | null): string {
    const challenge = randomBytes(32);
    this.db.prepare('DELETE FROM webauthn_challenges WHERE user_id = ? AND expires_at <= ?').run(userId, this.now());
    this.db
      .prepare('INSERT INTO webauthn_challenges (challenge_hash, user_id, purpose, mfa_token_hash, expires_at) VALUES (?, ?, ?, ?, ?)')
      .run(sha256(challenge), userId, purpose, mfaTokenHash, this.now() + CHALLENGE_TTL_MS);
    return b64u(challenge);
  }

  /** Consumes a challenge: found or not, valid or not, it can never be presented again. */
  private takeChallenge(userId: string, challenge: Buffer, purpose: 'register' | 'login', mfaTokenHash: string | null): boolean {
    // The MFA-step binding is compared by SQLite (IS: equal, or both NULL), never in JS with ===.
    const row = this.db
      .prepare('DELETE FROM webauthn_challenges WHERE challenge_hash = ? AND user_id = ? RETURNING purpose, (mfa_token_hash IS ?) AS same_step, expires_at')
      .get(sha256(challenge), userId, mfaTokenHash) as { purpose: string; same_step: number; expires_at: number } | undefined;
    return row !== undefined && row.purpose === purpose && row.same_step === 1 && row.expires_at > this.now();
  }

  private credentialIds(userId: string): string[] {
    const rows = this.db.prepare('SELECT credential_id FROM passkeys WHERE user_id = ?').all(userId) as { credential_id: Uint8Array }[];
    return rows.map((r) => b64u(r.credential_id));
  }

  /** Options for navigator.credentials.create(). The caller has re-checked the password. */
  registrationOptions(userId: string, account: string) {
    if (this.count(userId) >= MAX_PASSKEYS) throw conflict(`At most ${String(MAX_PASSKEYS)} passkeys per account`);
    return {
      challenge: this.newChallenge(userId, 'register', null),
      rp: { id: this.rp.id, name: this.rp.name },
      // The user handle is the account id: no e-mail stored on the authenticator.
      user: { id: b64u(Buffer.from(userId)), name: account, displayName: account },
      pubKeyCredParams: COSE_ALGS.map((alg) => ({ type: 'public-key', alg })),
      timeout: CHALLENGE_TTL_MS,
      attestation: 'none',
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      excludeCredentials: this.credentialIds(userId).map((id) => ({ type: 'public-key', id })),
    };
  }

  register(userId: string, name: string, cred: RegistrationResponse, ip: string | null) {
    const clientDataJSON = fromB64u(cred.response.clientDataJSON);
    if (!this.takeChallenge(userId, claimedChallenge(clientDataJSON), 'register', null)) {
      this.audit.record({ action: 'passkey.register', outcome: 'failure', actorId: userId, ip, details: { reason: 'challenge' } });
      throw badRequest('This passkey request has expired: start again');
    }
    let reg;
    try {
      reg = verifyRegistration(this.rp, claimedChallenge(clientDataJSON), clientDataJSON, fromB64u(cred.response.attestationObject));
    } catch (err) {
      if (!(err instanceof WebAuthnError)) throw err;
      this.audit.record({ action: 'passkey.register', outcome: 'failure', actorId: userId, ip, details: { reason: err.message.slice(0, 80) } });
      throw badRequest(`Passkey refused: ${err.message}`);
    }
    if (this.count(userId) >= MAX_PASSKEYS) throw conflict(`At most ${String(MAX_PASSKEYS)} passkeys per account`);
    const id = randomUUID();
    const inserted = this.db
      .prepare(
        `INSERT INTO passkeys (id, user_id, credential_id, public_key, alg, sign_count, name, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (credential_id) DO NOTHING`,
      )
      .run(id, userId, reg.credentialId, reg.publicKey, reg.alg, reg.signCount, name, this.now());
    // The same authenticator key, already enrolled (here or on another account).
    if (Number(inserted.changes) !== 1) throw conflict('This passkey is already registered');
    this.audit.record({ action: 'passkey.register', outcome: 'success', actorId: userId, target: id, ip, details: { alg: reg.alg } });
    return { id, name };
  }

  /** Options for navigator.credentials.get() during the MFA step identified by its token hash. */
  loginOptions(userId: string, mfaTokenHash: string) {
    const allow = this.credentialIds(userId);
    if (allow.length === 0) throw badRequest('No passkey on this account: use your authenticator code');
    return {
      challenge: this.newChallenge(userId, 'login', mfaTokenHash),
      rpId: this.rp.id,
      timeout: CHALLENGE_TTL_MS,
      userVerification: 'preferred',
      allowCredentials: allow.map((id) => ({ type: 'public-key', id })),
    };
  }

  /** Verifies an assertion for this MFA step. True only for a fresh, valid signature by one of the user's keys. */
  verifyLogin(userId: string, mfaTokenHash: string, cred: AssertionResponse, ip: string | null): boolean {
    const clientDataJSON = fromB64u(cred.response.clientDataJSON);
    const challenge = claimedChallenge(clientDataJSON);
    if (!this.takeChallenge(userId, challenge, 'login', mfaTokenHash)) return false;
    const row = this.db
      .prepare('SELECT id, public_key, alg, sign_count FROM passkeys WHERE user_id = ? AND credential_id = ?')
      .get(userId, fromB64u(cred.id)) as PasskeyRow | undefined;
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
      const updated = this.db
        .prepare('UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ? AND user_id = ? AND sign_count = ?')
        .run(signCount, this.now(), row.id, userId, row.sign_count);
      return Number(updated.changes) === 1;
    } catch (err) {
      if (err instanceof CloneWarning) {
        this.audit.record({ action: 'passkey.clone_detected', outcome: 'denied', actorId: userId, target: row.id, ip, details: { stored: row.sign_count } });
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
  passwordlessOptions() {
    const now = this.now();
    this.db.prepare('DELETE FROM webauthn_login_challenges WHERE expires_at <= ?').run(now);
    const { n } = this.db.prepare('SELECT COUNT(*) AS n FROM webauthn_login_challenges').get() as { n: number };
    if (n >= MAX_PENDING_LOGIN_CHALLENGES) throw unavailable('Too many passkey sign-ins in progress, try again in a minute');
    const challenge = randomBytes(32);
    this.db.prepare('INSERT INTO webauthn_login_challenges (challenge_hash, expires_at) VALUES (?, ?)').run(sha256(challenge), now + CHALLENGE_TTL_MS);
    return { challenge: b64u(challenge), rpId: this.rp.id, timeout: CHALLENGE_TTL_MS, userVerification: 'required', allowCredentials: [] };
  }

  /**
   * Verifies a passwordless assertion. The user handle names the account (W3C §7.2: the
   * credential must belong to it), and the lookup is scoped by that user id, so a valid
   * key of account A presented with B's handle finds nothing. User verification is
   * required: the passkey is the only factor here.
   */
  verifyPasswordless(cred: DiscoverableAssertionResponse): { userId: string } | { reason: PasswordlessFailure; userId?: string; passkeyId?: string } {
    const clientDataJSON = fromB64u(cred.response.clientDataJSON);
    const challenge = claimedChallenge(clientDataJSON);
    // Consumed whatever happens next: a challenge never answers twice.
    const taken = this.db
      .prepare('DELETE FROM webauthn_login_challenges WHERE challenge_hash = ? RETURNING expires_at')
      .get(sha256(challenge)) as { expires_at: number } | undefined;
    if (!taken || taken.expires_at <= this.now()) return { reason: 'challenge' };

    const userId = fromB64u(cred.response.userHandle).toString('utf8');
    if (!UUID.test(userId)) return { reason: 'user_handle' };
    const row = this.db
      .prepare('SELECT id, public_key, alg, sign_count FROM passkeys WHERE user_id = ? AND credential_id = ?')
      .get(userId, fromB64u(cred.id)) as PasskeyRow | undefined;
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
      const updated = this.db
        .prepare('UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ? AND user_id = ? AND sign_count = ?')
        .run(signCount, this.now(), row.id, userId, row.sign_count);
      return Number(updated.changes) === 1 ? { userId } : { reason: 'race', userId, passkeyId: row.id };
    } catch (err) {
      if (err instanceof CloneWarning) return { reason: 'clone', userId, passkeyId: row.id };
      if (err instanceof UserVerificationRequired) return { reason: 'user_verification', userId, passkeyId: row.id };
      if (err instanceof WebAuthnError) return { reason: 'assertion', userId, passkeyId: row.id };
      throw err;
    }
  }

  remove(userId: string, passkeyId: string, ip: string | null): void {
    const deleted = this.db.prepare('DELETE FROM passkeys WHERE id = ? AND user_id = ?').run(passkeyId, userId);
    if (Number(deleted.changes) !== 1) throw notFound('Passkey not found');
    this.audit.record({ action: 'passkey.delete', outcome: 'success', actorId: userId, target: passkeyId, ip });
  }

  isOwn(userId: string, passkeyId: string): boolean {
    return this.db.prepare('SELECT 1 FROM passkeys WHERE id = ? AND user_id = ?').get(passkeyId, userId) !== undefined;
  }
}
