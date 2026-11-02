import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { DecryptionError, type Kms } from './kms.js';

export { DecryptionError, KmsUnavailable, type KeyRing, type Kms } from './kms.js';

/**
 * Envelope encryption (the model used by AWS KMS, GCP KMS, Vault Transit):
 *
 *   - every note gets its own random 256-bit Data Encryption Key (DEK);
 *   - the note is encrypted with the DEK using AES-256-GCM (authenticated);
 *   - the DEK is itself encrypted ("wrapped") with a Key Encryption Key (KEK),
 *     held by a KMS (kms.ts): the local key ring, or Vault Transit (ADR 0019).
 *
 * Why it matters:
 *   - a database dump alone reveals nothing (KEKs never touch the DB);
 *   - KEK rotation only re-wraps 32-byte DEKs, never re-encrypts content;
 *   - the Additional Authenticated Data (AAD) binds each ciphertext to its
 *     note id and owner id: copying user A's ciphertext into user B's row,
 *     or swapping two rows, makes decryption fail instead of leaking data.
 *     The DEK is bound to its note the same way, by the wrap context.
 */

const ALGO = 'aes-256-gcm';
const IV_LEN = 12; // 96-bit nonce, NIST SP 800-38D recommendation for GCM
const TAG_LEN = 16;
const DEK_LEN = 32;

export interface Sealed {
  keyId: string;
  wrappedDek: Buffer;
  iv: Buffer;
  tag: Buffer;
  ciphertext: Buffer;
}

export interface SealedNote extends Sealed {
  noteId: string;
  ownerId: string;
}

const contentAad = (noteId: string, ownerId: string) => Buffer.from(`bastion:note-content:v1:${noteId}:${ownerId}`);
const dekContext = (noteId: string) => `bastion:note-dek:v1:${noteId}`;

function gcmEncrypt(key: Buffer, plaintext: Buffer, aad: Buffer) {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, key, iv, { authTagLength: TAG_LEN });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, tag: cipher.getAuthTag(), ciphertext };
}

function gcmDecrypt(key: Buffer, iv: Buffer, tag: Buffer, ciphertext: Buffer, aad: Buffer): Buffer {
  try {
    const decipher = createDecipheriv(ALGO, key, iv, { authTagLength: TAG_LEN });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    // Same error whatever went wrong: no padding/format oracle.
    throw new DecryptionError();
  }
}

export async function seal(kms: Kms, plaintext: string, noteId: string, ownerId: string): Promise<Sealed> {
  const dek = randomBytes(DEK_LEN);
  try {
    const { iv, tag, ciphertext } = gcmEncrypt(dek, Buffer.from(plaintext, 'utf8'), contentAad(noteId, ownerId));
    const { keyId, wrapped } = await kms.wrap(dek, dekContext(noteId));
    return { keyId, wrappedDek: wrapped, iv, tag, ciphertext };
  } finally {
    dek.fill(0); // best-effort: shorten the DEK's lifetime in memory
  }
}

/** Opens a page of notes with one KMS round trip (Vault batch), all or nothing. */
export async function openMany(kms: Kms, notes: readonly SealedNote[]): Promise<string[]> {
  const deks = await kms.unwrap(notes.map((n) => ({ keyId: n.keyId, wrapped: n.wrappedDek, context: dekContext(n.noteId) })));
  try {
    return notes.map((n, i) => {
      const dek = deks[i];
      if (dek?.length !== DEK_LEN) throw new DecryptionError();
      return gcmDecrypt(dek, n.iv, n.tag, n.ciphertext, contentAad(n.noteId, n.ownerId)).toString('utf8');
    });
  } finally {
    for (const d of deks) d.fill(0);
  }
}

export async function open(kms: Kms, sealed: Sealed, noteId: string, ownerId: string): Promise<string> {
  const [plaintext] = await openMany(kms, [{ ...sealed, noteId, ownerId }]);
  if (plaintext === undefined) throw new DecryptionError();
  return plaintext;
}

/** Key rotation: re-wrap a DEK under the active KEK without touching the content. */
export function rewrap(kms: Kms, keyId: string, wrappedDek: Buffer, noteId: string) {
  return kms.rewrap({ keyId, wrapped: wrappedDek, context: dekContext(noteId) });
}

/**
 * Small account secrets (TOTP seeds) are wrapped directly by the KMS: no per-item DEK is
 * needed for 20 bytes, but the same rules hold. The context names the purpose and the
 * owner, so a sealed blob copied to another user's row, or reused for another purpose,
 * fails to open.
 */
export async function sealSecret(kms: Kms, secret: Buffer, aad: string): Promise<{ keyId: string; blob: Buffer }> {
  const { keyId, wrapped } = await kms.wrap(secret, aad);
  return { keyId, blob: wrapped };
}

export async function openSecret(kms: Kms, keyId: string, blob: Buffer, aad: string): Promise<Buffer> {
  const [secret] = await kms.unwrap([{ keyId, wrapped: blob, context: aad }]);
  if (!secret) throw new DecryptionError();
  return secret;
}

export function rewrapSecret(kms: Kms, keyId: string, blob: Buffer, aad: string) {
  return kms.rewrap({ keyId, wrapped: blob, context: aad });
}
