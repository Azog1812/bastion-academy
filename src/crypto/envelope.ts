import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

/**
 * Envelope encryption (the model used by AWS KMS, GCP KMS, Vault Transit):
 *
 *   - every note gets its own random 256-bit Data Encryption Key (DEK);
 *   - the note is encrypted with the DEK using AES-256-GCM (authenticated);
 *   - the DEK is itself encrypted ("wrapped") with a Key Encryption Key (KEK)
 *     taken from a versioned key ring.
 *
 * Why it matters:
 *   - a database dump alone reveals nothing (KEKs never touch the DB);
 *   - KEK rotation only re-wraps 32-byte DEKs, never re-encrypts content;
 *   - the Additional Authenticated Data (AAD) binds each ciphertext to its
 *     note id and owner id: copying user A's ciphertext into user B's row,
 *     or swapping two rows, makes decryption fail instead of leaking data.
 */

const ALGO = 'aes-256-gcm';
const IV_LEN = 12; // 96-bit nonce, NIST SP 800-38D recommendation for GCM
const TAG_LEN = 16;

export interface KeyRing {
  readonly keys: ReadonlyMap<string, Buffer>;
  readonly activeKeyId: string;
}

export interface Sealed {
  keyId: string;
  wrappedDek: Buffer; // iv || tag || encrypted DEK
  iv: Buffer;
  tag: Buffer;
  ciphertext: Buffer;
}

export class DecryptionError extends Error {
  constructor() {
    super('Integrity check failed');
    this.name = 'DecryptionError';
  }
}

function contentAad(noteId: string, ownerId: string): Buffer {
  return Buffer.from(`bastion:note-content:v1:${noteId}:${ownerId}`);
}

function dekAad(noteId: string, keyId: string): Buffer {
  return Buffer.from(`bastion:note-dek:v1:${noteId}:${keyId}`);
}

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

function kek(ring: KeyRing, keyId: string): Buffer {
  const key = ring.keys.get(keyId);
  if (!key) throw new DecryptionError();
  return key;
}

function wrapDek(ring: KeyRing, dek: Buffer, noteId: string): { keyId: string; wrappedDek: Buffer } {
  const keyId = ring.activeKeyId;
  const { iv, tag, ciphertext } = gcmEncrypt(kek(ring, keyId), dek, dekAad(noteId, keyId));
  return { keyId, wrappedDek: Buffer.concat([iv, tag, ciphertext]) };
}

function unwrapDek(ring: KeyRing, keyId: string, wrapped: Buffer, noteId: string): Buffer {
  if (wrapped.length !== IV_LEN + TAG_LEN + 32) throw new DecryptionError();
  const iv = wrapped.subarray(0, IV_LEN);
  const tag = wrapped.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const ct = wrapped.subarray(IV_LEN + TAG_LEN);
  return gcmDecrypt(kek(ring, keyId), iv, tag, ct, dekAad(noteId, keyId));
}

export function seal(ring: KeyRing, plaintext: string, noteId: string, ownerId: string): Sealed {
  const dek = randomBytes(32);
  try {
    const { iv, tag, ciphertext } = gcmEncrypt(dek, Buffer.from(plaintext, 'utf8'), contentAad(noteId, ownerId));
    return { ...wrapDek(ring, dek, noteId), iv, tag, ciphertext };
  } finally {
    dek.fill(0); // best-effort: shorten the DEK's lifetime in memory
  }
}

export function open(ring: KeyRing, sealed: Sealed, noteId: string, ownerId: string): string {
  const dek = unwrapDek(ring, sealed.keyId, sealed.wrappedDek, noteId);
  try {
    return gcmDecrypt(dek, sealed.iv, sealed.tag, sealed.ciphertext, contentAad(noteId, ownerId)).toString('utf8');
  } finally {
    dek.fill(0);
  }
}

/** Key rotation: re-wrap a DEK under the active KEK without touching the content. */
export function rewrap(ring: KeyRing, keyId: string, wrappedDek: Buffer, noteId: string) {
  const dek = unwrapDek(ring, keyId, wrappedDek, noteId);
  try {
    return wrapDek(ring, dek, noteId);
  } finally {
    dek.fill(0);
  }
}
