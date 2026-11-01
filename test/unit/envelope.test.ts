import { createCipheriv, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { DecryptionError, open, rewrap, seal, type KeyRing, type Sealed } from '../../src/crypto/envelope.js';
import { LocalKms } from '../../src/crypto/kms.js';

const ring = (active = 'k1', extra: Record<string, Buffer> = {}): KeyRing => ({
  keys: new Map([['k1', randomBytes(32)], ...Object.entries(extra)]),
  activeKeyId: active,
});

describe('envelope encryption (AES-256-GCM + per-record DEK)', () => {
  const r = ring();
  const kms = new LocalKms(r);

  it('round-trips UTF-8 content', async () => {
    const s = await seal(kms, 'héllo 🔐 wörld', 'note-1', 'alice');
    expect(await open(kms, s, 'note-1', 'alice')).toBe('héllo 🔐 wörld');
  });

  it('never stores plaintext and uses a fresh IV and DEK every time', async () => {
    const a = await seal(kms, 'same content', 'n', 'o');
    const b = await seal(kms, 'same content', 'n', 'o');
    expect(a.ciphertext.toString('utf8')).not.toContain('same content');
    expect(a.iv.equals(b.iv)).toBe(false);
    expect(a.wrappedDek.equals(b.wrappedDek)).toBe(false);
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false);
  });

  it.each([
    ['ciphertext', (s: Sealed) => (s.ciphertext[0]! ^= 0x01)],
    ['auth tag', (s: Sealed) => (s.tag[0]! ^= 0x01)],
    ['iv', (s: Sealed) => (s.iv[0]! ^= 0x01)],
    ['wrapped DEK', (s: Sealed) => (s.wrappedDek[40]! ^= 0x01)],
  ])('detects a single flipped bit in the %s', async (_name, tamper) => {
    const s = await seal(kms, 'integrity matters', 'n', 'o');
    tamper(s);
    await expect(open(kms, s, 'n', 'o')).rejects.toThrow(DecryptionError);
  });

  it('binds ciphertext to its owner: moving it to another user fails (AAD)', async () => {
    const s = await seal(kms, "alice's diary", 'note-1', 'alice');
    await expect(open(kms, s, 'note-1', 'mallory')).rejects.toThrow(DecryptionError);
  });

  it('binds ciphertext to its record: swapping rows fails (AAD)', async () => {
    const s = await seal(kms, 'content', 'note-1', 'alice');
    await expect(open(kms, s, 'note-2', 'alice')).rejects.toThrow(DecryptionError);
  });

  it('fails closed on an unknown key id', async () => {
    const s = await seal(kms, 'x', 'n', 'o');
    await expect(open(kms, { ...s, keyId: 'ghost' }, 'n', 'o')).rejects.toThrow(DecryptionError);
  });

  it('fails with the same generic error for a truncated wrapped key', async () => {
    const s = await seal(kms, 'x', 'n', 'o');
    await expect(open(kms, { ...s, wrappedDek: s.wrappedDek.subarray(0, 10) }, 'n', 'o')).rejects.toThrow(DecryptionError);
  });

  it('rotates the KEK by re-wrapping the DEK only, content untouched', async () => {
    const old = ring('k1');
    const s = await seal(new LocalKms(old), 'long-lived secret', 'n', 'o');
    const rotated: KeyRing = { keys: new Map([...old.keys, ['k2', randomBytes(32)]]), activeKeyId: 'k2' };

    const { keyId, wrapped } = await rewrap(new LocalKms(rotated), s.keyId, s.wrappedDek, 'n');
    expect(keyId).toBe('k2');

    // k1 can now be retired: decryption only needs k2.
    const k2only = new LocalKms({ keys: new Map([['k2', rotated.keys.get('k2')!]]), activeKeyId: 'k2' });
    expect(await open(k2only, { ...s, keyId, wrappedDek: wrapped }, 'n', 'o')).toBe('long-lived secret');
  });

  it('still opens rows written before the KMS layer (ADR 0019): same associated data, same layout', async () => {
    // A DEK wrapped exactly as envelope.ts did until v2: AAD "bastion:note-dek:v1:<note>:<keyId>", iv || tag || ct.
    const kek = r.keys.get('k1')!;
    const dek = randomBytes(32);
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', kek, iv, { authTagLength: 16 });
    c.setAAD(Buffer.from('bastion:note-dek:v1:old-note:k1'));
    const wrappedDek = Buffer.concat([iv, Buffer.alloc(16), c.update(dek), c.final()]);
    c.getAuthTag().copy(wrappedDek, 12);
    const civ = randomBytes(12);
    const cc = createCipheriv('aes-256-gcm', dek, civ, { authTagLength: 16 });
    cc.setAAD(Buffer.from('bastion:note-content:v1:old-note:alice'));
    const ciphertext = Buffer.concat([cc.update('written by v2'), cc.final()]);
    const legacy: Sealed = { keyId: 'k1', wrappedDek, iv: civ, tag: cc.getAuthTag(), ciphertext };
    expect(await open(kms, legacy, 'old-note', 'alice')).toBe('written by v2');
  });
});
