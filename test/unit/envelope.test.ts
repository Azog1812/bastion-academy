import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { DecryptionError, open, rewrap, seal, type KeyRing } from '../../src/crypto/envelope.js';

const ring = (active = 'k1', extra: Record<string, Buffer> = {}): KeyRing => ({
  keys: new Map([['k1', randomBytes(32)], ...Object.entries(extra)]),
  activeKeyId: active,
});

describe('envelope encryption (AES-256-GCM + per-record DEK)', () => {
  const r = ring();

  it('round-trips UTF-8 content', () => {
    const s = seal(r, 'héllo 🔐 wörld', 'note-1', 'alice');
    expect(open(r, s, 'note-1', 'alice')).toBe('héllo 🔐 wörld');
  });

  it('never stores plaintext and uses a fresh IV and DEK every time', () => {
    const a = seal(r, 'same content', 'n', 'o');
    const b = seal(r, 'same content', 'n', 'o');
    expect(a.ciphertext.toString('utf8')).not.toContain('same content');
    expect(a.iv.equals(b.iv)).toBe(false);
    expect(a.wrappedDek.equals(b.wrappedDek)).toBe(false);
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false);
  });

  it.each([
    ['ciphertext', (s: ReturnType<typeof seal>) => (s.ciphertext[0]! ^= 0x01)],
    ['auth tag', (s: ReturnType<typeof seal>) => (s.tag[0]! ^= 0x01)],
    ['iv', (s: ReturnType<typeof seal>) => (s.iv[0]! ^= 0x01)],
    ['wrapped DEK', (s: ReturnType<typeof seal>) => (s.wrappedDek[40]! ^= 0x01)],
  ])('detects a single flipped bit in the %s', (_name, tamper) => {
    const s = seal(r, 'integrity matters', 'n', 'o');
    tamper(s);
    expect(() => open(r, s, 'n', 'o')).toThrow(DecryptionError);
  });

  it('binds ciphertext to its owner: moving it to another user fails (AAD)', () => {
    const s = seal(r, "alice's diary", 'note-1', 'alice');
    expect(() => open(r, s, 'note-1', 'mallory')).toThrow(DecryptionError);
  });

  it('binds ciphertext to its record: swapping rows fails (AAD)', () => {
    const s = seal(r, 'content', 'note-1', 'alice');
    expect(() => open(r, s, 'note-2', 'alice')).toThrow(DecryptionError);
  });

  it('fails closed on an unknown key id', () => {
    const s = seal(r, 'x', 'n', 'o');
    expect(() => open(r, { ...s, keyId: 'ghost' }, 'n', 'o')).toThrow(DecryptionError);
  });

  it('fails with the same generic error for a truncated wrapped key', () => {
    const s = seal(r, 'x', 'n', 'o');
    expect(() => open(r, { ...s, wrappedDek: s.wrappedDek.subarray(0, 10) }, 'n', 'o')).toThrow(DecryptionError);
  });

  it('rotates the KEK by re-wrapping the DEK only, content untouched', () => {
    const old = ring('k1');
    const s = seal(old, 'long-lived secret', 'n', 'o');
    const rotated: KeyRing = { keys: new Map([...old.keys, ['k2', randomBytes(32)]]), activeKeyId: 'k2' };

    const { keyId, wrappedDek } = rewrap(rotated, s.keyId, s.wrappedDek, 'n');
    expect(keyId).toBe('k2');

    // k1 can now be retired: decryption only needs k2.
    const k2only: KeyRing = { keys: new Map([['k2', rotated.keys.get('k2')!]]), activeKeyId: 'k2' };
    expect(open(k2only, { ...s, keyId, wrappedDek }, 'n', 'o')).toBe('long-lived secret');
  });
});
