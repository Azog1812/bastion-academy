import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import {
  base32Decode,
  base32Encode,
  generateRecoveryCodes,
  hashRecoveryCode,
  hotp,
  isRecoveryCodeFormat,
  otpauthUri,
  totpStep,
  verifyTotp,
} from '../../src/crypto/totp.js';
import { DecryptionError, openSecret, sealSecret } from '../../src/crypto/envelope.js';

const RFC_SECRET = Buffer.from('12345678901234567890');

describe('TOTP (RFC 6238)', () => {
  it('matches the RFC 6238 SHA-1 test vectors (last 6 digits)', () => {
    const vectors: [number, string][] = [
      [59, '287082'],
      [1_111_111_109, '081804'],
      [1_111_111_111, '050471'],
      [1_234_567_890, '005924'],
      [2_000_000_000, '279037'],
    ];
    for (const [t, code] of vectors) expect(hotp(RFC_SECRET, totpStep(t * 1000))).toBe(code);
  });

  it('round-trips base32 (RFC 4648 vector)', () => {
    expect(base32Encode(Buffer.from('foobar'))).toBe('MZXW6YTBOI');
    const raw = randomBytes(20);
    expect(base32Decode(base32Encode(raw)).equals(raw)).toBe(true);
    expect(() => base32Decode('not base32!')).toThrow();
  });

  it('accepts ±1 step of clock drift, nothing further', () => {
    const now = 1_700_000_000_000;
    const step = totpStep(now);
    expect(verifyTotp(RFC_SECRET, hotp(RFC_SECRET, step), now, 0)).toBe(step);
    expect(verifyTotp(RFC_SECRET, hotp(RFC_SECRET, step - 1), now, 0)).toBe(step - 1);
    expect(verifyTotp(RFC_SECRET, hotp(RFC_SECRET, step + 1), now, 0)).toBe(step + 1);
    expect(verifyTotp(RFC_SECRET, hotp(RFC_SECRET, step - 2), now, 0)).toBeNull();
    expect(verifyTotp(RFC_SECRET, hotp(RFC_SECRET, step + 2), now, 0)).toBeNull();
  });

  it('refuses a code whose step was already used (replay)', () => {
    const now = 1_700_000_000_000;
    const step = totpStep(now);
    expect(verifyTotp(RFC_SECRET, hotp(RFC_SECRET, step), now, step)).toBeNull();
    expect(verifyTotp(RFC_SECRET, hotp(RFC_SECRET, step - 1), now, step - 1)).toBeNull();
  });

  it('refuses malformed codes without computing anything', () => {
    for (const bad of ['', '12345', '1234567', 'abcdef', '12 456', '０１２３４５']) {
      expect(verifyTotp(RFC_SECRET, bad, Date.now(), 0)).toBeNull();
    }
  });

  it('builds an otpauth URI that authenticator apps understand', () => {
    const uri = new URL(otpauthUri(RFC_SECRET, 'ada@example.test', 'Bastion Academy'));
    expect(uri.protocol).toBe('otpauth:');
    expect(uri.searchParams.get('secret')).toBe(base32Encode(RFC_SECRET));
    expect(uri.searchParams.get('issuer')).toBe('Bastion Academy');
    expect(uri.searchParams.get('digits')).toBe('6');
  });
});

describe('recovery codes', () => {
  it('generates 10 distinct high-entropy codes and stores only their hashes', () => {
    const { codes, hashes } = generateRecoveryCodes();
    expect(new Set(codes).size).toBe(10);
    for (const c of codes) expect(c).toMatch(/^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$/);
    expect(hashes.join()).not.toContain(codes[0]);
    expect(hashes[0]).toBe(hashRecoveryCode(codes[0] ?? ''));
  });

  it('normalises case and dashes when a code is typed back', () => {
    const { codes } = generateRecoveryCodes();
    const code = codes[0] ?? '';
    expect(hashRecoveryCode(code.toLowerCase().replaceAll('-', ''))).toBe(hashRecoveryCode(code));
    expect(isRecoveryCodeFormat(code.toLowerCase())).toBe(true);
    expect(isRecoveryCodeFormat('123456')).toBe(false);
  });
});

describe('sealed account secrets', () => {
  const ring = { keys: new Map([['k1', randomBytes(32)], ['k2', randomBytes(32)]]), activeKeyId: 'k1' };

  it('opens only with the same purpose/owner binding', () => {
    const secret = randomBytes(20);
    const { keyId, blob } = sealSecret(ring, secret, 'bastion:totp-secret:v1:alice');
    expect(openSecret(ring, keyId, blob, 'bastion:totp-secret:v1:alice').equals(secret)).toBe(true);
    // Alice's sealed seed copied into Bob's row does not open.
    expect(() => openSecret(ring, keyId, blob, 'bastion:totp-secret:v1:bob')).toThrow(DecryptionError);
    expect(() => openSecret(ring, 'k2', blob, 'bastion:totp-secret:v1:alice')).toThrow(DecryptionError);
    expect(() => openSecret(ring, keyId, blob.subarray(0, 20), 'bastion:totp-secret:v1:alice')).toThrow(DecryptionError);
  });
});
