import { describe, expect, it } from 'vitest';
import { createDummyHash, hashPassword, needsRehash, verifyPassword } from '../../src/crypto/password.js';
import { passwordProblem } from '../../src/security/password-policy.js';

describe('scrypt password hashing', () => {
  it('verifies the right password and rejects the wrong one', async () => {
    const h = await hashPassword('correct horse battery staple', 10);
    expect(await verifyPassword('correct horse battery staple', h)).toBe(true);
    expect(await verifyPassword('correct horse battery stapl', h)).toBe(false);
  });

  it('uses a unique salt per hash', async () => {
    const [a, b] = await Promise.all([hashPassword('same', 10), hashPassword('same', 10)]);
    expect(a).not.toBe(b);
  });

  it('stores self-describing parameters', async () => {
    expect(await hashPassword('x', 10)).toMatch(/^scrypt\$ln=10,r=8,p=1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
  });

  it('normalises Unicode so the same visible password always matches (NFKC)', async () => {
    const h = await hashPassword('café-password', 10); // precomposed é
    expect(await verifyPassword('café-password', h)).toBe(true); // e + combining accent
  });

  it('rejects malformed or foreign hash formats instead of throwing', async () => {
    expect(await verifyPassword('x', '$2b$10$bcrypt-hash')).toBe(false);
    expect(await verifyPassword('x', '')).toBe(false);
  });

  it('flags hashes below the configured cost for transparent upgrade', async () => {
    const h = await hashPassword('x', 10);
    expect(needsRehash(h, 10)).toBe(false);
    expect(needsRehash(h, 12)).toBe(true);
    expect(needsRehash('garbage', 10)).toBe(true);
  });

  it('produces a dummy hash that matches no realistic password', async () => {
    const dummy = await createDummyHash(10);
    expect(await verifyPassword('', dummy)).toBe(false);
    expect(await verifyPassword('password', dummy)).toBe(false);
  });
});

describe('password policy (NIST 800-63B)', () => {
  const email = 'florent@example.test';

  it.each([
    ['short', 'at least 12'],
    ['a'.repeat(129), 'at most 128'],
    ['q1w2e3r4t5y6', 'too common'],
    ['Q1W2E3R4T5Y6', 'too common'],
    ['zzzzzzzzzzzzzzzz', 'repeated'],
    ['my-florent-password-2026', 'e-mail'],
    ['I love Bastion so much', 'service name'],
  ])('rejects %j (%s)', (pw, reason) => {
    expect(passwordProblem(pw, email)).toContain(reason);
  });

  it('accepts a long passphrase without composition rules', () => {
    expect(passwordProblem('correct horse battery staple', email)).toBeNull();
  });

  it('counts characters, not UTF-16 code units', () => {
    expect(passwordProblem('🔐🔑'.repeat(6), email)).toBeNull(); // 12 chars, 24 UTF-16 units
    expect(passwordProblem(`${'🔐🔑'.repeat(5)}🔐`, email)).toContain('at least 12');
  });
});
