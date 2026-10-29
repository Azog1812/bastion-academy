import { createHmac, randomBytes } from 'node:crypto';
import { SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import { createTokenSigner, generateRefreshToken, hashRefreshToken, InvalidTokenError } from '../../src/crypto/tokens.js';

const secret = randomBytes(32);
const signer = createTokenSigner({ secret, issuer: 'bastion', audience: 'bastion-api', ttlSeconds: 900 });
const b64url = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
const now = () => Math.floor(Date.now() / 1000);

async function expectInvalid(token: string, reason: 'invalid' | 'expired' = 'invalid') {
  await expect(signer.verify(token)).rejects.toEqual(new InvalidTokenError(reason));
}

describe('JWT access tokens', () => {
  it('round-trips claims', async () => {
    const token = await signer.sign({ sub: 'u1', role: 'user', tv: 3 });
    expect(await signer.verify(token)).toEqual({ sub: 'u1', role: 'user', tv: 3 });
  });

  it('rejects "alg: none" (unsigned token attack)', async () => {
    const claims = { sub: 'u1', role: 'admin', tv: 0, iss: 'bastion', aud: 'bastion-api', iat: now(), exp: now() + 600, jti: 'x' };
    await expectInvalid(`${b64url({ alg: 'none', typ: 'at+jwt' })}.${b64url(claims)}.`); // nosemgrep
  });

  it('rejects a payload modified after signing (privilege escalation attempt)', async () => {
    const [h, p, s] = (await signer.sign({ sub: 'u1', role: 'user', tv: 0 })).split('.');
    const payload = JSON.parse(Buffer.from(p!, 'base64url').toString()) as Record<string, unknown>;
    payload.role = 'admin';
    await expectInvalid(`${h}.${b64url(payload)}.${s}`);
  });

  it('rejects a token signed with another key', async () => {
    const other = createTokenSigner({ secret: randomBytes(32), issuer: 'bastion', audience: 'bastion-api', ttlSeconds: 900 });
    await expectInvalid(await other.sign({ sub: 'u1', role: 'admin', tv: 0 }));
  });

  it('rejects algorithms outside the allow-list, even with the right key (HS512)', async () => {
    const forged = await new SignJWT({ role: 'user', tv: 0 })
      .setProtectedHeader({ alg: 'HS512', typ: 'at+jwt' })
      .setSubject('u1').setIssuer('bastion').setAudience('bastion-api').setIssuedAt().setExpirationTime('5m').setJti('j')
      .sign(new Uint8Array(Buffer.concat([secret, secret])));
    await expectInvalid(forged);
  });

  it.each([
    ['wrong issuer', { issuer: 'evil' }],
    ['wrong audience', { audience: 'another-service' }],
  ])('rejects a %s (cross-service replay)', async (_n, o) => {
    const foreign = createTokenSigner({ secret, issuer: 'bastion', audience: 'bastion-api', ttlSeconds: 900, ...o });
    await expectInvalid(await foreign.sign({ sub: 'u1', role: 'user', tv: 0 }));
  });

  it('rejects an expired token with a distinct reason', async () => {
    const header = b64url({ alg: 'HS256', typ: 'at+jwt' });
    const body = b64url({ sub: 'u1', role: 'user', tv: 0, iss: 'bastion', aud: 'bastion-api', iat: now() - 7200, exp: now() - 3600, jti: 'j' });
    const sig = createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
    await expectInvalid(`${header}.${body}.${sig}`, 'expired');
  });

  it('rejects a validly signed token whose claims are structurally wrong', async () => {
    const weird = await new SignJWT({ role: 'superuser', tv: 0 })
      .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt' })
      .setSubject('u1').setIssuer('bastion').setAudience('bastion-api').setIssuedAt().setExpirationTime('5m').setJti('j')
      .sign(new Uint8Array(secret));
    await expectInvalid(weird);
  });

  it('rejects a token of another type (e.g. an ID token)', async () => {
    const idToken = await new SignJWT({ role: 'user', tv: 0 })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setSubject('u1').setIssuer('bastion').setAudience('bastion-api').setIssuedAt().setExpirationTime('5m').setJti('j')
      .sign(new Uint8Array(secret));
    await expectInvalid(idToken);
  });

  it('rejects garbage', async () => {
    await expectInvalid('not.a.jwt');
  });
});

describe('refresh tokens', () => {
  it('have 256 bits of entropy and are stored only as a SHA-256 hash', () => {
    const { token, hash } = generateRefreshToken();
    expect(Buffer.from(token, 'base64url')).toHaveLength(32);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).toBe(hashRefreshToken(token));
    expect(hash).not.toContain(token);
  });
});
