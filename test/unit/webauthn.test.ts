import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { CborError, decodeCbor } from '../../src/crypto/cbor.js';
import { CloneWarning, verifyAssertion, verifyRegistration, WebAuthnError, type RelyingParty } from '../../src/crypto/webauthn.js';
import { encodeCbor, SoftAuthenticator, type KeyKind } from '../webauthn-authenticator.js';

const rp: RelyingParty = { id: 'localhost', origins: ['http://localhost:3000'] };
const b = (s: string) => Buffer.from(s, 'base64url');
const fresh = () => randomBytes(32);

function enrol(a: SoftAuthenticator, o: Parameters<SoftAuthenticator['register']>[1] = {}) {
  const challenge = fresh();
  const r = a.register(challenge.toString('base64url'), o);
  return verifyRegistration(rp, challenge, b(r.response.clientDataJSON), b(r.response.attestationObject));
}

function login(a: SoftAuthenticator, stored: { publicKey: Uint8Array; alg: -7 | -8 | -257; signCount: number }, o: Parameters<SoftAuthenticator['assert']>[1] = {}, challenge = fresh()) {
  const r = a.assert(challenge.toString('base64url'), o);
  return verifyAssertion(rp, challenge, stored, b(r.response.clientDataJSON), b(r.response.authenticatorData), b(r.response.signature));
}

describe('WebAuthn relying party (ADR 0016)', () => {
  it.each<KeyKind>(['es256', 'ed25519', 'rs256'])('registers and verifies a %s passkey', (kind) => {
    const a = new SoftAuthenticator(kind);
    const reg = enrol(a);
    expect(reg.credentialId.equals(a.credentialId)).toBe(true);
    expect(reg.userVerified).toBe(true);
    expect(login(a, { publicKey: reg.publicKey, alg: reg.alg, signCount: reg.signCount })).toMatchObject({ signCount: 0, userVerified: true });
  });

  it('refuses a ceremony run on a phishing origin, or for another RP ID', () => {
    const a = new SoftAuthenticator();
    expect(() => enrol(a, { origin: 'http://localhost.evil.example' })).toThrow(/origin/);
    expect(() => enrol(a, { origin: 'http://localhost:3001' })).toThrow(/origin/);
    expect(() => enrol(a, { rpId: 'evil.example' })).toThrow(/RP ID/);
    const reg = enrol(a);
    const stored = { publicKey: reg.publicKey, alg: reg.alg, signCount: 0 };
    // A proxy relays everything, but the browser writes the proxy's origin into clientData.
    expect(() => login(a, stored, { origin: 'https://bastion-academy.example' })).toThrow(/origin/);
    expect(() => login(a, stored, { rpId: 'evil.example' })).toThrow(/RP ID/);
    expect(() => login(a, stored, { crossOrigin: true })).toThrow(/cross-origin/);
  });

  it('binds each response to its challenge and its ceremony type', () => {
    const a = new SoftAuthenticator();
    const reg = enrol(a);
    const stored = { publicKey: reg.publicKey, alg: reg.alg, signCount: 0 };
    const challenge = fresh();
    const r = a.assert(challenge.toString('base64url'));
    // Same response, another challenge (a replay): refused.
    expect(() => verifyAssertion(rp, fresh(), stored, b(r.response.clientDataJSON), b(r.response.authenticatorData), b(r.response.signature))).toThrow(/challenge/);
    // A registration response presented as a login, and the reverse.
    expect(() => login(a, stored, { type: 'webauthn.create' })).toThrow(/webauthn.get/);
    expect(() => enrol(a, { type: 'webauthn.get' })).toThrow(/webauthn.create/);
  });

  it('checks the signature with the stored key only', () => {
    const a = new SoftAuthenticator();
    const reg = enrol(a);
    expect(() => login(a, { publicKey: reg.publicKey, alg: reg.alg, signCount: 0 }, { tamperSignature: true })).toThrow(/bad signature/);
    const other = enrol(new SoftAuthenticator());
    expect(() => login(a, { publicKey: other.publicKey, alg: other.alg, signCount: 0 })).toThrow(/bad signature/);
  });

  it('requires user presence', () => {
    const a = new SoftAuthenticator();
    expect(() => enrol(a, { flags: 0x40 })).toThrow(/presence/);
    const reg = enrol(a);
    expect(() => login(a, { publicKey: reg.publicKey, alg: reg.alg, signCount: 0 }, { flags: 0x00 })).toThrow(/presence/);
  });

  it('detects a cloned authenticator through its signature counter', () => {
    const key = new SoftAuthenticator('es256', undefined, undefined, 10);
    const reg = enrol(key);
    expect(reg.signCount).toBe(10);
    const first = login(key, { publicKey: reg.publicKey, alg: reg.alg, signCount: reg.signCount });
    expect(first.signCount).toBe(11);
    // The clone signs with a counter the server has already seen.
    expect(() => login(key, { publicKey: reg.publicKey, alg: reg.alg, signCount: first.signCount }, { keepCounter: true })).toThrow(CloneWarning);
    // Synced passkeys report 0 forever: no false alarm.
    const synced = new SoftAuthenticator();
    const s = enrol(synced);
    expect(login(synced, { publicKey: s.publicKey, alg: s.alg, signCount: 0 }).signCount).toBe(0);
  });

  it('accepts only the three algorithms offered, with sound keys', () => {
    const a = new SoftAuthenticator();
    const cose = (patch: [number, unknown][]) => {
      const m = a.coseKey();
      for (const [k, v] of patch) m.set(k, v as never);
      return m;
    };
    expect(() => enrol(a, { cose: cose([[3, -36]]) })).toThrow(/unsupported/); // ES512
    expect(() => enrol(a, { cose: cose([[-1, 2]]) })).toThrow(/unsupported/); // P-384 curve with ES256
    expect(() => enrol(a, { cose: cose([[-2, Buffer.alloc(32, 1)]]) })).toThrow(/invalid COSE public key/); // not on the curve
    expect(() => enrol(a, { cose: cose([[-2, Buffer.alloc(31)]]) })).toThrow(/COSE key parameter/);
    expect(() => enrol(a, { cose: 'not a map' })).toThrow(/not a map/);
  });

  it('parses hostile CBOR without trusting its lengths', () => {
    const t = (bytes: number[] | Buffer) => () => decodeCbor(Buffer.from(bytes));
    expect(t([0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])).toThrow(CborError); // a 2^64-byte string
    expect(t([0x9a, 0xff, 0xff, 0xff, 0xff])).toThrow(/truncated/); // 4 billion array elements
    expect(t([0x5f, 0x41, 0x00, 0xff])).toThrow(/indefinite/);
    expect(t([0xc1, 0x00])).toThrow(/tags/);
    expect(t([0xfb, 0, 0, 0, 0, 0, 0, 0, 0])).toThrow(/float/);
    expect(t([0x00, 0x00])).toThrow(/trailing/);
    expect(t([0xa2, 0x01, 0x00, 0x01, 0x00])).toThrow(/duplicate/);
    expect(t([0xa1, 0x41, 0x00, 0x00])).toThrow(/map key/);
    expect(t(Buffer.concat([Buffer.alloc(20, 0x81), Buffer.from([0x00])]))).toThrow(/deeply/);
    expect(t(Buffer.concat([Buffer.from([0x99, 0x02, 0x00]), Buffer.alloc(512, 0x00)]))).toThrow(/too many/);
    expect(t([0x62, 0xc3, 0x28])).toThrow(); // invalid UTF-8
    // "__proto__" as a key stays a Map entry, never touches a prototype.
    const m = decodeCbor(encodeCbor(new Map([['__proto__', 1]])));
    expect(m instanceof Map && m.get('__proto__')).toBe(1);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('refuses malformed attestation objects and authenticator data', () => {
    const a = new SoftAuthenticator();
    const challenge = fresh();
    const r = a.register(challenge.toString('base64url'));
    const reg = (att: Buffer) => () => verifyRegistration(rp, challenge, b(r.response.clientDataJSON), att);
    expect(reg(Buffer.from([0x01]))).toThrow(/not a map/);
    expect(reg(encodeCbor(new Map([['fmt', 'none']])))).toThrow(/lacks/);
    expect(reg(Buffer.concat([b(r.response.attestationObject), Buffer.from([0])]))).toThrow(/trailing/);
    const shortAuth = encodeCbor(new Map<string, never>([['fmt', 'none' as never], ['attStmt', new Map() as never], ['authData', Buffer.alloc(10) as never]]));
    expect(reg(shortAuth)).toThrow(/too short/);
    expect(() => verifyRegistration(rp, challenge, Buffer.from('not json'), b(r.response.attestationObject))).toThrow(WebAuthnError);
  });
});
