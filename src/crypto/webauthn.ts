import { createHash, createPublicKey, timingSafeEqual, verify, type KeyObject } from 'node:crypto';
import { CborError, decodeCbor, decodeCborPrefix, type CborValue } from './cbor.js';

/**
 * WebAuthn relying-party checks (W3C WebAuthn Level 3, §7), on node:crypto only (ADR 0016).
 *
 * Why passkeys resist phishing: the browser writes the page's origin into the signed
 * client data, and the authenticator signs a hash of the RP ID it was registered for.
 * A look-alike site gets a signature over *its* origin, which these checks refuse; there
 * is no code for a proxy to relay. Every check below is part of that guarantee:
 *
 * - type, challenge (single use, from the server) and exact origin in clientDataJSON;
 * - rpIdHash in authenticator data, and the user-presence flag;
 * - the signature over authenticatorData || SHA-256(clientDataJSON) with the stored key;
 * - the signature counter, which must grow when the authenticator keeps one: a counter
 *   that goes back means two copies of the key exist (a cloned authenticator).
 *
 * Attestation (which authenticator model made the key) is not verified: a learning
 * platform does not restrict authenticator brands, and not asking for it (attestation
 * "none") keeps the user's device private. Possession of the key is what is proven.
 */

export class WebAuthnError extends Error {}
/** The signature counter went backwards: the credential may have been cloned. */
export class CloneWarning extends WebAuthnError {}

export interface RelyingParty {
  id: string;
  origins: readonly string[];
}

/** COSE algorithm identifiers accepted, in order of preference (offered to the browser). */
export const COSE_ALGS = [-8, -7, -257] as const; // EdDSA (Ed25519), ES256 (P-256), RS256
export type CoseAlg = (typeof COSE_ALGS)[number];

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;
const FLAG_ED = 0x80;

const sha256 = (data: Uint8Array) => createHash('sha256').update(data).digest();
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && timingSafeEqual(a, b);

function clientData(json: Uint8Array, type: 'webauthn.create' | 'webauthn.get', challenge: Uint8Array, rp: RelyingParty): void {
  let data: unknown;
  try {
    data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(json));
  } catch {
    throw new WebAuthnError('clientDataJSON is not JSON');
  }
  if (typeof data !== 'object' || data === null) throw new WebAuthnError('clientDataJSON is not an object');
  const c = data as Record<string, unknown>;
  if (c.type !== type) throw new WebAuthnError(`expected a ${type} ceremony`);
  if (typeof c.challenge !== 'string' || !same(Buffer.from(c.challenge, 'base64url'), challenge)) throw new WebAuthnError('challenge mismatch');
  // Exact match: a phishing page's origin is written here by the browser, and refused.
  if (typeof c.origin !== 'string' || !rp.origins.includes(c.origin)) throw new WebAuthnError('origin not allowed');
  if (c.crossOrigin === true) throw new WebAuthnError('cross-origin ceremonies are refused');
}

interface AuthData {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  credential?: { id: Uint8Array; publicKey: CborValue };
}

export function parseAuthenticatorData(data: Uint8Array): AuthData {
  if (data.length < 37) throw new WebAuthnError('authenticator data too short');
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const flags = data[32] ?? 0;
  const out: AuthData = { rpIdHash: data.subarray(0, 32), flags, signCount: view.getUint32(33) };
  let pos = 37;
  try {
    if (flags & FLAG_AT) {
      if (data.length < pos + 18) throw new WebAuthnError('attested credential data too short');
      const idLength = view.getUint16(pos + 16);
      pos += 18;
      if (idLength < 16 || idLength > 1023 || data.length < pos + idLength) throw new WebAuthnError('bad credential id length');
      const id = data.slice(pos, pos + idLength);
      pos += idLength;
      const key = decodeCborPrefix(data.subarray(pos));
      pos += key.length;
      out.credential = { id, publicKey: key.value };
    }
    if (flags & FLAG_ED) {
      decodeCbor(data.subarray(pos)); // extensions: well-formed, then ignored
      pos = data.length;
    }
  } catch (err) {
    if (err instanceof CborError) throw new WebAuthnError(`malformed authenticator data: ${err.message}`);
    throw err;
  }
  if (pos !== data.length) throw new WebAuthnError('trailing bytes in authenticator data');
  return out;
}

const bytesAt = (m: Map<number | string, CborValue>, k: number, len?: number): Buffer => {
  const v = m.get(k);
  if (!(v instanceof Uint8Array) || (len !== undefined && v.length !== len)) throw new WebAuthnError(`bad COSE key parameter ${String(k)}`);
  return Buffer.from(v);
};

/** COSE_Key (RFC 9053) to a node KeyObject, for the three algorithms offered and nothing else. */
export function coseToKey(cose: CborValue): { key: KeyObject; alg: CoseAlg } {
  if (!(cose instanceof Map)) throw new WebAuthnError('COSE key is not a map');
  const kty = cose.get(1);
  const alg = cose.get(3);
  const jwk = (k: Record<string, string>) => createPublicKey({ key: k, format: 'jwk' });
  try {
    if (kty === 2 && alg === -7 && cose.get(-1) === 1) {
      return { key: jwk({ kty: 'EC', crv: 'P-256', x: bytesAt(cose, -2, 32).toString('base64url'), y: bytesAt(cose, -3, 32).toString('base64url') }), alg };
    }
    if (kty === 1 && alg === -8 && cose.get(-1) === 6) {
      return { key: jwk({ kty: 'OKP', crv: 'Ed25519', x: bytesAt(cose, -2, 32).toString('base64url') }), alg };
    }
    if (kty === 3 && alg === -257) {
      const n = bytesAt(cose, -1);
      if (n.length < 256) throw new WebAuthnError('RSA keys under 2048 bits are refused');
      return { key: jwk({ kty: 'RSA', n: n.toString('base64url'), e: bytesAt(cose, -2).toString('base64url') }), alg };
    }
  } catch (err) {
    // An x/y that is not on the curve, for instance.
    if (err instanceof WebAuthnError) throw err;
    throw new WebAuthnError('invalid COSE public key');
  }
  throw new WebAuthnError('unsupported key type or algorithm (Ed25519, ES256 or RS256 only)');
}

export interface Registration {
  credentialId: Buffer;
  /** SubjectPublicKeyInfo DER: what is stored, re-imported for every assertion. */
  publicKey: Buffer;
  alg: CoseAlg;
  signCount: number;
  userVerified: boolean;
}

export function verifyRegistration(rp: RelyingParty, challenge: Uint8Array, clientDataJSON: Uint8Array, attestationObject: Uint8Array): Registration {
  clientData(clientDataJSON, 'webauthn.create', challenge, rp);
  let att: CborValue;
  try {
    att = decodeCbor(attestationObject);
  } catch (err) {
    if (err instanceof CborError) throw new WebAuthnError(`malformed attestation object: ${err.message}`);
    throw err;
  }
  if (!(att instanceof Map)) throw new WebAuthnError('attestation object is not a map');
  const fmt = att.get('fmt');
  const authData = att.get('authData');
  if (typeof fmt !== 'string' || fmt.length > 32 || !(authData instanceof Uint8Array) || !(att.get('attStmt') instanceof Map)) {
    throw new WebAuthnError('attestation object lacks fmt, authData or attStmt');
  }
  const auth = parseAuthenticatorData(authData);
  if (!same(auth.rpIdHash, sha256(Buffer.from(rp.id)))) throw new WebAuthnError('credential made for another RP ID');
  if (!(auth.flags & FLAG_UP)) throw new WebAuthnError('user presence flag not set');
  if (!auth.credential) throw new WebAuthnError('no attested credential data');
  const { key, alg } = coseToKey(auth.credential.publicKey);
  return {
    credentialId: Buffer.from(auth.credential.id),
    publicKey: key.export({ format: 'der', type: 'spki' }),
    alg,
    signCount: auth.signCount,
    userVerified: (auth.flags & FLAG_UV) !== 0,
  };
}

export interface StoredCredential {
  publicKey: Uint8Array;
  alg: CoseAlg;
  signCount: number;
}

export function verifyAssertion(
  rp: RelyingParty,
  challenge: Uint8Array,
  credential: StoredCredential,
  clientDataJSON: Uint8Array,
  authenticatorData: Uint8Array,
  signature: Uint8Array,
): { signCount: number; userVerified: boolean } {
  clientData(clientDataJSON, 'webauthn.get', challenge, rp);
  const auth = parseAuthenticatorData(authenticatorData);
  if (!same(auth.rpIdHash, sha256(Buffer.from(rp.id)))) throw new WebAuthnError('assertion for another RP ID');
  if (!(auth.flags & FLAG_UP)) throw new WebAuthnError('user presence flag not set');
  if (auth.credential) throw new WebAuthnError('unexpected attested credential data in an assertion');

  const key = createPublicKey({ key: Buffer.from(credential.publicKey), format: 'der', type: 'spki' });
  const signed = Buffer.concat([authenticatorData, sha256(clientDataJSON)]);
  const ok =
    credential.alg === -8
      ? verify(null, signed, key, signature)
      : verify('sha256', signed, credential.alg === -7 ? { key, dsaEncoding: 'der' } : key, signature);
  if (!ok) throw new WebAuthnError('bad signature');

  // A counter of 0 on both sides means the authenticator keeps none (synced passkeys).
  if ((auth.signCount !== 0 || credential.signCount !== 0) && auth.signCount <= credential.signCount) {
    throw new CloneWarning('signature counter did not increase');
  }
  return { signCount: auth.signCount, userVerified: (auth.flags & FLAG_UV) !== 0 };
}
