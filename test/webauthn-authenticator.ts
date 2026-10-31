import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';

/**
 * A software authenticator for tests (ADR 0016): makes the same bytes a browser and a
 * security key would, so the relying-party checks run on real structures, and lets a
 * test change any of them (origin, RP ID, flags, counter, signature) to play the attacker.
 */

type Cbor = number | string | Uint8Array | boolean | null | Cbor[] | Map<number | string, Cbor>;

function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65_536) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(n, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}

export function encodeCbor(v: Cbor): Buffer {
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === 'string') {
    const s = Buffer.from(v);
    return Buffer.concat([head(3, s.length), s]);
  }
  if (v instanceof Uint8Array) return Buffer.concat([head(2, v.length), v]);
  if (v === false) return Buffer.from([0xf4]);
  if (v === true) return Buffer.from([0xf5]);
  if (v === null) return Buffer.from([0xf6]);
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(encodeCbor)]);
  return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [encodeCbor(k), encodeCbor(x)])]);
}

export type KeyKind = 'es256' | 'ed25519' | 'rs256';

export interface Options {
  origin?: string;
  rpId?: string;
  type?: string;
  flags?: number;
  crossOrigin?: boolean;
}

const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const sha256 = (b: Uint8Array | string) => createHash('sha256').update(b).digest();

export class SoftAuthenticator {
  readonly credentialId = randomBytes(32);
  private readonly privateKey: KeyObject;
  private readonly cose: Map<number, Cbor>;
  counter: number;

  constructor(
    readonly kind: KeyKind = 'es256',
    readonly origin = 'http://localhost:3000',
    readonly rpId = 'localhost',
    /** Synced passkeys keep no counter (0 forever); security keys count up. */
    counter = 0,
  ) {
    this.counter = counter;
    if (kind === 'ed25519') {
      const { privateKey, publicKey } = generateKeyPairSync('ed25519');
      this.privateKey = privateKey;
      const jwk = publicKey.export({ format: 'jwk' });
      this.cose = new Map<number, Cbor>([[1, 1], [3, -8], [-1, 6], [-2, Buffer.from(jwk.x ?? '', 'base64url')]]);
    } else if (kind === 'rs256') {
      const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
      this.privateKey = privateKey;
      const jwk = publicKey.export({ format: 'jwk' });
      this.cose = new Map<number, Cbor>([[1, 3], [3, -257], [-1, Buffer.from(jwk.n ?? '', 'base64url')], [-2, Buffer.from(jwk.e ?? '', 'base64url')]]);
    } else {
      const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      this.privateKey = privateKey;
      const jwk = publicKey.export({ format: 'jwk' });
      this.cose = new Map<number, Cbor>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, Buffer.from(jwk.x ?? '', 'base64url')],
        [-3, Buffer.from(jwk.y ?? '', 'base64url')],
      ]);
    }
  }

  coseKey(): Map<number, Cbor> {
    return new Map(this.cose);
  }

  clientData(type: string, challenge: string, o: Options): Buffer {
    return Buffer.from(JSON.stringify({ type: o.type ?? type, challenge, origin: o.origin ?? this.origin, crossOrigin: o.crossOrigin ?? false }));
  }

  authData(flags: number, rpId: string, attested?: { cose: Cbor }): Buffer {
    const count = Buffer.alloc(4);
    count.writeUInt32BE(this.counter);
    const parts: Buffer[] = [sha256(rpId), Buffer.from([flags]), count];
    if (attested) {
      const len = Buffer.alloc(2);
      len.writeUInt16BE(this.credentialId.length);
      parts.push(Buffer.alloc(16), len, this.credentialId, encodeCbor(attested.cose));
    }
    return Buffer.concat(parts);
  }

  /** The response to navigator.credentials.create(), as the page sends it. */
  register(challenge: string, o: Options & { cose?: Cbor; fmt?: string } = {}) {
    const clientDataJSON = this.clientData('webauthn.create', challenge, o);
    const authData = this.authData(o.flags ?? 0x45, o.rpId ?? this.rpId, { cose: o.cose ?? this.cose });
    const attestationObject = encodeCbor(new Map<string, Cbor>([['fmt', o.fmt ?? 'none'], ['attStmt', new Map()], ['authData', authData]]));
    return { id: b64u(this.credentialId), type: 'public-key', response: { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject) } };
  }

  /** The response to navigator.credentials.get(). Each call counts up, as a security key does. */
  assert(challenge: string, o: Options & { tamperSignature?: boolean; keepCounter?: boolean } = {}) {
    if (!o.keepCounter && this.counter > 0) this.counter++;
    const clientDataJSON = this.clientData('webauthn.get', challenge, o);
    const authenticatorData = this.authData(o.flags ?? 0x05, o.rpId ?? this.rpId);
    const signed = Buffer.concat([authenticatorData, sha256(clientDataJSON)]);
    const signature = this.kind === 'ed25519' ? sign(null, signed, this.privateKey) : sign('sha256', signed, this.privateKey);
    if (o.tamperSignature) signature[signature.length - 1] = (signature[signature.length - 1] ?? 0) ^ 1;
    return {
      id: b64u(this.credentialId),
      type: 'public-key',
      response: { clientDataJSON: b64u(clientDataJSON), authenticatorData: b64u(authenticatorData), signature: b64u(signature) },
    };
  }
}
