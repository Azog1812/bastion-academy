/**
 * A strict, bounded CBOR decoder (RFC 8949), only as much as WebAuthn needs (ADR 0016):
 * the attestation object and COSE public keys. Both come from the browser, so from
 * whoever controls it, and are parsed before any signature is checked.
 *
 * - Definite lengths only: indefinite-length items, tags and floats are refused, so
 *   nothing streams and nothing is interpreted beyond integers, strings, arrays, maps
 *   and true/false/null.
 * - Every length is checked against the bytes actually left before anything is
 *   allocated: a header announcing 2^63 bytes fails at once, it cannot exhaust memory.
 * - Nesting depth and item count are capped; duplicate map keys are refused (an
 *   ambiguous key, such as two "alg" entries, must not let parsers disagree).
 * - Map keys are integers or text only, kept in a Map: no object, no prototype.
 */

export class CborError extends Error {}

export type CborValue = number | string | Uint8Array | boolean | null | CborValue[] | Map<number | string, CborValue>;

const MAX_DEPTH = 8;
const MAX_ITEMS = 512;

/** Decodes one item starting at `start`; returns it and the offset just after it. */
function decodeAt(bytes: Uint8Array, start: number): { value: CborValue; end: number } {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let pos = start;
  let items = 0;

  const need = (n: number) => {
    if (n > bytes.length - pos) throw new CborError('truncated CBOR');
  };
  const argument = (info: number): number => {
    if (info < 24) return info;
    if (info === 24) {
      need(1);
      return bytes[pos++] ?? 0;
    }
    if (info === 25) {
      need(2);
      const v = view.getUint16(pos);
      pos += 2;
      return v;
    }
    if (info === 26) {
      need(4);
      const v = view.getUint32(pos);
      pos += 4;
      return v;
    }
    if (info === 27) {
      need(8);
      const v = view.getBigUint64(pos);
      pos += 8;
      // Anything this large is a length or an integer no WebAuthn structure has.
      if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new CborError('CBOR integer too large');
      return Number(v);
    }
    throw new CborError('indefinite or reserved CBOR length');
  };

  const item = (depth: number): CborValue => {
    if (depth > MAX_DEPTH) throw new CborError('CBOR nested too deeply');
    if (++items > MAX_ITEMS) throw new CborError('too many CBOR items');
    need(1);
    const head = bytes[pos++] ?? 0;
    const major = head >> 5;
    const info = head & 0x1f;
    switch (major) {
      case 0:
        return argument(info);
      case 1:
        return -1 - argument(info);
      case 2: {
        const n = argument(info);
        need(n);
        const out = bytes.slice(pos, pos + n);
        pos += n;
        return out;
      }
      case 3: {
        const n = argument(info);
        need(n);
        const out = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(pos, pos + n));
        pos += n;
        return out;
      }
      case 4: {
        const n = argument(info);
        // Each element takes at least one byte: a count above what is left is a lie.
        need(n);
        return Array.from({ length: n }, () => item(depth + 1));
      }
      case 5: {
        const n = argument(info);
        need(n * 2);
        const map = new Map<number | string, CborValue>();
        for (let k = 0; k < n; k++) {
          const key = item(depth + 1);
          if (typeof key !== 'number' && typeof key !== 'string') throw new CborError('CBOR map key must be an integer or a text string');
          if (map.has(key)) throw new CborError('duplicate CBOR map key');
          map.set(key, item(depth + 1));
        }
        return map;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        throw new CborError('unsupported CBOR simple value or float');
      default:
        throw new CborError('CBOR tags are not supported');
    }
  };

  const value = item(0);
  return { value, end: pos };
}

/** Decodes exactly one item: trailing bytes are an error. */
export function decodeCbor(bytes: Uint8Array): CborValue {
  const { value, end } = decodeAt(bytes, 0);
  if (end !== bytes.length) throw new CborError('trailing bytes after CBOR item');
  return value;
}

/**
 * Decodes the first item and says where it ends: in authenticator data the credential
 * public key is followed by optional extensions, with no length prefix.
 */
export function decodeCborPrefix(bytes: Uint8Array): { value: CborValue; length: number } {
  const { value, end } = decodeAt(bytes, 0);
  return { value, length: end };
}
