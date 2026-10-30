import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * TOTP (RFC 6238) and recovery codes, on node:crypto only (invariant 11: an
 * authenticator library would be supply-chain surface for ~60 lines of code).
 *
 * HMAC-SHA1 is what RFC 6238 specifies and what every authenticator app
 * implements. SHA-1 collisions do not affect HMAC: its security rests on the
 * secrecy of the key, not on collision resistance.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const TOTP_PERIOD_SECONDS = 30;
const DIGITS = 6;
/** One step either side: tolerates ±30 s of clock drift on the phone, no more. */
const DRIFT_STEPS = 1;

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = ((value << 8) | byte) & 0xfff;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET.charAt((value >>> (bits - 5)) & 31);
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET.charAt((value << (5 - bits)) & 31);
  return out;
}

export function base32Decode(input: string): Buffer {
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of input.replace(/[\s=]/g, '').toUpperCase()) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('invalid base32');
    value = ((value << 5) | idx) & 0xfff;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** 160-bit secret, the size RFC 4226 recommends for HMAC-SHA1. */
export const generateTotpSecret = (): Buffer => randomBytes(20);

export const totpStep = (nowMs: number): number => Math.floor(nowMs / 1000 / TOTP_PERIOD_SECONDS);

export function hotp(secret: Buffer, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', secret).update(msg).digest();
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  const bin = mac.readUInt32BE(offset) & 0x7fffffff;
  return String(bin % 10 ** DIGITS).padStart(DIGITS, '0');
}

/**
 * Returns the matched time step, or null. Steps at or below `lastStep` are
 * refused: a code seen once (by a shoulder-surfer, a phishing proxy, a log)
 * can never be replayed, even inside its 30-second window.
 */
export function verifyTotp(secret: Buffer, code: string, nowMs: number, lastStep: number): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const current = totpStep(nowMs);
  let match: number | null = null;
  // Every candidate is computed and compared: same work whether the code is right or wrong.
  for (let step = current - DRIFT_STEPS; step <= current + DRIFT_STEPS; step++) {
    const equal = timingSafeEqual(Buffer.from(hotp(secret, step)), Buffer.from(code));
    if (equal && step > lastStep) match = step;
  }
  return match;
}

export function otpauthUri(secret: Buffer, account: string, issuer: string): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const params = new URLSearchParams({
    secret: base32Encode(secret),
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(TOTP_PERIOD_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/* ---------- recovery codes ---------- */

export const RECOVERY_CODE_COUNT = 10;

/**
 * 80 random bits each (16 base32 chars), shown once, stored as SHA-256. A fast
 * hash is enough here, unlike passwords: 2^80 guesses is out of reach offline,
 * so there is nothing for scrypt's cost to protect.
 */
export function generateRecoveryCodes(): { codes: string[]; hashes: string[] } {
  const codes = Array.from({ length: RECOVERY_CODE_COUNT }, () =>
    (base32Encode(randomBytes(10)).match(/.{4}/g) ?? []).join('-'),
  );
  return { codes, hashes: codes.map(hashRecoveryCode) };
}

/** Dashes are optional when typing a code back. */
export const isRecoveryCodeFormat = (code: string): boolean => /^[A-Z2-7]{16}$/.test(code.toUpperCase().replaceAll('-', ''));

export function hashRecoveryCode(code: string): string {
  return createHash('sha256').update(code.toUpperCase().replaceAll('-', '')).digest('hex');
}
