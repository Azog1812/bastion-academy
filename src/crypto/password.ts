import { randomBytes, scrypt as scryptCb, timingSafeEqual, type ScryptOptions } from 'node:crypto';

/**
 * Password hashing with scrypt (memory-hard, built into Node — no native addon).
 * Parameters follow the OWASP Password Storage Cheat Sheet: N=2^17, r=8, p=1.
 *
 * Stored format (self-describing, so parameters can be raised later):
 *   scrypt$ln=17,r=8,p=1$<salt-base64>$<hash-base64>
 */

const KEY_LEN = 64;
const SALT_LEN = 16;
const R = 8;
const P = 1;

function scrypt(password: string, salt: Buffer, logN: number): Promise<Buffer> {
  const N = 2 ** logN;
  const opts: ScryptOptions = { N, r: R, p: P, maxmem: 256 * N * R };
  return new Promise((resolve, reject) => {
    scryptCb(password.normalize('NFKC'), salt, KEY_LEN, opts, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

export async function hashPassword(password: string, logN: number): Promise<string> {
  const salt = randomBytes(SALT_LEN);
  const hash = await scrypt(password, salt, logN);
  return `scrypt$ln=${logN},r=${R},p=${P}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

interface Parsed {
  logN: number;
  salt: Buffer;
  hash: Buffer;
}

function parse(stored: string): Parsed | null {
  const m = /^scrypt\$ln=(\d{1,2}),r=8,p=1\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$/.exec(stored);
  if (!m) return null;
  return { logN: Number(m[1]), salt: Buffer.from(m[2] as string, 'base64'), hash: Buffer.from(m[3] as string, 'base64') };
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parsed = parse(stored);
  if (!parsed) return false;
  const candidate = await scrypt(password, parsed.salt, parsed.logN);
  // Constant-time comparison: no early exit that would leak via timing.
  return candidate.length === parsed.hash.length && timingSafeEqual(candidate, parsed.hash);
}

export function needsRehash(stored: string, logN: number): boolean {
  const parsed = parse(stored);
  return !parsed || parsed.logN < logN;
}

/**
 * Login against an unknown e-mail still pays the full scrypt cost against
 * this dummy hash, so response time does not reveal whether an account exists.
 */
export async function createDummyHash(logN: number): Promise<string> {
  return hashPassword(randomBytes(32).toString('base64'), logN);
}
