import { createHmac } from 'node:crypto';

/**
 * Challenge artifacts: what a learner receives and has to analyse to recover
 * their flag. Each kind teaches one idea from the lessons. Artifacts are
 * deterministic per (user, challenge), derived from a seed, so reloading the
 * page shows the same puzzle, and nothing has to be stored.
 *
 * The set of kinds is closed: content/ can only pick one of these, never ship
 * code (ADR 0006).
 */

export const CHALLENGE_KINDS = ['base64-layers', 'xor-single-byte', 'http-headers', 'jwt-claims'] as const;
export type ChallengeKind = (typeof CHALLENGE_KINDS)[number];

/** Free-form but typed: the front-end shows each field as text in a <pre>. */
export type Artifact = Record<string, string>;

const b64url = (v: Buffer | string) => Buffer.from(v).toString('base64url');

/** "Encoding is not encryption": the flag, base64-encoded 2 to 4 times. */
function base64Layers(flag: string, seed: Buffer): Artifact {
  let data = flag;
  const layers = 2 + ((seed[0] ?? 0) % 3);
  for (let i = 0; i < layers; i++) data = Buffer.from(data).toString('base64');
  return { data };
}

/** Home-made crypto: single-byte XOR falls to a known-plaintext attack (every flag starts with "BASTION{"). */
function xorSingleByte(flag: string, seed: Buffer): Artifact {
  const key = 1 + ((seed[1] ?? 0) % 255);
  const ct = Buffer.from(flag).map((b) => b ^ key);
  return { ciphertextHex: Buffer.from(ct).toString('hex') };
}

/** Verbose servers: the flag leaks in a debug header among ordinary ones. */
function httpHeaders(flag: string, seed: Buffer): Artifact {
  const requestId = seed.subarray(2, 18).toString('hex');
  const response = [
    'HTTP/1.1 200 OK',
    'Content-Type: application/json; charset=utf-8',
    'Cache-Control: no-store',
    'Server: legacy-api/0.9.3',
    `X-Request-Id: ${requestId}`,
    `X-Debug-Session: ${flag}`,
    'Strict-Transport-Security: max-age=63072000',
    'Content-Length: 27',
    '',
    '{"status":"ok","items":[]}',
  ].join('\n');
  return { response };
}

/** "A JWT is signed, not encrypted": anyone holding the token can read its claims. */
function jwtClaims(flag: string, seed: Buffer): Artifact {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ sub: 'stagiaire-42', role: 'user', debug_note: flag, iat: 1_767_225_600 }));
  // Signed with a throwaway key derived from the seed: the signature is real but irrelevant to the puzzle.
  const signature = createHmac('sha256', seed).update(`${header}.${payload}`).digest('base64url');
  return { token: `${header}.${payload}.${signature}` };
}

export function buildArtifact(kind: ChallengeKind, flag: string, seed: Buffer): Artifact {
  switch (kind) {
    case 'base64-layers':
      return base64Layers(flag, seed);
    case 'xor-single-byte':
      return xorSingleByte(flag, seed);
    case 'http-headers':
      return httpHeaders(flag, seed);
    case 'jwt-claims':
      return jwtClaims(flag, seed);
  }
}
