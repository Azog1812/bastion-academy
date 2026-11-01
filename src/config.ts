import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { z } from 'zod';

/**
 * Configuration is read once, validated, and frozen.
 * The service refuses to start ("fail closed") if a secret is missing,
 * too short, or obviously a placeholder — a misconfigured security
 * control must never silently degrade to an insecure default.
 */

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const VAULT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * A secret key: standard base64 of random bytes. Placeholders are recognised by
 * what makes them placeholders, not by words: searching random base64 for
 * "xxxx" or "secret" rejects about one real key in 25,000 (it did, in CI).
 * - "change-me-…" and other typed values are not strict base64;
 * - base64 of a repeated word ("secretsecret…") decodes to a handful of distinct
 *   bytes, where 32 random bytes have about 30.
 */
export const base64Key = (minBytes: number) =>
  z
    .string()
    .refine((v) => BASE64.test(v) && v.length % 4 === 0, 'must be standard base64 of random bytes (node dist/cli.js gen-secrets)')
    .transform((v, ctx) => {
      const buf = Buffer.from(v, 'base64');
      if (buf.length < minBytes) {
        ctx.addIssue({ code: 'custom', message: `must decode to at least ${minBytes} bytes` });
        return z.NEVER;
      }
      if (new Set(buf).size < 16) {
        ctx.addIssue({ code: 'custom', message: 'looks like a placeholder or low-entropy value, not random bytes' });
        return z.NEVER;
      }
      return buf;
    });

/** "v1:<base64>,v2:<base64>" → Map(keyId → 32-byte key). Enables key rotation. */
const keyRing = z.string().transform((raw, ctx) => {
  const ring = new Map<string, Buffer>();
  for (const entry of raw.split(',').map((s) => s.trim()).filter(Boolean)) {
    const [id, material] = entry.split(':');
    if (!id || !material || !/^[a-z0-9]{1,16}$/i.test(id)) {
      ctx.addIssue({ code: 'custom', message: `invalid key entry "${id ?? ''}"` });
      return z.NEVER;
    }
    const key = Buffer.from(material, 'base64');
    if (key.length !== 32) {
      ctx.addIssue({ code: 'custom', message: `key "${id}" must be exactly 32 bytes (AES-256)` });
      return z.NEVER;
    }
    ring.set(id, key);
  }
  if (ring.size === 0) {
    ctx.addIssue({ code: 'custom', message: 'at least one encryption key is required' });
    return z.NEVER;
  }
  return ring;
});

const schema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('production'),
    HOST: z.string().default('0.0.0.0'),
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
    TRUST_PROXY: z.coerce.number().int().min(0).max(5).default(0),
    DATABASE_PATH: z.string().default('./data/bastion.db'),

    JWT_SECRET: base64Key(32),
    JWT_ISSUER: z.string().min(1).default('bastion'),
    JWT_AUDIENCE: z.string().min(1).default('bastion-api'),
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
    REFRESH_TOKEN_TTL_SECONDS: z.coerce.number().int().min(3600).max(2_592_000).default(604_800),

    /** HMAC key for the tamper-evident audit chain. Kept apart from every other key. */
    AUDIT_HMAC_KEY: base64Key(32),

    /** Derives each learner's challenge flags. A leak lets someone compute every flag, nothing more: kept apart for that reason. */
    FLAG_HMAC_KEY: base64Key(32),

    /**
     * Where the KEKs live (ADR 0019). `local`: the key ring below, in this process.
     * `vault`: Vault/OpenBao Transit; the key ring then only opens rows written before
     * the move, until `rotate-keys` has re-wrapped them.
     */
    KMS_PROVIDER: z.enum(['local', 'vault']).default('local'),
    ENCRYPTION_KEYS: keyRing.optional(),
    ACTIVE_KEY_ID: z.string().min(1).optional(),
    VAULT_ADDR: z
      .url({ protocol: /^https?$/ })
      .transform((v) => v.replace(/\/+$/, ''))
      .optional(),
    /** AppRole (preferred): exchanged for 1-hour tokens whose policy covers one Transit key (deploy/vault). */
    // Vault's ids are UUID-shaped random values without an RFC 4122 version: shape only.
    VAULT_ROLE_ID: z.string().regex(VAULT_ID, 'must be a Vault AppRole id').optional(),
    VAULT_SECRET_ID: z.string().regex(VAULT_ID, 'must be a Vault AppRole id').optional(),
    /** Or a static token, for tests and simple setups. */
    VAULT_TOKEN: z
      .string()
      .min(20)
      .max(512)
      .regex(/^[A-Za-z0-9._-]+$/, 'must be a Vault token')
      .optional(),
    VAULT_TRANSIT_MOUNT: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/).default('transit'),
    VAULT_TRANSIT_KEY: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/).default('bastion-kek'),

    /** log2(N) for scrypt. OWASP minimum is N=2^17 (r=8, p=1). Lowered only in tests. */
    SCRYPT_LOG_N: z.coerce.number().int().min(10).max(20).default(17),
    /** Requests per client IP per 15 minutes. Raised only for automated DAST runs. */
    RATE_LIMIT_GLOBAL: z.coerce.number().int().min(1).default(300),
    RATE_LIMIT_AUTH: z.coerce.number().int().min(1).default(10),
    RATE_LIMIT_REFRESH: z.coerce.number().int().min(1).default(30),
    RATE_LIMIT_QUIZ: z.coerce.number().int().min(1).default(30),
    /** Issuer shown in authenticator apps next to the account name. */
    MFA_ISSUER: z.string().min(1).max(40).default('Bastion Academy'),

    /**
     * Passkeys (ADR 0016). The RP ID binds every credential: a passkey made for
     * "localhost" signs nothing for another site. Origins are matched exactly against
     * what the browser writes into the signed client data. WebAuthn refuses IP
     * addresses as RP ID: open the platform at http://localhost:3000, not 127.0.0.1.
     */
    WEBAUTHN_RP_ID: z
      .string()
      .refine((v) => isIP(v) === 0, 'an IP address cannot be an RP ID')
      // Label by label (RFC 1123): no scheme, port, path or empty label.
      .refine((v) => v.length <= 253 && v.split('.').every((l) => /^[a-z0-9-]{1,63}$/.test(l) && !l.startsWith('-') && !l.endsWith('-')), 'must be a host name (no scheme, port or IP address)')
      .default('localhost'),
    WEBAUTHN_ORIGINS: z
      .string()
      .default('http://localhost:3000')
      .transform((v) => v.split(',').map((o) => o.trim()).filter(Boolean)),
    MAX_FAILED_LOGINS: z.coerce.number().int().min(3).max(20).default(5),

    /**
     * Labs (ADR 0009). Off unless a runner is configured: the platform itself never
     * talks to Docker, it asks the lab runner, the only component with that power.
     */
    LAB_RUNNER_URL: z.url({ protocol: /^https?$/ }).optional(),
    LAB_RUNNER_TOKEN: base64Key(32).optional(),
    /** A lab instance is destroyed after this, whatever happens (also enforced by the runner). */
    LAB_TTL_SECONDS: z.coerce.number().int().min(300).max(14_400).default(7200),
    /** Port of the lab gateway on 127.0.0.1, used to build each lab's URL. */
    LAB_GATEWAY_PORT: z.coerce.number().int().min(1).max(65535).default(8088),
    /** Lab starts per account per 15 minutes: each start creates containers and networks. */
    RATE_LIMIT_LAB: z.coerce.number().int().min(1).default(10),
    LOCKOUT_SECONDS: z.coerce.number().int().min(60).max(86_400).default(900),

    /**
     * Prometheus metrics (ADR 0011). Off unless a port is set; served on their own
     * listener, never on the API port, and only to a bearer of METRICS_TOKEN.
     */
    METRICS_PORT: z.coerce.number().int().min(1).max(65535).optional(),
    METRICS_HOST: z.string().default('127.0.0.1'),
    METRICS_TOKEN: base64Key(32).optional(),

    /**
     * Copy of the audit log for a SIEM (ADR 0015): one JSON line per entry, appended to
     * this file (mode 0600) for Wazuh's logcollector. Off unless set.
     */
    AUDIT_EXPORT_FILE: z.string().min(1).optional(),
  })
  .superRefine((cfg, ctx) => {
    if (cfg.KMS_PROVIDER === 'local' && !cfg.ENCRYPTION_KEYS) {
      ctx.addIssue({ code: 'custom', path: ['ENCRYPTION_KEYS'], message: 'is required with KMS_PROVIDER=local' });
    }
    if (cfg.ENCRYPTION_KEYS && (!cfg.ACTIVE_KEY_ID || !cfg.ENCRYPTION_KEYS.has(cfg.ACTIVE_KEY_ID))) {
      ctx.addIssue({ code: 'custom', path: ['ACTIVE_KEY_ID'], message: 'must reference a key in ENCRYPTION_KEYS' });
    }
    if (cfg.KMS_PROVIDER === 'vault') {
      if (!cfg.VAULT_ADDR) ctx.addIssue({ code: 'custom', path: ['VAULT_ADDR'], message: 'is required with KMS_PROVIDER=vault' });
      const approle = cfg.VAULT_ROLE_ID !== undefined || cfg.VAULT_SECRET_ID !== undefined;
      if (approle && (!cfg.VAULT_ROLE_ID || !cfg.VAULT_SECRET_ID)) {
        ctx.addIssue({ code: 'custom', path: ['VAULT_SECRET_ID'], message: 'AppRole needs both VAULT_ROLE_ID and VAULT_SECRET_ID' });
      }
      if (approle === (cfg.VAULT_TOKEN !== undefined)) {
        ctx.addIssue({ code: 'custom', path: ['VAULT_TOKEN'], message: 'set either VAULT_TOKEN or VAULT_ROLE_ID + VAULT_SECRET_ID with KMS_PROVIDER=vault' });
      }
      const url = cfg.VAULT_ADDR ? new URL(cfg.VAULT_ADDR) : undefined;
      // The token and every DEK cross this link. Plain http only to a single-label host (a
      // container name on a private network, as for the lab runner), never across a network.
      if (url && cfg.NODE_ENV === 'production' && url.protocol === 'http:' && url.hostname.includes('.')) {
        ctx.addIssue({ code: 'custom', path: ['VAULT_ADDR'], message: 'must be https, except to a container name on a private network' });
      }
      if (url && (url.pathname !== '/' || url.search !== '' || url.username !== '')) {
        ctx.addIssue({ code: 'custom', path: ['VAULT_ADDR'], message: 'scheme://host[:port] only' });
      }
    }
    for (const origin of cfg.WEBAUTHN_ORIGINS) {
      let url: URL | undefined;
      try {
        url = new URL(origin);
      } catch {
        url = undefined;
      }
      const host = url?.hostname ?? '';
      const ok =
        url !== undefined &&
        url.origin === origin &&
        (url.protocol === 'https:' || (url.protocol === 'http:' && host === 'localhost')) &&
        (host === cfg.WEBAUTHN_RP_ID || host.endsWith(`.${cfg.WEBAUTHN_RP_ID}`));
      if (!ok) {
        ctx.addIssue({
          code: 'custom',
          path: ['WEBAUTHN_ORIGINS'],
          message: `${origin}: an exact origin (scheme://host[:port]), https except on localhost, inside the RP ID ${cfg.WEBAUTHN_RP_ID}`,
        });
      }
    }
    if (cfg.LAB_RUNNER_URL !== undefined && !cfg.LAB_RUNNER_TOKEN) {
      ctx.addIssue({ code: 'custom', path: ['LAB_RUNNER_TOKEN'], message: 'is required when LAB_RUNNER_URL is set' });
    }
    if (cfg.METRICS_PORT !== undefined && !cfg.METRICS_TOKEN) {
      ctx.addIssue({ code: 'custom', path: ['METRICS_TOKEN'], message: 'is required when METRICS_PORT is set' });
    }
    if (cfg.METRICS_PORT === cfg.PORT) {
      ctx.addIssue({ code: 'custom', path: ['METRICS_PORT'], message: 'must differ from PORT: metrics never share the API listener' });
    }
    if (cfg.NODE_ENV === 'production' && cfg.SCRYPT_LOG_N < 17) {
      ctx.addIssue({ code: 'custom', path: ['SCRYPT_LOG_N'], message: 'must be >= 17 in production' });
    }
  });

export type Config = Readonly<z.output<typeof schema>>;

const FILE_SECRETS = ['JWT_SECRET', 'AUDIT_HMAC_KEY', 'FLAG_HMAC_KEY', 'ENCRYPTION_KEYS', 'LAB_RUNNER_TOKEN', 'METRICS_TOKEN', 'VAULT_TOKEN', 'VAULT_ROLE_ID', 'VAULT_SECRET_ID'] as const;

/**
 * Secrets can be provided as files (`JWT_SECRET_FILE=/run/secrets/jwt`), the
 * Docker/Kubernetes secrets convention. Files are preferable to environment
 * variables, which leak through /proc/<pid>/environ, crash dumps, child
 * processes and debug endpoints.
 */
export function resolveFileSecrets(
  env: NodeJS.ProcessEnv,
  read: (path: string) => string,
  names: readonly string[] = FILE_SECRETS,
): NodeJS.ProcessEnv {
  const out = { ...env };
  for (const name of names) {
    const path = env[`${name}_FILE`];
    if (!path) continue;
    if (env[name]) throw new Error(`Invalid configuration, refusing to start:\n  - ${name}: set either ${name} or ${name}_FILE, not both`);
    try {
      out[name] = read(path).trim();
    } catch {
      throw new Error(`Invalid configuration, refusing to start:\n  - ${name}_FILE: cannot read secret file`);
    }
  }
  return out;
}

export function loadConfig(
  env: NodeJS.ProcessEnv = process.env,
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- path comes from operator config
  read: (path: string) => string = (path) => readFileSync(path, 'utf8'),
): Config {
  const parsed = schema.safeParse(resolveFileSecrets(env, read));
  if (!parsed.success) {
    // Report which variables are wrong, never their values.
    const problems = parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid configuration, refusing to start:\n${problems}`);
  }
  return Object.freeze(parsed.data);
}
