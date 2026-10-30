import { readFileSync } from 'node:fs';
import { z } from 'zod';

/**
 * Configuration is read once, validated, and frozen.
 * The service refuses to start ("fail closed") if a secret is missing,
 * too short, or obviously a placeholder — a misconfigured security
 * control must never silently degrade to an insecure default.
 */

const PLACEHOLDER = /change[-_ ]?me|example|secret|password|xxxx/i;

const base64Key = (minBytes: number) =>
  z
    .string()
    .refine((v) => !PLACEHOLDER.test(v), 'looks like a placeholder value')
    .transform((v, ctx) => {
      const buf = Buffer.from(v, 'base64');
      if (buf.length < minBytes) {
        ctx.addIssue({ code: 'custom', message: `must decode to at least ${minBytes} bytes` });
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

    ENCRYPTION_KEYS: keyRing,
    ACTIVE_KEY_ID: z.string().min(1),

    /** log2(N) for scrypt. OWASP minimum is N=2^17 (r=8, p=1). Lowered only in tests. */
    SCRYPT_LOG_N: z.coerce.number().int().min(10).max(20).default(17),
    /** Requests per client IP per 15 minutes. Raised only for automated DAST runs. */
    RATE_LIMIT_GLOBAL: z.coerce.number().int().min(1).default(300),
    RATE_LIMIT_AUTH: z.coerce.number().int().min(1).default(10),
    RATE_LIMIT_REFRESH: z.coerce.number().int().min(1).default(30),
    RATE_LIMIT_QUIZ: z.coerce.number().int().min(1).default(30),
    /** Issuer shown in authenticator apps next to the account name. */
    MFA_ISSUER: z.string().min(1).max(40).default('Bastion Academy'),
    MAX_FAILED_LOGINS: z.coerce.number().int().min(3).max(20).default(5),
    LOCKOUT_SECONDS: z.coerce.number().int().min(60).max(86_400).default(900),
  })
  .superRefine((cfg, ctx) => {
    if (!cfg.ENCRYPTION_KEYS.has(cfg.ACTIVE_KEY_ID)) {
      ctx.addIssue({ code: 'custom', path: ['ACTIVE_KEY_ID'], message: 'must reference a key in ENCRYPTION_KEYS' });
    }
    if (cfg.NODE_ENV === 'production' && cfg.SCRYPT_LOG_N < 17) {
      ctx.addIssue({ code: 'custom', path: ['SCRYPT_LOG_N'], message: 'must be >= 17 in production' });
    }
  });

export type Config = Readonly<z.output<typeof schema>>;

const FILE_SECRETS = ['JWT_SECRET', 'AUDIT_HMAC_KEY', 'FLAG_HMAC_KEY', 'ENCRYPTION_KEYS'] as const;

/**
 * Secrets can be provided as files (`JWT_SECRET_FILE=/run/secrets/jwt`), the
 * Docker/Kubernetes secrets convention. Files are preferable to environment
 * variables, which leak through /proc/<pid>/environ, crash dumps, child
 * processes and debug endpoints.
 */
function resolveFileSecrets(env: NodeJS.ProcessEnv, read: (path: string) => string): NodeJS.ProcessEnv {
  const out = { ...env };
  for (const name of FILE_SECRETS) {
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
