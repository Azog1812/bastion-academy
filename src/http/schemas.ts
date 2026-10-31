import { z } from 'zod';
import { slug } from '../curriculum/catalog.js';
import { PASSWORD_MAX } from '../security/password-policy.js';

/**
 * Every schema is `.strict()`: unknown fields are rejected, not ignored.
 * That closes mass-assignment attacks (OWASP API3:2023), e.g. sending
 * `"role": "admin"` alongside a registration payload.
 */

const email = z
  .string()
  .trim()
  .toLowerCase()
  .max(254)
  .pipe(z.email({ message: 'must be a valid e-mail address' }));

// Upper bound checked before hashing: a 10 MB "password" must not reach scrypt (DoS).
const password = z.string().min(1).max(PASSWORD_MAX * 4);

export const credentialsSchema = z.object({ email, password }).strict();

export const refreshSchema = z.object({ refreshToken: z.string().min(20).max(200) }).strict();

export const changePasswordSchema = z
  .object({ currentPassword: password, newPassword: password })
  .strict();

const noteContent = {
  title: z.string().trim().min(1).max(200),
  body: z.string().max(65_536),
};

export const createNoteSchema = z.object(noteContent).strict();

export const updateNoteSchema = z
  .object({ ...noteContent, version: z.number().int().positive() })
  .strict();

export const noteIdSchema = z.object({ id: z.uuid() }).strict();

export const lessonIdSchema = z.object({ id: slug }).strict();
export const moduleIdSchema = z.object({ id: slug }).strict();
export const environmentIdSchema = z.object({ id: slug }).strict();
export const moduleChoiceSchema = z.object({ added: z.boolean() }).strict();

export const completeLessonSchema = z
  .object({
    answers: z
      .array(z.object({ question: slug, choices: z.array(z.number().int().min(0).max(5)).max(6) }).strict())
      .max(20)
      .default([]),
  })
  .strict();

export const paginationSchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(100).default(20),
    offset: z.coerce.number().int().min(0).max(100_000).default(0),
  })
  .strict();

export const auditQuerySchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(500).default(100),
    before: z.coerce.number().int().positive().optional(),
  })
  .strict();

export const challengeIdSchema = z.object({ id: slug }).strict();

export const submitFlagSchema = z.object({ flag: z.string().trim().min(1).max(100) }).strict();

/** The rule itself is validated against the challenge's dataset fields by the service (ADR 0010). */
/** A JSON rule (ADR 0010) or the XML text of Wazuh rules (ADR 0014); the service checks which one the challenge takes. */
export const detectSchema = z.object({ rule: z.union([z.record(z.string(), z.unknown()), z.string().min(1).max(8000)]) }).strict();

/** Letters, digits, space, dash, underscore; no leading/trailing space. Rendered with textContent anyway. */
export const profileSchema = z
  .object({
    displayName: z
      .string()
      .trim()
      .min(3)
      .max(24)
      .regex(/^[\p{L}\p{N} _-]+$/u, 'letters, digits, spaces, "-" and "_" only')
      .refine((v) => !v.includes('  '), 'no double spaces')
      .nullable(),
  })
  .strict();

export const reauthSchema = z.object({ password }).strict();

const otp = z.string().trim().min(6).max(19);

export const mfaCodeSchema = z.object({ code: otp }).strict();

export const mfaDisableSchema = z.object({ password, code: otp }).strict();

const mfaToken = z.string().min(20).max(100);

/* Passkeys (ADR 0016): exactly the fields the page sends, base64url, each bounded before decoding. */
const b64url = (max: number) => z.string().min(1).max(max).regex(/^[A-Za-z0-9_-]+$/, 'base64url');

const assertionSchema = z
  .object({
    id: b64url(1400),
    type: z.literal('public-key'),
    response: z.object({ clientDataJSON: b64url(4096), authenticatorData: b64url(4096), signature: b64url(1400) }).strict(),
  })
  .strict();

export const passkeyCredentialSchema = z
  .object({
    id: b64url(1400),
    type: z.literal('public-key'),
    response: z.object({ clientDataJSON: b64url(4096), attestationObject: b64url(12_000) }).strict(),
  })
  .strict();

export const mfaLoginSchema = z.union([
  z.object({ mfaToken, code: otp }).strict(),
  z.object({ mfaToken, passkey: assertionSchema }).strict(),
]);

export const passkeyOptionsLoginSchema = z.object({ mfaToken }).strict();

export const passkeyRegisterSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(1)
      .max(40)
      .regex(/^[\p{L}\p{N} ._'-]+$/u, 'letters, digits, spaces and . _ \' - only'),
    credential: passkeyCredentialSchema,
  })
  .strict();

/** The code is needed only to remove the last second factor (then it is a recovery code). */
export const passkeyDeleteSchema = z.object({ password, code: otp.optional() }).strict();

export const passkeyIdSchema = z.object({ id: z.uuid() }).strict();
