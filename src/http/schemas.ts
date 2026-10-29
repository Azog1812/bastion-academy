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
