import { COMMON_PASSWORDS } from './common-passwords.js';

/**
 * Password policy aligned with NIST SP 800-63B §5.1.1 and OWASP ASVS v4 §2.1:
 *  - length is what matters: 12 to 128 characters, every Unicode character allowed;
 *  - no arbitrary composition rules ("1 uppercase, 1 symbol…"), which push users
 *    toward predictable patterns such as "Password1!";
 *  - reject known-breached / very common passwords and context-specific ones.
 */
export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 128;

export function passwordProblem(password: string, email: string): string | null {
  // NIST 800-63B counts each Unicode code point as one character (not UTF-16 units).
  // eslint-disable-next-line @typescript-eslint/no-misused-spread -- code points are exactly what we want here
  const length = [...password].length;
  if (length < PASSWORD_MIN) return `must be at least ${PASSWORD_MIN} characters`;
  if (length > PASSWORD_MAX) return `must be at most ${PASSWORD_MAX} characters`;

  const lowered = password.toLowerCase();
  if (COMMON_PASSWORDS.has(lowered)) return 'is too common, it appears in public breach lists';
  if (/^(.)\1+$/u.test(password)) return 'must not be a single repeated character';

  const localPart = email.split('@')[0]?.toLowerCase() ?? '';
  if (localPart.length >= 4 && lowered.includes(localPart)) return 'must not contain your e-mail address';
  if (/bastion/i.test(password)) return 'must not contain the service name';
  return null;
}
