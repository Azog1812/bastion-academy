import { randomBytes, randomInt } from 'node:crypto';
import { AuditLog } from './audit.js';
import { loadConfig } from './config.js';
import { openDatabase } from './db.js';
import { MfaService } from './services/mfa-service.js';
import { NoteService } from './services/note-service.js';
import { recoverAccount } from './services/recovery.js';

/**
 * Operator CLI. Privileged actions (granting admin, rotating keys) are
 * deliberately NOT exposed over HTTP: they require shell access to the
 * host, which is a separate, stronger trust boundary.
 *
 *   node dist/cli.js gen-secrets
 *   node dist/cli.js promote <email>
 *   node dist/cli.js rotate-keys
 *   node dist/cli.js recover-account <email>
 *   node dist/cli.js verify-audit
 */

const [command, arg] = process.argv.slice(2);
const b64 = (n: number) => randomBytes(n).toString('base64');

/**
 * A password for the Wazuh stack. Wazuh's policy asks for upper case, lower case, a
 * digit and a symbol; 24 random characters from 64 give ~144 bits. Symbols are limited
 * to "." and "-", which survive YAML, shell and URL contexts without escaping.
 */
function wazuhPassword(): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-';
  for (;;) {
    const p = Array.from({ length: 24 }, () => alphabet.charAt(randomInt(alphabet.length))).join('');
    if (/[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p) && /[.-]/.test(p)) return p;
  }
}

async function main(): Promise<number> {
  if (command === 'gen-secrets') {
    process.stdout.write(
      [
        `JWT_SECRET=${b64(32)}`,
        `AUDIT_HMAC_KEY=${b64(32)}`,
        `FLAG_HMAC_KEY=${b64(32)}`,
        `LAB_RUNNER_TOKEN=${b64(32)}`,
        `METRICS_TOKEN=${b64(32)}`,
        `WAZUH_ADMIN_PASSWORD=${wazuhPassword()}`,
        `WAZUH_DASHBOARD_PASSWORD=${wazuhPassword()}`,
        `WAZUH_API_PASSWORD=${wazuhPassword()}`,
        `ENCRYPTION_KEYS=k1:${b64(32)}`,
        'ACTIVE_KEY_ID=k1',
        '',
      ].join('\n'),
    );
    return 0;
  }

  const config = loadConfig();
  const db = openDatabase(config.DATABASE_PATH);
  const audit = new AuditLog(db, config.AUDIT_HMAC_KEY);

  switch (command) {
    case 'promote': {
      if (!arg) throw new Error('usage: promote <email>');
      const res = db.prepare("UPDATE users SET role = 'admin', token_version = token_version + 1 WHERE email = ?").run(arg);
      if (Number(res.changes) !== 1) throw new Error('no such user');
      audit.record({ action: 'admin.promote', outcome: 'success', target: arg, details: { via: 'cli' } });
      console.log(`${arg} is now admin (existing sessions revoked, log in again)`);
      return 0;
    }
    case 'rotate-keys': {
      const ring = { keys: config.ENCRYPTION_KEYS, activeKeyId: config.ACTIVE_KEY_ID };
      const { rewrapped } = new NoteService(db, ring, audit).rotateKeys();
      const resealed = new MfaService(db, ring, audit, config.MFA_ISSUER).rotateKeys();
      audit.record({ action: 'admin.key_rotation', outcome: 'success', details: { activeKeyId: config.ACTIVE_KEY_ID, rewrapped, resealed } });
      console.log(`re-wrapped ${rewrapped} data keys and ${resealed} MFA secrets under ${config.ACTIVE_KEY_ID}; old keys can now be retired`);
      return 0;
    }
    case 'recover-account': {
      if (!arg) throw new Error('usage: recover-account <email>');
      const { temporaryPassword } = await recoverAccount(db, audit, arg, config.SCRYPT_LOG_N);
      console.log(`${arg}: second factors and sessions removed. Temporary password (shown once, change it at first login):`);
      console.log(temporaryPassword);
      return 0;
    }
    case 'verify-audit': {
      const result = audit.verify();
      console.log(JSON.stringify(result));
      return result.valid ? 0 : 2;
    }
    default:
      console.error('commands: gen-secrets | promote <email> | rotate-keys | recover-account <email> | verify-audit');
      return 64;
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    console.error(err instanceof Error ? err.message : err);
    process.exitCode = 1;
  },
);
