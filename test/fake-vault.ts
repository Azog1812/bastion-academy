import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * A Vault Transit stand-in for tests (ADR 0019): the endpoints Bastion calls, with the
 * behaviour checked against the real Vault (test/vault-real): derived keys (a wrong
 * context fails), versioned ciphertexts `vault:vN:`, batch decrypt with per-item errors,
 * rewrap, 400 on bad data, 403 on a bad token. Tests switch it to "sealed", make it
 * redirect, or loosen the key to play a misconfigured or hostile key service.
 */
export class FakeVault {
  readonly token = `hvs.${randomBytes(18).toString('base64url')}`;
  /** AppRole credentials; each login issues a new token valid for `leaseSeconds`. */
  readonly roleId = '6a1f6b2e-1111-4c4c-8d8d-0123456789ab';
  readonly secretId = '9b2e7c3d-2222-4d4d-9e9e-ba9876543210';
  leaseSeconds = 3600;
  logins = 0;
  private issued = new Set<string>();
  private versions: Buffer[] = [randomBytes(32)];
  calls: string[] = [];
  sealed = false;
  redirectTo: string | null = null;
  key: Record<string, unknown> = { type: 'aes256-gcm96', derived: true, exportable: false, allow_plaintext_backup: false, deletion_allowed: false };
  private server: Server | null = null;
  url = '';

  /** Every token issued by AppRole stops working (revocation, or expiry). */
  revokeIssued(): void {
    this.issued.clear();
  }

  rotate(): void {
    this.versions.push(randomBytes(32));
  }

  private derived(version: number, context: Buffer): Buffer {
    const k = this.versions[version - 1];
    if (!k) throw new Error('no such version');
    return createHmac('sha256', k).update(context).digest();
  }

  private encrypt(plaintext: Buffer, context: Buffer, version = this.versions.length): string {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', this.derived(version, context), iv, { authTagLength: 16 });
    const ct = Buffer.concat([c.update(plaintext), c.final()]);
    return `vault:v${String(version)}:${Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64')}`;
  }

  private decrypt(ciphertext: string, context: Buffer): Buffer {
    const m = /^vault:v(\d+):(.+)$/.exec(ciphertext);
    if (!m) throw new Error('invalid ciphertext');
    const raw = Buffer.from(m[2] ?? '', 'base64');
    const d = createDecipheriv('aes-256-gcm', this.derived(Number(m[1]), context), raw.subarray(0, 12), { authTagLength: 16 });
    d.setAuthTag(raw.subarray(12, 28));
    return Buffer.concat([d.update(raw.subarray(28)), d.final()]);
  }

  private async body(req: IncomingMessage): Promise<Record<string, unknown>> {
    let raw = '';
    for await (const chunk of req) raw += String(chunk);
    return raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
  }

  async start(): Promise<string> {
    this.server = createServer((req, res) => {
      void (async () => {
        const send = (status: number, payload: unknown) => res.writeHead(status, { 'Content-Type': 'application/json' }).end(JSON.stringify(payload));
        const path = req.url ?? '';
        this.calls.push(`${req.method ?? ''} ${path}`);
        if (this.redirectTo) {
          res.writeHead(307, { Location: `${this.redirectTo}${path}` }).end();
          return;
        }
        if (this.sealed) return send(503, { errors: ['Vault is sealed'] });
        const b = await this.body(req);
        if (path === '/v1/auth/approle/login') {
          if (b.role_id !== this.roleId || b.secret_id !== this.secretId) return send(400, { errors: ['invalid role or secret ID'] });
          this.logins++;
          const issued = `hvs.${randomBytes(18).toString('base64url')}`;
          this.issued.add(issued);
          return send(200, { auth: { client_token: issued, lease_duration: this.leaseSeconds } });
        }
        const presented = String(req.headers['x-vault-token'] ?? '');
        if (presented !== this.token && !this.issued.has(presented)) return send(403, { errors: ['permission denied'] });
        const ctx = (v: unknown) => Buffer.from(typeof v === 'string' ? v : '', 'base64');
        try {
          if (req.method === 'GET' && path === '/v1/transit/keys/bastion-kek') {
            return send(200, { data: { ...this.key, latest_version: this.versions.length } });
          }
          if (path === '/v1/transit/encrypt/bastion-kek') {
            return send(200, { data: { ciphertext: this.encrypt(Buffer.from(String(b.plaintext), 'base64'), ctx(b.context)) } });
          }
          if (path === '/v1/transit/decrypt/bastion-kek') {
            const items = (b.batch_input ?? []) as { ciphertext: string; context: string }[];
            const results = items.map((i) => {
              try {
                return { plaintext: this.decrypt(i.ciphertext, ctx(i.context)).toString('base64') };
              } catch {
                return { plaintext: '', error: 'cipher: message authentication failed' };
              }
            });
            if (results.every((r) => r.error)) return send(400, { errors: ['cipher: message authentication failed'] });
            return send(200, { data: { batch_results: results } });
          }
          if (path === '/v1/transit/rewrap/bastion-kek') {
            const plain = this.decrypt(String(b.ciphertext), ctx(b.context));
            return send(200, { data: { ciphertext: this.encrypt(plain, ctx(b.context)) } });
          }
          if (path === '/v1/transit/keys/bastion-kek/rotate') {
            this.rotate();
            return send(200, { data: {} });
          }
          return send(404, { errors: [] });
        } catch {
          return send(400, { errors: ['cipher: message authentication failed'] });
        }
      })();
    });
    await new Promise<void>((r) => this.server?.listen(0, '127.0.0.1', r));
    this.url = `http://127.0.0.1:${String((this.server.address() as AddressInfo).port)}`;
    return this.url;
  }

  async stop(): Promise<void> {
    await new Promise<void>((r) => this.server?.close(() => { r(); }));
  }
}
