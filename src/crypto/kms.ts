import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

/**
 * Key Encryption Keys behind one interface (ADR 0019). Envelope encryption (envelope.ts)
 * only ever asks a KMS to wrap, unwrap or re-wrap a small secret (a 32-byte DEK, a TOTP
 * seed) under a *context* that binds it to what it protects (note id, user id). Where the
 * KEK lives is this module's business:
 *
 * - `LocalKms`: the key ring from configuration (ENCRYPTION_KEYS), AES-256-GCM in process.
 *   The KEKs sit in the platform's memory: whoever reads that memory or the secret file
 *   has them.
 * - `VaultTransitKms`: the KEK never leaves Vault (or OpenBao). Bastion sends the DEK and
 *   gets an opaque ciphertext back; a stolen database *and* the platform's files still
 *   need a live, authorised call to Vault, which is logged there and can be revoked.
 * - `CompositeKms`: wraps with the active one, unwraps with whichever owns the key id,
 *   so a database can move from the local ring to Vault with `rotate-keys`.
 */

/** The ciphertext does not authenticate: tampering, a wrong context, or an unknown key. */
export class DecryptionError extends Error {
  constructor() {
    super('Integrity check failed');
    this.name = 'DecryptionError';
  }
}

/**
 * The key service cannot answer (down, sealed, token refused). Kept apart from
 * DecryptionError on purpose: an outage must answer 503, not raise the tampering alert.
 */
export class KmsUnavailable extends Error {
  constructor(reason: string) {
    super(`Key service unavailable: ${reason}`);
    this.name = 'KmsUnavailable';
  }
}

export interface Wrapped {
  keyId: string;
  wrapped: Buffer;
}

export interface WrappedItem extends Wrapped {
  /** What the secret belongs to ("bastion:note-dek:v1:<noteId>"); a different context fails. */
  context: string;
}

export interface Kms {
  /** The key id new wraps get: rows with another one are re-wrapped by rotate-keys. */
  activeKeyId(): Promise<string>;
  owns(keyId: string): boolean;
  wrap(secret: Buffer, context: string): Promise<Wrapped>;
  /** All or nothing, in order: one item that fails integrity fails the call. */
  unwrap(items: readonly WrappedItem[]): Promise<Buffer[]>;
  /** Under the active key. Vault does it without the secret ever leaving it. */
  rewrap(item: WrappedItem): Promise<Wrapped>;
}

/* ------------------------------------------------------------------ local ring */

const IV_LEN = 12; // 96-bit nonce, NIST SP 800-38D
const TAG_LEN = 16;

export interface KeyRing {
  readonly keys: ReadonlyMap<string, Buffer>;
  readonly activeKeyId: string;
}

/**
 * The configured key ring. Byte-compatible with every row written before ADR 0019: the
 * GCM associated data is `<context>:<keyId>`, and the blob is iv || tag || ciphertext.
 */
export class LocalKms implements Kms {
  constructor(private readonly ring: KeyRing) {}

  activeKeyId(): Promise<string> {
    return Promise.resolve(this.ring.activeKeyId);
  }

  owns(keyId: string): boolean {
    return this.ring.keys.has(keyId);
  }

  private key(keyId: string): Buffer {
    const key = this.ring.keys.get(keyId);
    if (!key) throw new DecryptionError();
    return key;
  }

  wrap(secret: Buffer, context: string): Promise<Wrapped> {
    const keyId = this.ring.activeKeyId;
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv('aes-256-gcm', this.key(keyId), iv, { authTagLength: TAG_LEN });
    cipher.setAAD(Buffer.from(`${context}:${keyId}`));
    const ct = Buffer.concat([cipher.update(secret), cipher.final()]);
    return Promise.resolve({ keyId, wrapped: Buffer.concat([iv, cipher.getAuthTag(), ct]) });
  }

  private unwrapOne({ keyId, wrapped, context }: WrappedItem): Buffer {
    if (wrapped.length <= IV_LEN + TAG_LEN) throw new DecryptionError();
    try {
      const decipher = createDecipheriv('aes-256-gcm', this.key(keyId), wrapped.subarray(0, IV_LEN), { authTagLength: TAG_LEN });
      decipher.setAAD(Buffer.from(`${context}:${keyId}`));
      decipher.setAuthTag(wrapped.subarray(IV_LEN, IV_LEN + TAG_LEN));
      return Buffer.concat([decipher.update(wrapped.subarray(IV_LEN + TAG_LEN)), decipher.final()]);
    } catch {
      throw new DecryptionError(); // one error whatever failed: no oracle
    }
  }

  unwrap(items: readonly WrappedItem[]): Promise<Buffer[]> {
    try {
      return Promise.resolve(items.map((i) => this.unwrapOne(i)));
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new DecryptionError());
    }
  }

  async rewrap(item: WrappedItem): Promise<Wrapped> {
    const [secret] = await this.unwrap([item]);
    if (!secret) throw new DecryptionError();
    try {
      return await this.wrap(secret, item.context);
    } finally {
      secret.fill(0);
    }
  }
}

/* ------------------------------------------------------------------ Vault Transit */

/**
 * How Bastion proves itself to Vault. AppRole is the machine login Vault recommends: the
 * role id and secret id are exchanged for a short-lived token (1 h), fetched again when it
 * expires, so no long-lived token sits on disk. A static token is accepted for tests and
 * simple setups.
 */
export type VaultAuth = { token: string } | { roleId: string; secretId: string };

export interface VaultOptions {
  /** https://vault.example:8200 (no trailing slash, no path). */
  addr: string;
  auth: VaultAuth;
  mount: string;
  key: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

const b64 = (s: string | Buffer) => Buffer.from(s).toString('base64');

/** What the key must look like before Bastion trusts it with every DEK. */
interface KeyInfo {
  type?: unknown;
  derived?: unknown;
  exportable?: unknown;
  deletion_allowed?: unknown;
  allow_plaintext_backup?: unknown;
  latest_version?: unknown;
}

/**
 * Vault (or OpenBao) Transit, over its HTTP API with node's fetch: no client library
 * (invariant 11). The key is `derived`: Transit derives a key per context, so the context
 * plays the role the GCM associated data plays locally (a DEK presented with another
 * note's id does not decrypt), and unlike `associated_data` it also works for `rewrap`,
 * which re-encrypts under the newest key version inside Vault: rotation never brings a
 * DEK out.
 *
 * Key ids are `vault:<key>:v<version>`; the stored blob is Vault's own ciphertext
 * (`vault:v<version>:...`), and the two must agree, or the row was tampered with.
 */
export class VaultTransitKms implements Kms {
  private readonly fetch: typeof fetch;
  private readonly prefix: string;
  private token: { value: string; renewAt: number } | null = null;
  private login: Promise<string> | null = null;

  constructor(
    private readonly o: VaultOptions,
    private readonly now: () => number = Date.now,
  ) {
    this.fetch = o.fetch ?? globalThis.fetch;
    this.prefix = `vault:${o.key}:v`;
  }

  /** The current token; with AppRole, a fresh login when there is none or it is about to expire. */
  private async currentToken(): Promise<string> {
    const auth = this.o.auth;
    if ('token' in auth) return auth.token;
    if (this.token && this.now() < this.token.renewAt) return this.token.value;
    // One login in flight at a time: concurrent requests wait for the same token.
    this.login ??= (async () => {
      try {
        const res = await this.send('POST', 'auth/approle/login', { role_id: auth.roleId, secret_id: auth.secretId }, null);
        if (!res.ok) throw new KmsUnavailable(`login refused (HTTP ${String(res.status)})`);
        let value: unknown;
        let ttl: unknown;
        try {
          const json = (await res.json()) as { auth?: { client_token?: unknown; lease_duration?: unknown } };
          value = json.auth?.client_token;
          ttl = json.auth?.lease_duration;
        } catch {
          value = undefined;
        }
        if (typeof value !== 'string' || typeof ttl !== 'number') throw new KmsUnavailable('malformed login answer');
        // Renew at two thirds of the lease: never present a token about to expire.
        this.token = { value, renewAt: this.now() + (ttl * 1000 * 2) / 3 };
        return value;
      } finally {
        this.login = null;
      }
    })();
    return this.login;
  }

  private async send(method: 'GET' | 'POST', path: string, body: unknown, token: string | null): Promise<Response> {
    try {
      return await this.fetch(`${this.o.addr}/v1/${path}`, {
        method,
        headers: { ...(token === null ? {} : { 'X-Vault-Token': token }), 'X-Vault-Request': 'true', 'Content-Type': 'application/json' },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: AbortSignal.timeout(this.o.timeoutMs ?? 5000),
        // A redirect would carry the token (or the secret id) to wherever it points.
        redirect: 'error',
      });
    } catch {
      throw new KmsUnavailable('unreachable');
    }
  }

  owns(keyId: string): boolean {
    return keyId.startsWith(this.prefix);
  }

  /** `kind` decides what a 400 means: bad data on decrypt/rewrap, our own bug on encrypt. */
  private async call(method: 'GET' | 'POST', path: string, body: unknown, kind: 'read' | 'write' | 'decrypt'): Promise<Record<string, unknown>> {
    let res = await this.send(method, path, body, await this.currentToken());
    if (res.status === 403 && 'roleId' in this.o.auth) {
      // The token was revoked or expired early: log in again, once.
      this.token = null;
      res = await this.send(method, path, body, await this.currentToken());
    }
    if (res.status === 400 && kind === 'decrypt') throw new DecryptionError();
    // Never the body: Vault's messages can echo input. The status says enough (403: token, 503: sealed).
    if (!res.ok) throw new KmsUnavailable(`HTTP ${String(res.status)}`);
    try {
      const json = (await res.json()) as { data?: unknown };
      if (typeof json.data !== 'object' || json.data === null) throw new Error('no data');
      return json.data as Record<string, unknown>;
    } catch {
      throw new KmsUnavailable('malformed answer');
    }
  }

  private transit(op: string) {
    return `${this.o.mount}/${op}/${this.o.key}`;
  }

  private keyIdOf(ciphertext: unknown): Wrapped {
    const m = typeof ciphertext === 'string' ? /^vault:v([1-9][0-9]{0,8}):[A-Za-z0-9+/=]+$/.exec(ciphertext) : null;
    if (!m || typeof ciphertext !== 'string') throw new KmsUnavailable('malformed ciphertext');
    return { keyId: `${this.prefix}${m[1] ?? ''}`, wrapped: Buffer.from(ciphertext) };
  }

  /** The stored ciphertext, if and only if it matches its key id. */
  private ciphertextOf({ keyId, wrapped }: WrappedItem): string {
    const version = keyId.startsWith(this.prefix) ? keyId.slice(this.prefix.length) : '';
    const ct = wrapped.toString('utf8');
    if (!/^[1-9][0-9]{0,8}$/.test(version) || !ct.startsWith(`vault:v${version}:`)) throw new DecryptionError();
    return ct;
  }

  /**
   * Boot check, fail closed: the key exists, is derived, cannot be exported, backed up in
   * clear or deleted. A key that could be exported would put every KEK one API call away.
   */
  async check(): Promise<{ latestVersion: number }> {
    const k = (await this.call('GET', `${this.o.mount}/keys/${this.o.key}`, undefined, 'read')) as KeyInfo;
    const problems = [
      k.type !== 'aes256-gcm96' && 'type must be aes256-gcm96',
      k.derived !== true && 'key must be derived (context binding)',
      k.exportable !== false && 'key must not be exportable',
      k.allow_plaintext_backup !== false && 'key must not allow plaintext backup',
      k.deletion_allowed !== false && 'key must not allow deletion',
      typeof k.latest_version !== 'number' && 'no latest_version',
    ].filter((p): p is string => typeof p === 'string');
    if (problems.length > 0) throw new KmsUnavailable(`unsafe Transit key: ${problems.join(', ')}`);
    return { latestVersion: k.latest_version as number };
  }

  async activeKeyId(): Promise<string> {
    return `${this.prefix}${String((await this.check()).latestVersion)}`;
  }

  async wrap(secret: Buffer, context: string): Promise<Wrapped> {
    const data = await this.call('POST', this.transit('encrypt'), { plaintext: b64(secret), context: b64(context) }, 'write');
    return this.keyIdOf(data.ciphertext);
  }

  async unwrap(items: readonly WrappedItem[]): Promise<Buffer[]> {
    if (items.length === 0) return [];
    // One round trip for a page of notes, not one per note.
    const batch = items.map((i) => ({ ciphertext: this.ciphertextOf(i), context: b64(i.context) }));
    const data = await this.call('POST', this.transit('decrypt'), { batch_input: batch }, 'decrypt');
    const results = data.batch_results;
    if (!Array.isArray(results) || results.length !== items.length) throw new KmsUnavailable('malformed answer');
    return results.map((r: unknown) => {
      const { plaintext, error } = (r ?? {}) as { plaintext?: unknown; error?: unknown };
      if ((typeof error === 'string' && error !== '') || typeof plaintext !== 'string') throw new DecryptionError();
      return Buffer.from(plaintext, 'base64');
    });
  }

  async rewrap(item: WrappedItem): Promise<Wrapped> {
    const data = await this.call('POST', this.transit('rewrap'), { ciphertext: this.ciphertextOf(item), context: b64(item.context) }, 'decrypt');
    return this.keyIdOf(data.ciphertext);
  }

  /** A new key version (operator CLI only). Old versions still decrypt until rows are re-wrapped. */
  async rotateKey(): Promise<void> {
    await this.call('POST', `${this.o.mount}/keys/${this.o.key}/rotate`, {}, 'write');
  }
}

/* ------------------------------------------------------------------ composite */

/** Wraps with `active`; unwraps with whichever KMS owns the key id (migration, ADR 0019). */
export class CompositeKms implements Kms {
  constructor(
    private readonly active: Kms,
    private readonly legacy: readonly Kms[],
  ) {}

  private all(): readonly Kms[] {
    return [this.active, ...this.legacy];
  }

  private ownerOf(keyId: string): Kms {
    const owner = this.all().find((k) => k.owns(keyId));
    if (!owner) throw new DecryptionError(); // a key id nobody knows: tampered, or the key was retired
    return owner;
  }

  activeKeyId(): Promise<string> {
    return this.active.activeKeyId();
  }

  owns(keyId: string): boolean {
    return this.all().some((k) => k.owns(keyId));
  }

  wrap(secret: Buffer, context: string): Promise<Wrapped> {
    return this.active.wrap(secret, context);
  }

  async unwrap(items: readonly WrappedItem[]): Promise<Buffer[]> {
    const out = new Array<Buffer>(items.length);
    const byOwner = new Map<Kms, number[]>();
    items.forEach((item, i) => {
      const owner = this.ownerOf(item.keyId);
      byOwner.set(owner, [...(byOwner.get(owner) ?? []), i]);
    });
    for (const [owner, indexes] of byOwner) {
      const plain = await owner.unwrap(indexes.map((i) => items[i] as WrappedItem));
      indexes.forEach((idx, k) => (out[idx] = plain[k] as Buffer));
    }
    return out;
  }

  async rewrap(item: WrappedItem): Promise<Wrapped> {
    const owner = this.ownerOf(item.keyId);
    if (owner === this.active) return this.active.rewrap(item);
    // Moving between KMSs: the secret passes through memory once, then is wiped.
    const [secret] = await owner.unwrap([item]);
    if (!secret) throw new DecryptionError();
    try {
      return await this.active.wrap(secret, item.context);
    } finally {
      secret.fill(0);
    }
  }
}
