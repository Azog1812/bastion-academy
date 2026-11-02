import { connect as tcpConnect, type Socket } from 'node:net';
import { connect as tlsConnect } from 'node:tls';

/**
 * A minimal Redis (RESP2) client on node:net (ADR 0023). Bastion needs a handful of
 * commands (AUTH, EVAL, DEL, PING) for its shared rate-limit counters; a full client
 * library would add a dependency tree for that (invariant 11).
 *
 * Replies are parsed with hard bounds: a server that misbehaves, or a man in the middle on
 * a plain connection, cannot make this process allocate without limit or recurse deeply.
 * Commands are length-prefixed bulk strings, so no argument can inject a second command.
 */

/** An error reply from the server (`-ERR …`): the command reached Redis and was refused. */
export class RedisReplyError extends Error {
  override readonly name = 'RedisReplyError';
}

/** Redis could not be reached, timed out, or broke the protocol. */
export class RedisUnavailable extends Error {
  override readonly name = 'RedisUnavailable';
}

export type RespValue = string | number | null | RedisReplyError | RespValue[];

const MAX_BULK = 512 * 1024;
const MAX_ARRAY = 1024;
const MAX_DEPTH = 4;
const MAX_LINE = 1024;
/** Unparsed bytes kept while waiting for the rest of a reply. */
const MAX_BUFFER = 2 * 1024 * 1024;

type Parsed = { value: RespValue; next: number } | null;

function line(buf: Buffer, pos: number): { text: string; next: number } | null {
  const end = buf.indexOf('\r\n', pos, 'latin1');
  if (end === -1) {
    if (buf.length - pos > MAX_LINE) throw new RedisUnavailable('protocol: line too long');
    return null;
  }
  if (end - pos > MAX_LINE) throw new RedisUnavailable('protocol: line too long');
  return { text: buf.toString('latin1', pos, end), next: end + 2 };
}

function integer(text: string): number {
  if (!/^-?\d{1,18}$/.test(text)) throw new RedisUnavailable('protocol: bad integer');
  const n = Number(text);
  if (!Number.isSafeInteger(n)) throw new RedisUnavailable('protocol: integer out of range');
  return n;
}

/** One RESP2 value at `pos`, or null if the buffer does not hold all of it yet. Exported for tests. */
export function parseReply(buf: Buffer, pos = 0, depth = 0): Parsed {
  if (pos >= buf.length) return null;
  if (depth > MAX_DEPTH) throw new RedisUnavailable('protocol: nesting too deep');
  const type = String.fromCharCode(buf[pos] ?? 0);
  const head = line(buf, pos + 1);
  if (head === null) return null;
  switch (type) {
    case '+':
      return { value: head.text, next: head.next };
    case '-':
      return { value: new RedisReplyError(head.text), next: head.next };
    case ':':
      return { value: integer(head.text), next: head.next };
    case '$': {
      const len = integer(head.text);
      if (len === -1) return { value: null, next: head.next };
      if (len < 0 || len > MAX_BULK) throw new RedisUnavailable('protocol: bulk string too large');
      if (buf.length < head.next + len + 2) return null;
      if (buf[head.next + len] !== 0x0d || buf[head.next + len + 1] !== 0x0a) throw new RedisUnavailable('protocol: bad bulk terminator');
      return { value: buf.toString('utf8', head.next, head.next + len), next: head.next + len + 2 };
    }
    case '*': {
      const count = integer(head.text);
      if (count === -1) return { value: null, next: head.next };
      if (count < 0 || count > MAX_ARRAY) throw new RedisUnavailable('protocol: array too large');
      const items: RespValue[] = [];
      let next = head.next;
      for (let i = 0; i < count; i++) {
        const item = parseReply(buf, next, depth + 1);
        if (item === null) return null;
        items.push(item.value);
        next = item.next;
      }
      return { value: items, next };
    }
    default:
      // RESP3 types are never asked for (no HELLO 3): anything else is a protocol error.
      throw new RedisUnavailable('protocol: unexpected reply type');
  }
}

/** A command as RESP: an array of length-prefixed bulk strings. Exported for tests. */
export function encodeCommand(args: readonly (string | number)[]): Buffer {
  const parts: Buffer[] = [Buffer.from(`*${String(args.length)}\r\n`)];
  for (const arg of args) {
    const b = Buffer.from(String(arg), 'utf8');
    parts.push(Buffer.from(`$${String(b.length)}\r\n`), b, Buffer.from('\r\n'));
  }
  return Buffer.concat(parts);
}

interface Pending {
  resolve: (v: RespValue) => void;
  reject: (e: Error) => void;
}

export interface RedisOptions {
  /** A reply slower than this breaks the connection (pipelined replies would desynchronise). */
  timeoutMs?: number;
  /** Commands waiting for a reply, at most: beyond, new ones fail at once. */
  maxPending?: number;
  /** After a failure, commands fail fast for this long instead of reconnecting at every call. */
  retryAfterMs?: number;
}

export class RedisClient {
  private socket: Socket | null = null;
  private connecting: Promise<void> | null = null;
  private buffer: Buffer = Buffer.alloc(0);
  private readonly pending: Pending[] = [];
  private timer: NodeJS.Timeout | null = null;
  private failedAt = 0;
  private closed = false;
  private readonly url: URL;
  private readonly timeoutMs: number;
  private readonly maxPending: number;
  private readonly retryAfterMs: number;

  constructor(url: string, options: RedisOptions = {}) {
    this.url = new URL(url);
    if (this.url.protocol !== 'redis:' && this.url.protocol !== 'rediss:') throw new Error('REDIS_URL must be redis:// or rediss://');
    this.timeoutMs = options.timeoutMs ?? 1000;
    this.maxPending = options.maxPending ?? 10_000;
    this.retryAfterMs = options.retryAfterMs ?? 1000;
  }

  async command(args: readonly (string | number)[]): Promise<RespValue> {
    if (this.closed) throw new RedisUnavailable('client closed');
    if (this.pending.length >= this.maxPending) throw new RedisUnavailable('too many pending commands');
    await this.connected();
    const reply = await this.send(args);
    if (reply instanceof RedisReplyError) throw reply;
    return reply;
  }

  close(): void {
    this.closed = true;
    this.fail(new RedisUnavailable('client closed'));
  }

  private send(args: readonly (string | number)[]): Promise<RespValue> {
    const socket = this.socket;
    if (socket === null) return Promise.reject(new RedisUnavailable('not connected'));
    return new Promise<RespValue>((resolve, reject) => {
      this.pending.push({ resolve, reject });
      this.arm();
      socket.write(encodeCommand(args));
    });
  }

  private connected(): Promise<void> {
    if (this.socket !== null) return Promise.resolve();
    if (this.connecting !== null) return this.connecting;
    if (Date.now() - this.failedAt < this.retryAfterMs) return Promise.reject(new RedisUnavailable('redis unavailable (retrying shortly)'));
    this.connecting = this.open().finally(() => {
      this.connecting = null;
    });
    return this.connecting;
  }

  private async open(): Promise<void> {
    const host = this.url.hostname.replace(/^\[|\]$/g, '');
    const port = Number(this.url.port || 6379);
    const socket = await new Promise<Socket>((resolve, reject) => {
      const s =
        this.url.protocol === 'rediss:'
          ? // Certificate and host name verified (Node's defaults); a private CA via NODE_EXTRA_CA_CERTS.
            tlsConnect({ host, port, servername: host })
          : tcpConnect({ host, port });
      const timer = setTimeout(() => {
        s.destroy();
        reject(new RedisUnavailable('connect timeout'));
      }, this.timeoutMs);
      s.once(this.url.protocol === 'rediss:' ? 'secureConnect' : 'connect', () => {
        clearTimeout(timer);
        resolve(s);
      });
      s.once('error', (err: Error) => {
        clearTimeout(timer);
        reject(new RedisUnavailable(`connect failed: ${err.message}`));
      });
    }).catch((err: unknown) => {
      this.failedAt = Date.now();
      throw err;
    });
    socket.setNoDelay(true);
    socket.on('data', (chunk: Buffer) => {
      this.onData(chunk);
    });
    socket.on('error', () => {
      this.fail(new RedisUnavailable('connection error'));
    });
    socket.on('close', () => {
      this.fail(new RedisUnavailable('connection closed'));
    });
    this.socket = socket;
    this.buffer = Buffer.alloc(0);

    // ACL user and password from the URL (redis://user:password@host). Sent before any
    // other command; a refusal closes the connection.
    const user = decodeURIComponent(this.url.username);
    const password = decodeURIComponent(this.url.password);
    try {
      if (password.length > 0) {
        const auth = await this.send(user !== '' ? ['AUTH', user, password] : ['AUTH', password]);
        if (auth instanceof RedisReplyError) throw new RedisUnavailable('authentication refused');
      }
      const db = this.url.pathname.replace(/^\//, '');
      if (db !== '') {
        if (!/^\d{1,2}$/.test(db)) throw new RedisUnavailable('bad database number');
        const selected = await this.send(['SELECT', db]);
        if (selected instanceof RedisReplyError) throw new RedisUnavailable('database selection refused');
      }
    } catch (err) {
      this.fail(err instanceof Error ? err : new RedisUnavailable('handshake failed'));
      throw err;
    }
  }

  private onData(chunk: Buffer): void {
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length > MAX_BUFFER) {
      this.fail(new RedisUnavailable('protocol: reply too large'));
      return;
    }
    try {
      let pos = 0;
      for (;;) {
        const parsed = parseReply(this.buffer, pos);
        if (parsed === null) break;
        pos = parsed.next;
        const waiter = this.pending.shift();
        // A reply nobody asked for: the stream cannot be trusted any more.
        if (waiter === undefined) throw new RedisUnavailable('protocol: unsolicited reply');
        waiter.resolve(parsed.value);
      }
      this.buffer = this.buffer.subarray(pos);
      this.arm();
    } catch (err) {
      this.fail(err instanceof Error ? err : new RedisUnavailable('protocol error'));
    }
  }

  /** One timer for the oldest pending command; replies arrive in order. */
  private arm(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    if (this.pending.length === 0) return;
    this.timer = setTimeout(() => {
      this.fail(new RedisUnavailable('reply timeout'));
    }, this.timeoutMs);
    this.timer.unref();
  }

  private fail(err: Error): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    const socket = this.socket;
    this.socket = null;
    if (socket !== null) {
      this.failedAt = Date.now();
      socket.destroy();
    }
    this.buffer = Buffer.alloc(0);
    for (const p of this.pending.splice(0)) p.reject(err instanceof RedisUnavailable ? err : new RedisUnavailable(err.message));
  }
}
