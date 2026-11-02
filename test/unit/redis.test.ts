import { createServer, type AddressInfo, type Server, type Socket } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { encodeCommand, parseReply, RedisClient, RedisReplyError, RedisUnavailable } from '../../src/redis.js';

/**
 * The in-house RESP client (ADR 0023). The parser must hold against a hostile or broken
 * server (or a man in the middle on a plain link): bounded sizes, bounded nesting, no
 * reply nobody asked for.
 */
describe('RESP parser', () => {
  const parse = (s: string) => parseReply(Buffer.from(s, 'latin1'));

  it('reads every RESP2 type, and waits for incomplete replies', () => {
    expect(parse('+OK\r\n')).toEqual({ value: 'OK', next: 5 });
    expect(parse(':42\r\n')?.value).toBe(42);
    expect(parse('$5\r\nhello\r\n')?.value).toBe('hello');
    expect(parse('$-1\r\n')?.value).toBeNull();
    expect(parse('*2\r\n:1\r\n:250\r\n')?.value).toEqual([1, 250]);
    expect(parse('-ERR nope\r\n')?.value).toBeInstanceOf(RedisReplyError);
    expect(parse('$5\r\nhel')).toBeNull();
    expect(parse('*2\r\n:1\r\n')).toBeNull();
    expect(parse(':4')).toBeNull();
  });

  it('refuses what would cost memory or stack, and what it does not speak', () => {
    expect(() => parse('$999999999\r\n')).toThrow(/too large/);
    expect(() => parse('*100000\r\n')).toThrow(/too large/);
    expect(() => parse('*1\r\n'.repeat(10) + ':1\r\n')).toThrow(/too deep/);
    expect(() => parse(`+${'a'.repeat(2000)}`)).toThrow(/line too long/);
    expect(() => parse(':12x\r\n')).toThrow(/bad integer/);
    expect(() => parse(':99999999999999999\r\n')).toThrow(/out of range/);
    expect(() => parse('$3\r\nabcde\r\n')).toThrow(/terminator/);
    expect(() => parse('%1\r\n')).toThrow(/unexpected reply type/); // a RESP3 map
  });

  it('length-prefixes every argument, so none can smuggle a second command', () => {
    const cmd = encodeCommand(['GET', 'k\r\n*1\r\n$8\r\nFLUSHALL\r\n']).toString('latin1');
    expect(cmd.startsWith('*2\r\n$3\r\nGET\r\n$21\r\n')).toBe(true);
    expect(encodeCommand(['SET', 'é']).toString('latin1')).toContain('$2\r\n'); // bytes, not characters
  });
});

describe('RESP client', () => {
  let server: Server | undefined;
  afterEach(() => {
    server?.close();
    server = undefined;
  });

  /** A fake server: `reply` decides what goes back for each command received. */
  const fake = async (reply: (args: string[], socket: Socket) => string | null) => {
    const seen: string[][] = [];
    const connections = { count: 0 };
    server = createServer((socket) => {
      connections.count++;
      socket.on('error', () => undefined); // the client may reset the connection: that is the point
      let buf = Buffer.alloc(0);
      socket.on('data', (chunk: Buffer) => {
        buf = Buffer.concat([buf, chunk]);
        for (;;) {
          const parsed = parseReply(buf);
          if (parsed === null) break;
          buf = buf.subarray(parsed.next);
          const args = parsed.value as string[];
          seen.push(args);
          const out = reply(args, socket);
          if (out !== null) socket.write(out);
        }
      });
    });
    await new Promise<void>((resolve) => server?.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    return { port, seen, connections };
  };

  it('authenticates with the ACL user of the URL before anything else', async () => {
    const { port, seen } = await fake((args) => (args[0] === 'AUTH' ? '+OK\r\n' : '+PONG\r\n'));
    const c = new RedisClient(`redis://bastion:s%40cret@127.0.0.1:${String(port)}`);
    expect(await c.command(['PING'])).toBe('PONG');
    expect(seen[0]).toEqual(['AUTH', 'bastion', 's@cret']);
    c.close();
  });

  it('refuses to go on when authentication fails', async () => {
    const { port } = await fake((args) => (args[0] === 'AUTH' ? '-WRONGPASS invalid username-password pair\r\n' : '+PONG\r\n'));
    const c = new RedisClient(`redis://bastion:bad@127.0.0.1:${String(port)}`);
    await expect(c.command(['PING'])).rejects.toBeInstanceOf(RedisUnavailable);
    c.close();
  });

  it('gives error replies to the caller and keeps the connection', async () => {
    const { port } = await fake((args) => (args[0] === 'GET' ? '-NOPERM no\r\n' : '+PONG\r\n'));
    const c = new RedisClient(`redis://127.0.0.1:${String(port)}`);
    await expect(c.command(['GET', 'x'])).rejects.toBeInstanceOf(RedisReplyError);
    expect(await c.command(['PING'])).toBe('PONG');
    c.close();
  });

  it('breaks the connection on a slow reply, fails fast, then reconnects', async () => {
    let silent = true;
    const { port } = await fake(() => (silent ? null : '+PONG\r\n'));
    const c = new RedisClient(`redis://127.0.0.1:${String(port)}`, { timeoutMs: 50, retryAfterMs: 100 });
    await expect(c.command(['PING'])).rejects.toThrow(/timeout/);
    silent = false;
    // Within retryAfterMs: no reconnection storm, an immediate failure.
    await expect(c.command(['PING'])).rejects.toThrow(/retrying shortly/);
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(await c.command(['PING'])).toBe('PONG');
    c.close();
  });

  it('drops the connection on a reply nobody asked for', async () => {
    const { port, connections } = await fake(() => '+PONG\r\n+EXTRA\r\n');
    const c = new RedisClient(`redis://127.0.0.1:${String(port)}`, { retryAfterMs: 0 });
    expect(await c.command(['PING'])).toBe('PONG');
    // The extra reply desynchronised the stream: the next command needs a new connection.
    expect(await c.command(['PING'])).toBe('PONG');
    expect(connections.count).toBe(2);
    c.close();
  });

  it('stops buffering a reply that grows past the cap', async () => {
    // 1024 strings of 512 KiB each are allowed one by one, not 512 MiB in total.
    const chunk = `$${String(512 * 1024)}\r\n${'x'.repeat(512 * 1024)}\r\n`;
    const { port } = await fake(() => `*1024\r\n${chunk.repeat(5)}`);
    const c = new RedisClient(`redis://127.0.0.1:${String(port)}`);
    await expect(c.command(['PING'])).rejects.toThrow(/reply too large/);
    c.close();
  });

  it('rejects everything pending when the server goes away', async () => {
    const { port } = await fake((_args, socket) => {
      socket.destroy();
      return null;
    });
    const c = new RedisClient(`redis://127.0.0.1:${String(port)}`);
    await expect(Promise.all([c.command(['PING']), c.command(['PING'])])).rejects.toBeInstanceOf(RedisUnavailable);
    c.close();
  });

  it('refuses another scheme', () => {
    expect(() => new RedisClient('http://127.0.0.1:6379')).toThrow(/redis:\/\//);
  });
});
