import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { createGateway, instanceFromHost } from '../../src/labs/gateway/proxy.js';
import { createLogger } from '../../src/logger.js';
import { createRunnerApp } from '../../src/labs/runner/app.js';
import { dockerSocket, type DockerApi, type DockerResponse } from '../../src/labs/runner/docker.js';
import { httpLabRunner, LabRunnerError } from '../../src/services/lab-service.js';
import { LabImageMissing, LabRunner } from '../../src/labs/runner/runner.js';
import { containerSpec, networkSpec } from '../../src/labs/runner/spec.js';
import { LAB_IDS, MAX_LIMITS } from '../../src/labs/catalog.js';

const ID = 'a'.repeat(32);
const FLAG = `BASTION{${'0'.repeat(32)}}`;
const logger = createLogger('silent');

/** Answers Docker API calls from a script and records them. */
class FakeDocker implements DockerApi {
  calls: string[] = [];
  bodies: unknown[] = [];
  constructor(private readonly answer: (method: string, path: string) => DockerResponse = () => ({ status: 201, body: {} })) {}
  call(method: string, path: string, body?: unknown): Promise<DockerResponse> {
    this.calls.push(`${method} ${path}`);
    this.bodies.push(body);
    return Promise.resolve(this.answer(method, path));
  }
}
const ok = (method: string, path: string): DockerResponse => {
  if (path.endsWith('/start') || method === 'DELETE') return { status: 204, body: null };
  if (path.endsWith('/connect') || path.endsWith('/disconnect')) return { status: 200, body: null };
  return { status: 201, body: {} };
};

describe('lab container spec: the box around an intentionally vulnerable app', () => {
  const spec = containerSpec('sqli-login', ID, FLAG, 1234);

  it('removes privileges, writes and resources an attacker inside the lab would use', () => {
    const h = spec.HostConfig;
    expect(spec.User).toBe('65532:65532');
    expect(h.Privileged).toBe(false);
    expect(h.ReadonlyRootfs).toBe(true);
    expect(h.CapDrop).toEqual(['ALL']);
    expect(h.SecurityOpt).toContain('no-new-privileges:true');
    expect(h.Tmpfs['/tmp']).toMatch(/noexec/);
    expect(h.Memory).toBe(h.MemorySwap); // no swap on top of the memory cap
    expect(h.Memory).toBeLessThanOrEqual(256 * 1024 * 1024);
    expect(h.PidsLimit).toBeGreaterThan(0);
    expect(h.NanoCpus).toBeLessThanOrEqual(1e9);
    expect(h.RestartPolicy).toEqual({ Name: 'no' });
  });

  it('publishes no port, mounts nothing, and joins only its own network', () => {
    const h = spec.HostConfig as Record<string, unknown>;
    expect(h.PortBindings).toEqual({});
    expect(h.Binds).toBeUndefined();
    expect(h.Mounts).toBeUndefined();
    expect(h.NetworkMode).toBe(`bastion-lab-${ID}`);
    expect(Object.keys(spec.NetworkingConfig.EndpointsConfig)).toEqual([`bastion-lab-${ID}`]);
  });

  it('carries the learner\'s flag and nothing else from the platform; the image comes from the catalog', () => {
    expect(spec.Env).toEqual([`FLAG=${FLAG}`]);
    expect(spec.Image).toBe('bastion-lab-sqli-login:local');
  });

  it('per-lab limits come from the catalog and never exceed the hard ceiling', () => {
    for (const lab of LAB_IDS) {
      const h = containerSpec(lab, ID, FLAG, 1).HostConfig;
      expect(h.Memory).toBe(h.MemorySwap);
      expect(h.Memory).toBeLessThanOrEqual(MAX_LIMITS.memoryMiB * 1024 * 1024);
      expect(h.PidsLimit).toBeLessThanOrEqual(MAX_LIMITS.pids);
      expect(h.NanoCpus).toBeLessThanOrEqual(MAX_LIMITS.cpus * 1e9);
      // Whatever the limits, the rest of the box is identical for every lab.
      expect(h).toMatchObject({ ReadonlyRootfs: true, CapDrop: ['ALL'], Privileged: false, PortBindings: {} });
    }
    expect(containerSpec('xss-stored', ID, FLAG, 1).HostConfig.Memory).toBe(512 * 1024 * 1024);
  });

  it('runs under a stronger sandbox when one is configured', () => {
    expect((spec.HostConfig as Record<string, unknown>).Runtime).toBeUndefined();
    expect(containerSpec('sqli-login', ID, FLAG, 1, 'runsc').HostConfig).toMatchObject({ Runtime: 'runsc' });
  });

  it('gives each instance a network with no route out', () => {
    expect(networkSpec(ID, 1)).toMatchObject({ Name: `bastion-lab-${ID}`, Internal: true, Driver: 'bridge' });
  });
});

describe('lab runner', () => {
  it('creates network, container, gateway link, then starts, in that order', async () => {
    const docker = new FakeDocker(ok);
    await new LabRunner(docker, 'gw', logger, undefined, () => 1000).start({ instanceId: ID, lab: 'idor-invoices', flag: FLAG, ttlSeconds: 60 });
    expect(docker.calls).toEqual([
      'POST /networks/create',
      `POST /containers/create?name=bastion-lab-${ID}`,
      `POST /networks/bastion-lab-${ID}/connect`,
      `POST /containers/bastion-lab-${ID}/start`,
    ]);
    expect(docker.bodies[2]).toEqual({ Container: 'gw' });
    expect((docker.bodies[0] as { Labels: Record<string, string> }).Labels['bastion.lab.expires']).toBe('61000');
  });

  it('a missing image is reported, and the half-created instance is removed', async () => {
    const docker = new FakeDocker((m, p) => (p.startsWith('/containers/create') ? { status: 404, body: { message: 'No such image' } } : ok(m, p)));
    await expect(new LabRunner(docker, 'gw', logger).start({ instanceId: ID, lab: 'sqli-login', flag: FLAG, ttlSeconds: 60 })).rejects.toBeInstanceOf(
      LabImageMissing,
    );
    expect(docker.calls).toContain(`DELETE /containers/bastion-lab-${ID}?force=true&v=true`);
    expect(docker.calls).toContain(`DELETE /networks/bastion-lab-${ID}`);
  });

  it('stop is idempotent: already-gone objects are fine', async () => {
    const docker = new FakeDocker(() => ({ status: 404, body: null }));
    await expect(new LabRunner(docker, 'gw', logger).stop(ID)).resolves.toBeUndefined();
  });

  it('the reaper removes expired instances only, and ignores objects with forged ids', async () => {
    const expired = 'b'.repeat(32);
    const listing = [
      { Labels: { 'bastion.lab.instance': expired, 'bastion.lab.expires': '500' } },
      { Labels: { 'bastion.lab.instance': ID, 'bastion.lab.expires': '5000' } },
      { Labels: { 'bastion.lab.instance': '../../etc', 'bastion.lab.expires': '1' } },
    ];
    const docker = new FakeDocker((m, p) => (m === 'GET' ? { status: 200, body: listing } : ok(m, p)));
    expect(await new LabRunner(docker, 'gw', logger, undefined, () => 1000).reap()).toBe(1);
    expect(docker.calls.filter((c) => c.startsWith('DELETE /containers'))).toEqual([`DELETE /containers/bastion-lab-${expired}?force=true&v=true`]);
    // The live instance keeps its gateway link (re-attached after a stack restart).
    expect(docker.calls).toContain(`POST /networks/bastion-lab-${ID}/connect`);
    expect(docker.calls).not.toContain(`POST /networks/bastion-lab-${expired}/connect`);
  });

  it('a reap during a start does not attach the gateway first and make the start fail', async () => {
    // A Docker that behaves like the real one: a created network is listed, and a second attach answers 403.
    const networks = new Set<string>();
    const attached = new Set<string>();
    const docker = new FakeDocker((m, p) => {
      if (m === 'POST' && p === '/networks/create') networks.add(`bastion-lab-${ID}`);
      if (m === 'GET') return { status: 200, body: p.startsWith('/networks') ? [...networks].map(() => ({ Labels: { 'bastion.lab.instance': ID, 'bastion.lab.expires': '5000' } })) : [] };
      const net = /^\/networks\/([^/]+)\/connect$/.exec(p)?.[1];
      if (net) {
        if (attached.has(net)) return { status: 403, body: { message: 'endpoint with name gw already exists in network' } };
        attached.add(net);
      }
      return ok(m, p);
    });
    const runner = new LabRunner(docker, 'gw', logger, undefined, () => 1000);
    // The periodic reap is already listing networks when the start creates one: it sees it and attaches the gateway.
    const reap = runner.reap();
    const start = runner.start({ instanceId: ID, lab: 'sqli-login', flag: FLAG, ttlSeconds: 60 });
    await expect(start).resolves.toEqual({ expiresAt: 61_000 });
    await reap;
    expect(docker.calls).not.toContain(`DELETE /containers/bastion-lab-${ID}?force=true&v=true`);
  });
});

describe('lab runner API', () => {
  const token = randomBytes(32);
  const auth = { Authorization: `Bearer ${token.toString('base64')}` };
  const api = (docker = new FakeDocker(ok)) => ({ docker, http: request(createRunnerApp(new LabRunner(docker, 'gw', logger), token, logger)) });
  const body = { instanceId: ID, lab: 'sqli-login', flag: FLAG, ttlSeconds: 600 };

  it('refuses every request without the exact token', async () => {
    const { http, docker } = api();
    await http.post('/instances').send(body).expect(401);
    await http.post('/instances').set({ Authorization: 'Bearer nope' }).send(body).expect(401);
    await http.delete(`/instances/${ID}`).expect(401);
    expect(docker.calls).toEqual([]);
    await http.get('/healthz').expect(200);
  });

  it('accepts only a closed lab id, a hex instance id, a flag and a bounded TTL: no image, command or mount', async () => {
    const { http, docker } = api();
    for (const bad of [
      { ...body, image: 'alpine' },
      { ...body, lab: 'docker-socket' },
      { ...body, instanceId: '../x' },
      { ...body, flag: 'anything' },
      { ...body, ttlSeconds: 999_999 },
      { ...body, cmd: ['sh'] },
    ]) {
      await http.post('/instances').set(auth).send(bad).expect(400);
    }
    await http.post('/instances').set(auth).set('content-type', 'application/json').send('{not json').expect(400);
    await http.delete('/instances/..%2F..%2Fetc').set(auth).expect(400);
    expect(docker.calls).toEqual([]);
    await http.post('/instances').set(auth).send(body).expect(201);
    await http.delete(`/instances/${ID}`).set(auth).expect(204);
  });

  it('maps Docker failures to generic codes', async () => {
    const missing = api(new FakeDocker((m, p) => (p.startsWith('/containers/create') ? { status: 404, body: {} } : ok(m, p))));
    await missing.http.post('/instances').set(auth).send(body).expect(503, { error: 'lab_image_missing' });
    const taken = api(new FakeDocker((m, p) => (p === '/networks/create' ? { status: 409, body: {} } : ok(m, p))));
    await taken.http.post('/instances').set(auth).send(body).expect(409, { error: 'already_running' });
    const broken = api(new FakeDocker(() => ({ status: 500, body: { message: 'internal detail' } })));
    const res = await broken.http.post('/instances').set(auth).send(body).expect(502);
    expect(JSON.stringify(res.body)).not.toMatch(/internal detail/);
    await broken.http.delete(`/instances/${ID}`).set(auth).expect(502);
    await broken.http.get('/nope').set(auth).expect(404);
  });
});

describe('platform → runner, over real HTTP', () => {
  let server: Server | undefined;
  afterEach(() => {
    server?.close();
  });

  const serve = async (docker: FakeDocker, token: Buffer) => {
    server = createServer(createRunnerApp(new LabRunner(docker, 'gw', logger), token, logger));
    await new Promise<void>((resolve) => {
      server?.listen(0, '127.0.0.1', resolve);
    });
    return `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
  };
  const req = { instanceId: ID, lab: 'sqli-login' as const, flag: FLAG, ttlSeconds: 600 };

  it('the shared token opens the runner, any other token does not', async () => {
    const token = randomBytes(32);
    const docker = new FakeDocker(ok);
    const url = await serve(docker, token);
    await httpLabRunner(url, token).start(req);
    await httpLabRunner(url, token).stop(ID);
    expect(docker.calls[0]).toBe('POST /networks/create');
    await expect(httpLabRunner(url, randomBytes(32)).start(req)).rejects.toMatchObject({ status: 401, code: 'unauthorized' });
  });

  it('runner errors reach the platform as codes, never as Docker messages', async () => {
    const token = randomBytes(32);
    const url = await serve(new FakeDocker((m, p) => (p.startsWith('/containers/create') ? { status: 404, body: {} } : ok(m, p))), token);
    await expect(httpLabRunner(url, token).start(req)).rejects.toEqual(new LabRunnerError(503, 'lab_image_missing'));
    await expect(httpLabRunner('http://127.0.0.1:9', token, 2000).start(req)).rejects.toThrow();
  });
});

describe('docker socket client', () => {
  let server: Server | undefined;
  afterEach(() => {
    server?.close();
  });

  it('speaks the versioned Engine API over a local socket and parses JSON or text', async () => {
    const path = process.platform === 'win32' ? `\\\\.\\pipe\\bastion-test-${randomBytes(4).toString('hex')}` : join(tmpdir(), `bastion-${randomBytes(4).toString('hex')}.sock`);
    const seen: string[] = [];
    server = createServer((req, res) => {
      let body = '';
      req.on('data', (c: Buffer) => (body += c.toString()));
      req.on('end', () => {
        seen.push(`${req.method ?? ''} ${req.url ?? ''} ${body}`);
        if (req.url?.endsWith('/text')) res.end('OK');
        else res.writeHead(201, { 'content-type': 'application/json' }).end('{"Id":"abc"}');
      });
    });
    await new Promise<void>((resolve) => {
      server?.listen(path, resolve);
    });
    const docker = dockerSocket(path);
    expect(await docker.call('POST', '/containers/create', { Image: 'x' })).toEqual({ status: 201, body: { Id: 'abc' } });
    expect(await docker.call('GET', '/text')).toEqual({ status: 200, body: 'OK' });
    expect(seen[0]).toBe('POST /v1.44/containers/create {"Image":"x"}');
  });
});

describe('lab gateway', () => {
  it('answers its own health probe, on a non-lab host only', async () => {
    await request(createGateway()).get('/healthz').expect(200, { status: 'ok' });
  });

  let upstream: Server | undefined;
  let gateway: Server | undefined;
  afterEach(() => {
    upstream?.close();
    gateway?.close();
  });

  it('routes only l<32 hex>.lab.localhost, whatever else the Host header says', () => {
    expect(instanceFromHost(`l${ID}.lab.localhost:8088`)).toBe(ID);
    expect(instanceFromHost(`L${ID.toUpperCase()}.LAB.LOCALHOST`)).toBe(ID);
    for (const host of [undefined, '', 'lab.localhost', `l${ID}.lab.localhost.evil.test`, `l${ID}x.lab.localhost`, 'metadata.google.internal', '169.254.169.254', `x.l${ID}.lab.localhost`]) {
      expect(instanceFromHost(host)).toBeNull();
    }
  });

  const listen = (s: Server) =>
    new Promise<number>((resolve) => {
      s.listen(0, '127.0.0.1', () => {
        resolve((s.address() as AddressInfo).port);
      });
    });

  it('proxies to the instance it computed, and fails closed otherwise', async () => {
    upstream = createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'x-lab': 'yes' });
      res.end(JSON.stringify({ path: req.url, method: req.method, connection: req.headers.connection ?? null }));
    });
    const upPort = await listen(upstream);
    const seen: string[] = [];
    gateway = createGateway((id) => {
      seen.push(id);
      return { host: '127.0.0.1', port: upPort };
    });
    const gw = request(gateway);
    const res = await gw.get('/api/x?y=1').set('Host', `l${ID}.lab.localhost:8088`).expect(200);
    expect(res.body).toMatchObject({ path: '/api/x?y=1', method: 'GET' });
    expect(res.headers['x-lab']).toBe('yes');
    expect(seen).toEqual([ID]);

    await gw.get('/').set('Host', '169.254.169.254').expect(404);
    expect(seen).toEqual([ID]);
  });

  it('answers 502 when the lab is stopped', async () => {
    const closed = createServer();
    const port = await listen(closed);
    closed.close();
    gateway = createGateway(() => ({ host: '127.0.0.1', port }));
    const res = await request(gateway).get('/').set('Host', `l${ID}.lab.localhost`).expect(502);
    expect(res.text).toMatch(/Lab indisponible/);
  });
});
