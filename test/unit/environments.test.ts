import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { ENVIRONMENTS } from '../../src/labs/environments.js';
import { createRunnerApp } from '../../src/labs/runner/app.js';
import type { DockerApi, DockerResponse } from '../../src/labs/runner/docker.js';
import { EnvironmentController, EnvironmentMissing } from '../../src/labs/runner/environments.js';
import { LabRunner } from '../../src/labs/runner/runner.js';
import { createLogger } from '../../src/logger.js';
import { httpLabRunner, LabRunnerError } from '../../src/services/lab-service.js';

const logger = createLogger('silent');
const [INDEXER, MANAGER, DASHBOARD] = ENVIRONMENTS.wazuh.containers;
const T0 = Date.parse('2026-10-31T10:00:00Z');

type Container = { running: boolean; health?: string; startedAt?: string } | 'absent';

/** A Docker engine holding the three Wazuh containers, in the given states. */
class FakeEngine implements DockerApi {
  calls: string[] = [];
  constructor(readonly containers: Record<string, Container>) {}
  call(method: string, path: string): Promise<DockerResponse> {
    this.calls.push(`${method} ${path}`);
    const m = /^\/containers\/([^/]+)\/(json|start|stop)/.exec(path);
    const c = m?.[1] === undefined ? undefined : this.containers[m[1]];
    if (!m || c === undefined || c === 'absent') return Promise.resolve({ status: 404, body: { message: 'No such container' } });
    if (m[2] === 'json') {
      return Promise.resolve({
        status: 200,
        body: { State: { Running: c.running, StartedAt: c.startedAt ?? '0001-01-01T00:00:00Z', ...(c.health ? { Health: { Status: c.health } } : {}) } },
      });
    }
    const wanted = m[2] === 'start';
    const status = c.running === wanted ? 304 : 204;
    c.running = wanted;
    return Promise.resolve({ status, body: null });
  }
}

const all = (c: Container): Record<string, Container> =>
  Object.fromEntries(ENVIRONMENTS.wazuh.containers.map((n) => [n, typeof c === 'string' ? c : { ...c }]));

describe('environment controller (runner side, ADR 0013)', () => {
  it('reports missing, stopped, starting and running from the containers', async () => {
    const st = (containers: Record<string, Container>) => new EnvironmentController(new FakeEngine(containers), logger).status('wazuh');
    expect(await st(all('absent'))).toEqual({ state: 'missing', startedAt: null });
    expect(await st({ ...all({ running: false }), [DASHBOARD as string]: 'absent' })).toMatchObject({ state: 'missing' });
    expect(await st(all({ running: false }))).toEqual({ state: 'stopped', startedAt: null });
    expect(await st({ ...all({ running: true, health: 'healthy', startedAt: '2026-10-31T10:00:05Z' }), [DASHBOARD as string]: { running: true, health: 'starting', startedAt: '2026-10-31T10:00:00Z' } })).toEqual({
      state: 'starting',
      startedAt: T0,
    });
    expect(await st(all({ running: true, health: 'healthy', startedAt: '2026-10-31T10:00:00Z' }))).toEqual({ state: 'running', startedAt: T0 });
    // No healthcheck at all counts as ready.
    expect(await st(all({ running: true }))).toMatchObject({ state: 'running' });
  });

  it('starts in catalog order and stops in reverse, by fixed name only: never creates anything', async () => {
    const engine = new FakeEngine(all({ running: false }));
    const env = new EnvironmentController(engine, logger);
    await env.start('wazuh');
    await env.stop('wazuh');
    const actions = engine.calls.filter((c) => !c.endsWith('/json'));
    expect(actions).toEqual([
      `POST /containers/${INDEXER as string}/start`,
      `POST /containers/${MANAGER as string}/start`,
      `POST /containers/${DASHBOARD as string}/start`,
      `POST /containers/${DASHBOARD as string}/stop?t=10`,
      `POST /containers/${MANAGER as string}/stop?t=10`,
      `POST /containers/${INDEXER as string}/stop?t=10`,
    ]);
    expect(engine.calls.every((c) => /^(GET|POST) \/containers\/bastion-wazuh-(indexer|manager|dashboard)\/(json|start|stop\?t=10)$/.test(c))).toBe(true);
  });

  it('is idempotent, and refuses to start what is not installed', async () => {
    const env = new EnvironmentController(new FakeEngine(all({ running: true })), logger);
    await expect(env.start('wazuh')).resolves.toMatchObject({ state: 'running' }); // 304 everywhere
    await env.stop('wazuh');
    await env.stop('wazuh'); // already stopped: 304
    await expect(new EnvironmentController(new FakeEngine(all('absent')), logger).start('wazuh')).rejects.toBeInstanceOf(EnvironmentMissing);
    await expect(new EnvironmentController(new FakeEngine(all('absent')), logger).stop('wazuh')).resolves.toBeUndefined();
  });

  it('stops an environment left running past its limit, and only that', async () => {
    const limit = ENVIRONMENTS.wazuh.maxRunSeconds * 1000;
    const running = () => all({ running: true, health: 'healthy', startedAt: new Date(T0).toISOString() });
    const young = new FakeEngine(running());
    expect(await new EnvironmentController(young, logger, () => T0 + limit - 1000).reap()).toBe(0);
    expect(young.calls.some((c) => c.includes('/stop'))).toBe(false);
    const old = new FakeEngine(running());
    expect(await new EnvironmentController(old, logger, () => T0 + limit + 1000).reap()).toBe(1);
    expect(Object.values(old.containers).every((c) => c !== 'absent' && !c.running)).toBe(true);
    // Not installed or stopped: nothing to do.
    expect(await new EnvironmentController(new FakeEngine(all('absent')), logger, () => T0 + limit * 2).reap()).toBe(0);
  });

  it('surfaces Docker failures instead of guessing, and the reaper survives them', async () => {
    const broken: DockerApi = { call: () => Promise.resolve({ status: 500, body: null }) };
    const env = new EnvironmentController(broken, logger);
    await expect(env.status('wazuh')).rejects.toThrow(/inspect failed/);
    await expect(env.start('wazuh')).rejects.toThrow(/start failed/);
    await expect(env.stop('wazuh')).rejects.toThrow(/stop failed/);
    await expect(env.reap()).resolves.toBe(0);
  });
});

describe('environment API of the runner', () => {
  const token = randomBytes(32);
  const auth = { Authorization: `Bearer ${token.toString('base64')}` };
  const api = (engine: DockerApi) => request(createRunnerApp(new LabRunner(engine, 'gw', logger), token, logger, new EnvironmentController(engine, logger)));

  it('needs the token and a catalog id', async () => {
    const engine = new FakeEngine(all({ running: false }));
    await api(engine).post('/environments/wazuh/start').expect(401);
    await api(engine).post('/environments/elastic/start').set(auth).expect(404);
    await api(engine).post('/environments/..%2F..%2Fcontainers/start').set(auth).expect(404);
    expect(engine.calls).toEqual([]);
  });

  it('starts, reports and stops; a missing installation answers 503, a Docker error 502', async () => {
    const engine = new FakeEngine(all({ running: false }));
    await api(engine).get('/environments/wazuh').set(auth).expect(200, { state: 'stopped', startedAt: null });
    await api(engine).post('/environments/wazuh/start').set(auth).expect(202);
    await api(engine).post('/environments/wazuh/stop').set(auth).expect(204);
    await api(new FakeEngine(all('absent'))).post('/environments/wazuh/start').set(auth).expect(503, { error: 'environment_missing' });
    const broken: DockerApi = { call: () => Promise.resolve({ status: 500, body: null }) };
    await api(broken).get('/environments/wazuh').set(auth).expect(502, { error: 'environment_failed' });
    await api(broken).post('/environments/wazuh/stop').set(auth).expect(502);
  });
});

describe('platform → runner environment client, over real HTTP', () => {
  let server: Server | undefined;
  afterEach(() => {
    server?.close();
    server = undefined;
  });

  it('keeps only the expected fields of the answer and maps errors', async () => {
    const token = randomBytes(32);
    const engine = new FakeEngine(all({ running: false }));
    server = createServer(createRunnerApp(new LabRunner(engine, 'gw', logger), token, logger, new EnvironmentController(engine, logger)));
    await new Promise<void>((resolve) => {
      server?.listen(0, '127.0.0.1', resolve);
    });
    const url = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
    const client = httpLabRunner(url, token);
    await expect(client.environmentStatus('wazuh')).resolves.toEqual({ state: 'stopped', startedAt: null });
    await expect(client.startEnvironment('wazuh')).resolves.toMatchObject({ state: 'running' });
    await expect(client.stopEnvironment('wazuh')).resolves.toBeUndefined();
    await expect(httpLabRunner(url, randomBytes(32)).environmentStatus('wazuh')).rejects.toBeInstanceOf(LabRunnerError);
  });
});
