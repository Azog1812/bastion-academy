import { describe, expect, it } from 'vitest';
import { buildCurriculum } from '../../src/curriculum/catalog.js';
import type { EnvironmentId } from '../../src/labs/environments.js';
import type { EnvironmentRunnerClient, EnvironmentStatus } from '../../src/services/environment-service.js';
import { LabRunnerError } from '../../src/services/lab-service.js';
import { auditActions, newUser, setup, type Session, type TestContext } from '../helpers.js';

/** basics (mandatory) -> wazuh (optional, with the real Wazuh environment). */
const curriculum = buildCurriculum({
  index: { levels: [{ level: 1, title: 'L1', goal: 'g' }], paths: ['p'] },
  path: () => ({
    id: 'p',
    title: 'P',
    summary: 's',
    level: 1,
    modules: [
      { id: 'basics', title: 'B', summary: 's', lessons: [{ id: 'intro', title: 'Intro', minutes: 5 }] },
      { id: 'wazuh', title: 'W', summary: 's', prerequisites: ['basics'], optional: true, lessons: [{ id: 'w1', title: 'W1', minutes: 5 }] },
    ],
  }),
  body: () => '# body',
});

/** The runner as the platform sees it: records calls, answers like the real one. */
class FakeRunner implements EnvironmentRunnerClient {
  calls: string[] = [];
  state: EnvironmentStatus = { state: 'stopped', startedAt: null };
  failWith: LabRunnerError | Error | null = null;
  environmentStatus(id: EnvironmentId): Promise<EnvironmentStatus> {
    this.calls.push(`status ${id}`);
    return this.failWith ? Promise.reject(this.failWith) : Promise.resolve(this.state);
  }
  startEnvironment(id: EnvironmentId): Promise<EnvironmentStatus> {
    this.calls.push(`start ${id}`);
    if (this.failWith) return Promise.reject(this.failWith);
    this.state = { state: 'running', startedAt: Date.parse('2026-10-31T10:00:00Z') };
    return Promise.resolve(this.state);
  }
  stopEnvironment(id: EnvironmentId): Promise<void> {
    this.calls.push(`stop ${id}`);
    if (this.failWith) return Promise.reject(this.failWith);
    this.state = { state: 'stopped', startedAt: null };
    return Promise.resolve();
  }
}

const ready = async (t: TestContext, s: Session) => {
  await t.http.put('/v1/me/modules/wazuh').set(s.auth).send({ added: true }).expect(200);
  await t.http.post('/v1/lessons/intro/complete').set(s.auth).send({}).expect(200);
};
const list = async (t: TestContext, s: Session) => (await t.http.get('/v1/environments').set(s.auth).expect(200)).body.items as Record<string, unknown>[];

describe('shared environments (ADR 0013): a real Wazuh started from the UI', () => {
  it('requires authentication', async () => {
    const t = setup({ curriculum, environmentRunner: new FakeRunner() });
    await t.http.get('/v1/environments').expect(401);
    await t.http.post('/v1/environments/wazuh/start').send({}).expect(401);
    await t.http.post('/v1/environments/wazuh/stop').send({}).expect(401);
  });

  it('stays closed until the module is added and unlocked, and then tells nothing about the machine', async () => {
    const runner = new FakeRunner();
    const t = setup({ curriculum, environmentRunner: runner });
    const alice = await newUser(t);
    expect(await list(t, alice)).toEqual([
      { id: 'wazuh', title: 'Wazuh (SIEM)', moduleId: 'wazuh', available: false, state: 'unavailable', url: null, login: null, stopsAt: null },
    ]);
    await t.http.post('/v1/environments/wazuh/start').set(alice.auth).send({}).expect(403);
    await t.http.put('/v1/me/modules/wazuh').set(alice.auth).send({ added: true }).expect(200);
    await t.http.post('/v1/environments/wazuh/start').set(alice.auth).send({}).expect(403); // prerequisites still apply
    await t.http.post('/v1/environments/wazuh/stop').set(alice.auth).send({}).expect(403);
    expect(runner.calls).toEqual([]);
    expect(auditActions(t).filter((a) => a.startsWith('environment.'))).toEqual(['environment.start:denied', 'environment.start:denied', 'environment.stop:denied']);
  });

  it('starts and stops for an allowed learner, audits both, and never sends a secret', async () => {
    const runner = new FakeRunner();
    const t = setup({ curriculum, environmentRunner: runner });
    const alice = await newUser(t);
    await ready(t, alice);
    expect((await list(t, alice))[0]).toMatchObject({ available: true, state: 'stopped', url: null });

    const started = await t.http.post('/v1/environments/wazuh/start').set(alice.auth).send({}).expect(202);
    expect(started.body).toMatchObject({ state: 'running', url: 'https://localhost:8443', stopsAt: '2026-10-31T18:00:00.000Z' });
    expect(started.body.login).toContain('WAZUH_ADMIN_PASSWORD');
    expect(JSON.stringify(started.body)).not.toMatch(/password"|hash|token/i);

    await t.http.post('/v1/environments/wazuh/stop').set(alice.auth).send({}).expect(204);
    expect(runner.calls).toEqual(['status wazuh', 'start wazuh', 'status wazuh', 'stop wazuh']);
    expect(auditActions(t).filter((a) => a.startsWith('environment.'))).toEqual(['environment.start:success', 'environment.stop:success']);
  });

  it('only acts on catalog environments whose module exists', async () => {
    const t = setup({ curriculum, environmentRunner: new FakeRunner() });
    const alice = await newUser(t);
    await ready(t, alice);
    await t.http.post('/v1/environments/elastic/start').set(alice.auth).send({}).expect(404);
    await t.http.post('/v1/environments/..%2Fwazuh/start').set(alice.auth).send({}).expect(400);
    await t.http.post('/v1/environments/wazuh/start').set(alice.auth).send({ image: 'evil' }).expect(202); // the body is never read
  });

  it('explains a missing installation, hides runner internals, and reports an unreachable runner', async () => {
    const runner = new FakeRunner();
    const t = setup({ curriculum, environmentRunner: runner });
    const alice = await newUser(t);
    await ready(t, alice);
    runner.failWith = new LabRunnerError(503, 'environment_missing');
    const res = await t.http.post('/v1/environments/wazuh/start').set(alice.auth).send({}).expect(503);
    expect(res.body.message).toContain('docker compose --profile wazuh up -d');
    runner.failWith = new Error('connect ECONNREFUSED 172.18.0.3:4000');
    const res2 = await t.http.post('/v1/environments/wazuh/start').set(alice.auth).send({}).expect(503);
    expect(JSON.stringify(res2.body)).not.toContain('172.18');
    await t.http.post('/v1/environments/wazuh/stop').set(alice.auth).send({}).expect(503);
    expect((await list(t, alice))[0]).toMatchObject({ state: 'unavailable' });
    expect(auditActions(t).filter((a) => a.startsWith('environment.'))).toEqual(['environment.start:failure', 'environment.start:failure', 'environment.stop:failure']);
  });

  it('is off without a runner, and rate-limited per account', async () => {
    const off = setup({ curriculum });
    const bob = await newUser(off);
    await ready(off, bob);
    await off.http.post('/v1/environments/wazuh/start').set(bob.auth).send({}).expect(503);

    const t = setup({ curriculum, environmentRunner: new FakeRunner(), rateLimits: { lab: 2 } });
    const alice = await newUser(t);
    await ready(t, alice);
    await t.http.post('/v1/environments/wazuh/start').set(alice.auth).send({}).expect(202);
    await t.http.post('/v1/environments/wazuh/stop').set(alice.auth).send({}).expect(204);
    await t.http.post('/v1/environments/wazuh/start').set(alice.auth).send({}).expect(429);
  });

  it('is hidden when the curriculum has no module for it', async () => {
    const bare = buildCurriculum({
      index: { levels: [{ level: 1, title: 'L1', goal: 'g' }], paths: ['p'] },
      path: () => ({ id: 'p', title: 'P', summary: 's', level: 1, modules: [{ id: 'basics', title: 'B', summary: 's', lessons: [{ id: 'intro', title: 'I', minutes: 5 }] }] }),
      body: () => '# body',
    });
    const t = setup({ curriculum: bare, environmentRunner: new FakeRunner() });
    const alice = await newUser(t);
    expect(await list(t, alice)).toEqual([]);
    await t.http.post('/v1/environments/wazuh/start').set(alice.auth).send({}).expect(404);
  });
});
