import { describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config.js';
import { buildCurriculum } from '../../src/curriculum/catalog.js';
import { LabRunnerError, type LabRunnerClient, type LabStart } from '../../src/services/lab-service.js';
import { auditActions, newUser, setup, testEnv, type Session, type TestContext } from '../helpers.js';

/** basics (open): two lab challenges and an artifact one; advanced (locked): a lab. */
const curriculum = buildCurriculum({
  index: { levels: [{ level: 1, title: 'L1', goal: 'g' }], paths: ['p'] },
  path: () => ({
    id: 'p',
    title: 'P',
    summary: 's',
    level: 1,
    modules: [
      { id: 'basics', title: 'B', summary: 's', lessons: [{ id: 'intro', title: 'Intro', minutes: 5 }] },
      { id: 'advanced', title: 'A', summary: 's', prerequisites: ['basics'], lessons: [{ id: 'deep', title: 'Deep', minutes: 5 }] },
    ],
  }),
  body: () => '# body',
  challenges: {
    challenges: [
      { id: 'sqli', title: 'SQLi', moduleId: 'basics', points: 200, lab: 'sqli-login', brief: 'attack the login' },
      { id: 'idor', title: 'IDOR', moduleId: 'basics', points: 200, lab: 'idor-invoices', brief: 'read the invoices' },
      { id: 'b64', title: 'B64', moduleId: 'basics', points: 50, kind: 'base64-layers', brief: 'decode' },
      { id: 'late', title: 'Late', moduleId: 'advanced', points: 300, lab: 'mass-assignment', brief: 'locked' },
    ],
  },
});

/** Records what the platform asks for; can be told to fail like the real runner would. */
class FakeRunner implements LabRunnerClient {
  starts: LabStart[] = [];
  stops: string[] = [];
  failWith: LabRunnerError | Error | null = null;
  start(req: LabStart): Promise<void> {
    if (this.failWith) return Promise.reject(this.failWith);
    this.starts.push(req);
    return Promise.resolve();
  }
  stop(id: string): Promise<void> {
    this.stops.push(id);
    return Promise.resolve();
  }
}

const ctx = (opts: { rateLimits?: { lab: number }; noRunner?: boolean } = {}) => {
  const runner = new FakeRunner();
  const t = setup({ curriculum, ...(opts.noRunner ? {} : { labRunner: runner }), ...(opts.rateLimits ? { rateLimits: opts.rateLimits } : {}) });
  return { t, runner };
};

const start = (t: TestContext, s: Session, id: string) => t.http.post(`/v1/challenges/${id}/lab`).set(s.auth).send({});
const stop = (t: TestContext, s: Session, id: string) => t.http.delete(`/v1/challenges/${id}/lab`).set(s.auth);
const view = async (t: TestContext, s: Session, id: string) =>
  (await t.http.get(`/v1/challenges/${id}`).set(s.auth).expect(200)).body as {
    lab: { id: string; enabled: boolean; instance: { url: string; expiresAt: string } | null } | null;
    artifact: Record<string, string>;
  };

describe('labs: per-learner instances', () => {
  it('a lab challenge carries no artifact and never the flag; starting one injects the learner\'s own flag', async () => {
    const { t, runner } = ctx();
    const s = await newUser(t);
    const before = await view(t, s, 'sqli');
    expect(before.artifact).toEqual({});
    expect(before.lab).toMatchObject({ id: 'sqli-login', enabled: true, instance: null });
    expect(JSON.stringify(before)).not.toMatch(/BASTION\{/);

    const res = await start(t, s, 'sqli').expect(201);
    expect(res.body.url).toMatch(/^http:\/\/l[0-9a-f]{32}\.lab\.localhost:8088\/$/);
    expect(JSON.stringify(res.body)).not.toMatch(/BASTION\{/);
    expect(runner.starts).toHaveLength(1);
    const sent = runner.starts[0];
    expect(sent).toMatchObject({ lab: 'sqli-login', ttlSeconds: t.config.LAB_TTL_SECONDS });
    expect(res.body.url).toContain(`l${sent?.instanceId ?? ''}.`);

    // The flag inside the lab is exactly the one that scores for this learner.
    await t.http.post('/v1/challenges/sqli/submit').set(s.auth).send({ flag: sent?.flag }).expect(200, { correct: true, points: 200, alreadySolved: false });
    expect((await view(t, s, 'sqli')).lab?.instance?.url).toBe(res.body.url);
    expect(auditActions(t)).toContain('lab.start:success');
  });

  it('starting again is idempotent, including two concurrent starts: one runner call, one instance', async () => {
    const { t, runner } = ctx();
    const s = await newUser(t);
    const [a, b] = await Promise.all([start(t, s, 'sqli'), start(t, s, 'sqli')]);
    expect(a.status).toBe(201);
    expect(b.status).toBe(201);
    expect(a.body.url).toBe(b.body.url);
    expect((await start(t, s, 'sqli').expect(201)).body.url).toBe(a.body.url);
    expect(runner.starts).toHaveLength(1);
  });

  it('one running lab per learner: a second lab needs the first one stopped', async () => {
    const { t, runner } = ctx();
    const s = await newUser(t);
    await start(t, s, 'sqli').expect(201);
    await start(t, s, 'idor').expect(409);
    await stop(t, s, 'sqli').expect(204);
    expect(runner.stops).toEqual([runner.starts[0]?.instanceId]);
    expect((await view(t, s, 'sqli')).lab?.instance).toBeNull();
    await start(t, s, 'idor').expect(201);
    expect(auditActions(t)).toContain('lab.stop:success');
  });

  it('learners get different instances and flags, and cannot see or stop each other\'s lab (no IDOR)', async () => {
    const { t, runner } = ctx();
    const alice = await newUser(t);
    const mallory = await newUser(t);
    await start(t, alice, 'sqli').expect(201);
    expect((await view(t, mallory, 'sqli')).lab?.instance).toBeNull();
    await stop(t, mallory, 'sqli').expect(404);
    expect(runner.stops).toEqual([]);
    await start(t, mallory, 'sqli').expect(201);
    const [a, m] = runner.starts;
    expect(a?.instanceId).not.toBe(m?.instanceId);
    expect(a?.flag).not.toBe(m?.flag);
    // Alice's flag, taken from her lab, does not score for Mallory.
    await t.http.post('/v1/challenges/sqli/submit').set(mallory.auth).send({ flag: a?.flag }).expect(200, { correct: false });
  });

  it('a locked lab cannot be started (server-side gating), and the attempt is audited', async () => {
    const { t, runner } = ctx();
    const s = await newUser(t);
    await start(t, s, 'late').expect(403);
    expect(runner.starts).toHaveLength(0);
    expect(auditActions(t)).toContain('lab.start:denied');
  });

  it('unknown challenges, non-lab challenges and bad ids get no lab', async () => {
    const { t, runner } = ctx();
    const s = await newUser(t);
    await start(t, s, 'b64').expect(404);
    await start(t, s, 'nope').expect(404);
    await start(t, s, '..%2F..%2Fetc').expect(400);
    await stop(t, s, 'b64').expect(404);
    expect((await view(t, s, 'b64')).lab).toBeNull();
    expect(runner.starts).toHaveLength(0);
  });

  it('a runner failure leaves nothing behind and says why without internals', async () => {
    const { t, runner } = ctx();
    const s = await newUser(t);
    runner.failWith = new LabRunnerError(503, 'lab_image_missing');
    const missing = await start(t, s, 'sqli').expect(503);
    expect(missing.body.message).toMatch(/docker compose --profile labs build/);
    runner.failWith = new Error('connect ECONNREFUSED 10.0.0.7:4000');
    const down = await start(t, s, 'sqli').expect(503);
    expect(JSON.stringify(down.body)).not.toMatch(/ECONNREFUSED|10\.0\.0\.7/);
    expect((await view(t, s, 'sqli')).lab?.instance).toBeNull();
    runner.failWith = null;
    await start(t, s, 'sqli').expect(201);
    expect(auditActions(t).filter((a) => a === 'lab.start:failure')).toHaveLength(2);
  });

  it('expired labs are destroyed by the reaper, and an expired slot does not block a new start', async () => {
    const { t, runner } = ctx();
    const s = await newUser(t);
    await start(t, s, 'sqli').expect(201);
    t.db.prepare('UPDATE lab_instances SET expires_at = 0').run();
    expect((await view(t, s, 'sqli')).lab?.instance).toBeNull();
    expect(await t.services.labs.reap()).toBe(1);
    expect(runner.stops).toEqual([runner.starts[0]?.instanceId]);
    expect(auditActions(t)).toContain('lab.expire:success');

    await start(t, s, 'idor').expect(201);
    t.db.prepare('UPDATE lab_instances SET expires_at = 0').run();
    await start(t, s, 'sqli').expect(201); // the expired idor lab is cleaned up first
    expect(runner.stops).toHaveLength(2);
  });

  it('lab starts are rate-limited per account', async () => {
    const { t } = ctx({ rateLimits: { lab: 2 } });
    const s = await newUser(t);
    await start(t, s, 'sqli').expect(201);
    await stop(t, s, 'sqli').expect(204);
    await start(t, s, 'sqli').expect(201);
    await start(t, s, 'sqli').expect(429);
    await start(t, await newUser(t), 'sqli').expect(201);
  });

  it('labs stay off unless a runner is configured, and the runner token is then mandatory', async () => {
    const { t } = ctx({ noRunner: true });
    const s = await newUser(t);
    expect((await view(t, s, 'sqli')).lab).toMatchObject({ enabled: false, instance: null });
    await start(t, s, 'sqli').expect(503);
    expect(() => loadConfig(testEnv({ LAB_RUNNER_URL: 'http://lab-runner:4000' }))).toThrow(/LAB_RUNNER_TOKEN/);
    expect(() => loadConfig(testEnv({ LAB_RUNNER_URL: 'file:///etc/passwd', LAB_RUNNER_TOKEN: Buffer.alloc(32, 7).toString('base64') }))).toThrow(/LAB_RUNNER_URL/);
  });
});

describe('lab challenges in content', () => {
  it('need exactly one of kind or lab, and only known labs', () => {
    const one = (extra: object) =>
      buildCurriculum({
        index: { levels: [{ level: 1, title: 'L1', goal: 'g' }], paths: ['p'] },
        path: () => ({ id: 'p', title: 'P', summary: 's', level: 1, modules: [{ id: 'basics', title: 'B', summary: 's', lessons: [{ id: 'i', title: 'I', minutes: 5 }] }] }),
        body: () => '# b',
        challenges: { challenges: [{ id: 'c', title: 'C', moduleId: 'basics', points: 10, brief: 'b', ...extra }] },
      });
    expect(() => one({})).toThrow();
    expect(() => one({ kind: 'base64-layers', lab: 'sqli-login' })).toThrow();
    expect(() => one({ lab: 'docker-socket' })).toThrow();
    expect(() => one({ lab: 'sqli-login', image: 'alpine' })).toThrow();
    expect(one({ lab: 'sqli-login' }).challenges.get('c')?.lab).toBe('sqli-login');
  });
});
