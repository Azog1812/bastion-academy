import { describe, expect, it } from 'vitest';
import { buildCurriculum } from '../../src/curriculum/catalog.js';
import { auditActions, newUser, setup, type Session, type TestContext } from '../helpers.js';

/** basics (open): a detection challenge and a flag challenge; advanced (locked): a detection challenge. */
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
      { id: 'ssh', title: 'SSH', moduleId: 'basics', points: 250, detection: 'ssh-bruteforce', brief: 'detect' },
      { id: 'b64', title: 'B64', moduleId: 'basics', points: 50, kind: 'base64-layers', brief: 'decode' },
      { id: 'late', title: 'Late', moduleId: 'advanced', points: 300, detection: 'web-sqli', brief: 'locked' },
    ],
  },
});

const GOOD = { match: { event: ['failed_password', 'invalid_user'] }, threshold: { groupBy: 'src_ip', min: 10, windowSeconds: 3600 } };
const SHORT_WINDOW = { ...GOOD, threshold: { ...GOOD.threshold, windowSeconds: 120 } };

const ctx = (quiz = 10_000) => setup({ curriculum, rateLimits: { quiz } });
const detect = (t: TestContext, s: Session, id: string, rule: unknown) => t.http.post(`/v1/challenges/${id}/detect`).set(s.auth).send({ rule });

describe('detection challenges', () => {
  it('serve the learner\'s own dataset and its fields, never the labels', async () => {
    const t = ctx();
    const s = await newUser(t);
    const res = await t.http.get('/v1/challenges/ssh').set(s.auth).expect(200);
    expect(res.body.detection).toMatchObject({ unit: 'entity', entityField: 'src_ip' });
    expect(res.body.detection.fields).toContain('src_ip');
    const lines = (res.body.artifact.events as string).split('\n');
    expect(lines.length).toBe(res.body.detection.events);
    expect(JSON.parse(lines[0] ?? '{}')).toHaveProperty('id', 'e001');
    // Nothing in what the learner receives says which events are malicious.
    expect(JSON.stringify(res.body)).not.toMatch(/malicious|label|attack|BASTION\{/i);
    const other = await newUser(t);
    expect((await t.http.get('/v1/challenges/ssh').set(other.auth).expect(200)).body.artifact.events).not.toBe(res.body.artifact.events);
  });

  it('an imperfect rule gets feedback and no points; a perfect one solves, once', async () => {
    const t = ctx();
    const s = await newUser(t);
    const partial = (await detect(t, s, 'ssh', SHORT_WINDOW).expect(200)).body;
    expect(partial).toMatchObject({ solved: false, points: 0, missed: 1, falsePositives: 0 });
    expect(partial.examples.missed).toHaveLength(1);
    const ok = (await detect(t, s, 'ssh', GOOD).expect(200)).body;
    expect(ok).toMatchObject({ solved: true, perfect: true, points: 250, alreadySolved: false, missed: 0, falsePositives: 0 });
    expect((await detect(t, s, 'ssh', GOOD).expect(200)).body).toMatchObject({ solved: true, alreadySolved: true });
    const list = (await t.http.get('/v1/challenges').set(s.auth).expect(200)).body.items as { id: string; solved: boolean }[];
    expect(list.find((c) => c.id === 'ssh')?.solved).toBe(true);
    expect((await t.http.get('/v1/scoreboard').set(s.auth).expect(200)).body.me.score).toBe(250);
    expect(auditActions(t).filter((a) => a.startsWith('challenge.submit'))).toEqual(['challenge.submit:failure', 'challenge.submit:success']);
  });

  it('rejects rules outside the language with the reason: unknown fields, prototype keys, regex, oversized', async () => {
    const t = ctx();
    const s = await newUser(t);
    for (const bad of [
      { match: { password: 'x' } },
      { match: { 'event|re': '(a+)+$' } },
      JSON.parse('{"match": {"__proto__": "x"}}') as unknown,
      { match: { event: 'x'.repeat(201) } },
      { match: Array.from({ length: 11 }, () => ({ event: 'x' })) },
      { match: { event: 'x' }, eval: 'process.exit()' },
      { match: { event: 'x' }, threshold: { groupBy: 'src_ip', min: 1, windowSeconds: 10 } },
    ]) {
      const res = await detect(t, s, 'ssh', bad).expect(400);
      expect(res.body.error).toBe('validation_error');
    }
    await t.http.post('/v1/challenges/ssh/detect').set(s.auth).send({ rule: 'match everything' }).expect(400);
    await t.http.post('/v1/challenges/ssh/detect').set(s.auth).send({ rule: GOOD, extra: 1 }).expect(400);
  });

  it('locked, unknown and non-detection challenges get no evaluation', async () => {
    const t = ctx();
    const s = await newUser(t);
    await detect(t, s, 'late', { match: { query: 'x' } }).expect(403);
    await detect(t, s, 'b64', GOOD).expect(404);
    await detect(t, s, 'nope', GOOD).expect(404);
    expect(auditActions(t)).toContain('challenge.submit:denied');
  });

  it('evaluations are rate-limited per account', async () => {
    const t = ctx(2); // detect budget = 2 × quiz budget
    const s = await newUser(t);
    for (let i = 0; i < 4; i++) await detect(t, s, 'ssh', SHORT_WINDOW).expect(200);
    await detect(t, s, 'ssh', SHORT_WINDOW).expect(429);
    await detect(t, await newUser(t), 'ssh', SHORT_WINDOW).expect(200);
  });

  it('a flag cannot solve a detection challenge', async () => {
    const t = ctx();
    const s = await newUser(t);
    await t.http.post('/v1/challenges/ssh/submit').set(s.auth).send({ flag: 'BASTION{00000000000000000000000000000000}' }).expect(200, { correct: false });
  });
});
