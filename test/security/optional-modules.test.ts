import { describe, expect, it } from 'vitest';
import { buildCurriculum } from '../../src/curriculum/catalog.js';
import { auditActions, newUser, setup, type Session, type TestContext } from '../helpers.js';

/** basics (mandatory) -> siem (optional, heavy) ; a challenge lives in siem. */
const curriculum = buildCurriculum({
  index: { levels: [{ level: 1, title: 'L1', goal: 'g' }], paths: ['p'] },
  path: () => ({
    id: 'p',
    title: 'P',
    summary: 's',
    level: 1,
    modules: [
      { id: 'basics', title: 'B', summary: 's', lessons: [{ id: 'intro', title: 'Intro', minutes: 5 }] },
      {
        id: 'siem',
        title: 'S',
        summary: 's',
        prerequisites: ['basics'],
        optional: true,
        requirements: { docker: true, ramGb: 8 },
        lessons: [{ id: 'siem-lesson', title: 'SIEM', minutes: 5 }],
      },
    ],
  }),
  body: () => '# body',
  challenges: { challenges: [{ id: 'siem-chal', title: 'C', moduleId: 'siem', points: 50, kind: 'base64-layers', brief: 'b' }] },
});

const choose = (t: TestContext, s: Session, id: string, body: unknown) => t.http.put(`/v1/me/modules/${id}`).set(s.auth).send(body as object);
const modules = async (t: TestContext, s: Session) =>
  (await t.http.get('/v1/curriculum').set(s.auth).expect(200)).body as {
    paths: { modules: { id: string; optional: boolean; added: boolean; unlocked: boolean; requirements: object }[] }[];
    progress: { completed: number; total: number };
  };

describe('optional modules: each learner shapes their training', () => {
  it('starts with optional modules left out, shows their requirements, and does not count them', async () => {
    const t = setup({ curriculum });
    const alice = await newUser(t);
    const cur = await modules(t, alice);
    expect(cur.paths[0]?.modules).toEqual([
      expect.objectContaining({ id: 'basics', optional: false, added: true, requirements: {} }),
      expect.objectContaining({ id: 'siem', optional: true, added: false, requirements: { docker: true, ramGb: 8 } }),
    ]);
    expect(cur.progress).toEqual({ completed: 0, total: 1 });
  });

  it('keeps a left-out module closed server-side: lessons, quiz and challenges', async () => {
    const t = setup({ curriculum });
    const alice = await newUser(t);
    await t.http.post('/v1/lessons/intro/complete').set(alice.auth).send({}).expect(200);
    // Prerequisites done, but the module was never added: still closed.
    await t.http.get('/v1/lessons/siem-lesson').set(alice.auth).expect(403);
    await t.http.post('/v1/lessons/siem-lesson/complete').set(alice.auth).send({}).expect(403);
    await t.http.get('/v1/challenges/siem-chal').set(alice.auth).expect(403);
    expect(t.db.prepare("SELECT details FROM audit_log WHERE action = 'lesson.complete' AND outcome = 'denied'").all()).toEqual([
      { details: '{"reason":"not_added"}' },
      { details: '{"reason":"not_added"}' },
    ]);
  });

  it('opens an added module once its prerequisites are done, and keeps progress when removed', async () => {
    const t = setup({ curriculum });
    const alice = await newUser(t);
    await choose(t, alice, 'siem', { added: true }).expect(200, { id: 'siem', added: true });
    await t.http.get('/v1/lessons/siem-lesson').set(alice.auth).expect(403); // prerequisites still apply
    await t.http.post('/v1/lessons/intro/complete').set(alice.auth).send({}).expect(200);
    await t.http.post('/v1/lessons/siem-lesson/complete').set(alice.auth).send({}).expect(200);
    await t.http.get('/v1/challenges/siem-chal').set(alice.auth).expect(200);
    expect((await modules(t, alice)).progress).toEqual({ completed: 2, total: 2 });

    await choose(t, alice, 'siem', { added: false }).expect(200, { id: 'siem', added: false });
    expect((await modules(t, alice)).progress).toEqual({ completed: 1, total: 1 });
    await t.http.get('/v1/lessons/siem-lesson').set(alice.auth).expect(403);

    await choose(t, alice, 'siem', { added: true }).expect(200);
    expect((await modules(t, alice)).progress).toEqual({ completed: 2, total: 2 });
    expect(auditActions(t).filter((a) => a.startsWith('module.select'))).toHaveLength(3);
  });

  it('is idempotent and audits only real changes', async () => {
    const t = setup({ curriculum });
    const alice = await newUser(t);
    await choose(t, alice, 'siem', { added: true }).expect(200);
    await choose(t, alice, 'siem', { added: true }).expect(200);
    await choose(t, alice, 'siem', { added: false }).expect(200);
    await choose(t, alice, 'siem', { added: false }).expect(200);
    expect(auditActions(t).filter((a) => a.startsWith('module.select'))).toEqual(['module.select:success', 'module.select:success']);
  });

  it("isolates choices: one learner's modules never open for another", async () => {
    const t = setup({ curriculum });
    const alice = await newUser(t);
    const bob = await newUser(t);
    await choose(t, alice, 'siem', { added: true }).expect(200);
    expect((await modules(t, bob)).paths[0]?.modules[1]).toMatchObject({ added: false });
    await t.http.post('/v1/lessons/intro/complete').set(bob.auth).send({}).expect(200);
    await t.http.get('/v1/lessons/siem-lesson').set(bob.auth).expect(403);
  });

  it('refuses to remove mandatory modules, unknown ids and malformed bodies', async () => {
    const t = setup({ curriculum });
    const alice = await newUser(t);
    await choose(t, alice, 'basics', { added: false }).expect(400);
    await choose(t, alice, 'ghost', { added: true }).expect(404);
    await choose(t, alice, '..%2Fetc', { added: true }).expect(400);
    await choose(t, alice, 'siem', { added: 'yes' }).expect(400);
    await choose(t, alice, 'siem', { added: true, userId: 'someone-else' }).expect(400);
    await choose(t, alice, 'siem', {}).expect(400);
    await t.http.put('/v1/me/modules/siem').send({ added: true }).expect(401);
  });

  it("deleting an account removes its choices", async () => {
    const t = setup({ curriculum });
    const alice = await newUser(t);
    await choose(t, alice, 'siem', { added: true }).expect(200);
    t.db.prepare('DELETE FROM users WHERE id = ?').run(alice.id);
    expect(t.db.prepare('SELECT COUNT(*) AS n FROM module_choices WHERE user_id = ?').get(alice.id)).toEqual({ n: 0 });
  });
});
