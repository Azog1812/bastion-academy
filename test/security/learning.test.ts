import { describe, expect, it } from 'vitest';
import { buildCurriculum } from '../../src/curriculum/catalog.js';
import { auditActions, newUser, setup, type Session, type TestContext } from '../helpers.js';

/**
 * A small fixed curriculum, independent of the real content/ so content edits
 * never break security tests:  basics (no quiz) -> advanced (quiz, 2 questions).
 */
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
        id: 'advanced',
        title: 'A',
        summary: 's',
        prerequisites: ['basics'],
        lessons: [
          {
            id: 'quiz-lesson',
            title: 'Q',
            minutes: 5,
            quiz: [
              { id: 'single', prompt: 'one', choices: ['a', 'b', 'c'], answer: [1] },
              { id: 'multi', prompt: 'two', choices: ['a', 'b', 'c'], answer: [0, 2] },
            ],
          },
        ],
      },
    ],
  }),
  body: (_p, l) => `# ${l}`,
});

const RIGHT = { answers: [{ question: 'single', choices: [1] }, { question: 'multi', choices: [2, 0] }] };

const complete = (t: TestContext, s: Session, lesson: string, body: object = {}) =>
  t.http.post(`/v1/lessons/${lesson}/complete`).set(s.auth).send(body);

describe('learning: curriculum and progress', () => {
  it('requires authentication on every learning route', async () => {
    const t = setup({ curriculum });
    await t.http.get('/v1/curriculum').expect(401);
    await t.http.get('/v1/lessons/intro').expect(401);
    await t.http.post('/v1/lessons/intro/complete').send({}).expect(401);
  });

  it('unlocks a module only once its prerequisites are completed', async () => {
    const t = setup({ curriculum });
    const alice = await newUser(t);

    let cur = await t.http.get('/v1/curriculum').set(alice.auth).expect(200);
    expect(cur.body.paths[0].modules.map((m: { unlocked: boolean }) => m.unlocked)).toEqual([true, false]);
    expect(cur.body.progress).toEqual({ completed: 0, total: 2 });

    await t.http.get('/v1/lessons/quiz-lesson').set(alice.auth).expect(403);
    await complete(t, alice, 'quiz-lesson', RIGHT).expect(403);

    const done = await complete(t, alice, 'intro').expect(200);
    expect(done.body).toMatchObject({ passed: true, alreadyCompleted: false });

    cur = await t.http.get('/v1/curriculum').set(alice.auth).expect(200);
    expect(cur.body.paths[0].modules[0]).toMatchObject({ completed: true });
    expect(cur.body.paths[0].modules[1]).toMatchObject({ unlocked: true, completed: false });
    await t.http.get('/v1/lessons/quiz-lesson').set(alice.auth).expect(200);

    expect(auditActions(t)).toEqual(expect.arrayContaining(['lesson.complete:denied', 'lesson.complete:success']));
  });

  it('never sends quiz answers to the client', async () => {
    const t = setup({ curriculum });
    const alice = await newUser(t);
    await complete(t, alice, 'intro').expect(200);

    const lesson = await t.http.get('/v1/lessons/quiz-lesson').set(alice.auth).expect(200);
    expect(lesson.body.quiz).toEqual([
      { id: 'single', prompt: 'one', choices: ['a', 'b', 'c'], multiple: false },
      { id: 'multi', prompt: 'two', choices: ['a', 'b', 'c'], multiple: true },
    ]);
    const cur = await t.http.get('/v1/curriculum').set(alice.auth).expect(200);
    expect(JSON.stringify(lesson.body) + JSON.stringify(cur.body)).not.toContain('"answer"');
  });

  it('grades quizzes server-side: wrong, partial and over-selected answers fail', async () => {
    const t = setup({ curriculum });
    const alice = await newUser(t);
    await complete(t, alice, 'intro').expect(200);

    const wrong = await complete(t, alice, 'quiz-lesson', {
      answers: [{ question: 'single', choices: [0] }, { question: 'multi', choices: [0] }], // partial on multi
    }).expect(200);
    expect(wrong.body).toEqual({ passed: false, incorrect: ['single', 'multi'] });

    const greedy = await complete(t, alice, 'quiz-lesson', {
      answers: [{ question: 'single', choices: [1] }, { question: 'multi', choices: [0, 1, 2] }], // ticking everything
    }).expect(200);
    expect(greedy.body).toEqual({ passed: false, incorrect: ['multi'] });

    const cur = await t.http.get('/v1/curriculum').set(alice.auth).expect(200);
    expect(cur.body.progress.completed).toBe(1); // failed attempts are not recorded as progress

    const ok = await complete(t, alice, 'quiz-lesson', RIGHT).expect(200);
    expect(ok.body.passed).toBe(true);
    expect(auditActions(t)).toContain('lesson.complete:failure');
  });

  it('rejects malformed or incomplete submissions instead of guessing', async () => {
    const t = setup({ curriculum });
    const alice = await newUser(t);
    await complete(t, alice, 'intro').expect(200);

    await complete(t, alice, 'quiz-lesson', {}).expect(400); // nothing answered
    await complete(t, alice, 'quiz-lesson', { answers: [{ question: 'single', choices: [1] }] }).expect(400); // one missing
    await complete(t, alice, 'quiz-lesson', { answers: [...RIGHT.answers, { question: 'ghost', choices: [0] }] }).expect(400);
    await complete(t, alice, 'quiz-lesson', { answers: [...RIGHT.answers, RIGHT.answers[0]] }).expect(400); // answered twice
    await complete(t, alice, 'quiz-lesson', { ...RIGHT, completedAt: '2000-01-01' }).expect(400); // mass assignment
    await complete(t, alice, 'quiz-lesson', { answers: [{ question: 'single', choices: [99] }] }).expect(400);
    await complete(t, alice, 'quiz-lesson', { answers: { __proto__: { polluted: true } } }).expect(400);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('completion is idempotent and keeps the first timestamp', async () => {
    const t = setup({ curriculum });
    const alice = await newUser(t);
    const first = await complete(t, alice, 'intro').expect(200);
    const again = await complete(t, alice, 'intro').expect(200);
    expect(again.body).toEqual({ passed: true, alreadyCompleted: true, completedAt: first.body.completedAt });
    expect(auditActions(t).filter((a) => a === 'lesson.complete:success')).toHaveLength(1);
  });

  it("isolates progress: one learner's completions never unlock or show for another", async () => {
    const t = setup({ curriculum });
    const alice = await newUser(t);
    const bob = await newUser(t);
    await complete(t, alice, 'intro').expect(200);

    const cur = await t.http.get('/v1/curriculum').set(bob.auth).expect(200);
    expect(cur.body.progress.completed).toBe(0);
    await t.http.get('/v1/lessons/quiz-lesson').set(bob.auth).expect(403);
    const lesson = await t.http.get('/v1/lessons/intro').set(bob.auth).expect(200);
    expect(lesson.body).toMatchObject({ completed: false, completedAt: null });
  });

  it('rejects unknown and traversal-shaped lesson ids', async () => {
    const t = setup({ curriculum });
    const alice = await newUser(t);
    await t.http.get('/v1/lessons/does-not-exist').set(alice.auth).expect(404);
    await t.http.get('/v1/lessons/..%2F..%2Fpackage.json').set(alice.auth).expect(400);
    await t.http.get('/v1/lessons/INTRO').set(alice.auth).expect(400);
    await complete(t, alice, 'does-not-exist').expect(404);
  });

  it('rate-limits quiz attempts per account, not per IP', async () => {
    const t = setup({ curriculum, rateLimits: { quiz: 3 } });
    const alice = await newUser(t);
    const bob = await newUser(t);
    for (let i = 0; i < 3; i++) await complete(t, alice, 'intro').expect(200);
    await complete(t, alice, 'intro').expect(429);
    // Same IP (the test client), different account: not throttled.
    await complete(t, bob, 'intro').expect(200);
  });

  it("deleting a user's account removes their progress", async () => {
    const t = setup({ curriculum });
    const alice = await newUser(t);
    await complete(t, alice, 'intro').expect(200);
    t.db.prepare('DELETE FROM users WHERE id = ?').run(alice.id);
    const { n } = t.db.prepare('SELECT COUNT(*) AS n FROM lesson_progress WHERE user_id = ?').get(alice.id) as { n: number };
    expect(n).toBe(0);
  });
});
