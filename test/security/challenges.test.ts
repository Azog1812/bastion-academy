import { describe, expect, it } from 'vitest';
import { buildCurriculum, CurriculumError } from '../../src/curriculum/catalog.js';
import { auditActions, newUser, setup, type Session, type TestContext } from '../helpers.js';

/** basics (open, 2 challenges) -> advanced (locked until basics is done, 1 challenge). */
const source = (challenges: unknown) => ({
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
  challenges,
});

const curriculum = buildCurriculum(
  source({
    challenges: [
      { id: 'b64', title: 'B64', moduleId: 'basics', points: 50, kind: 'base64-layers', brief: 'decode' },
      { id: 'xor', title: 'XOR', moduleId: 'basics', points: 100, kind: 'xor-single-byte', brief: 'xor' },
      { id: 'hdr', title: 'HDR', moduleId: 'basics', points: 30, kind: 'http-headers', brief: 'headers' },
      { id: 'jwt', title: 'JWT', moduleId: 'basics', points: 20, kind: 'jwt-claims', brief: 'jwt' },
      { id: 'late', title: 'Late', moduleId: 'advanced', points: 200, kind: 'base64-layers', brief: 'locked' },
    ],
  }),
);

const ctx = (): TestContext => setup({ curriculum });

const FLAG = /BASTION\{[0-9a-f]{32}\}/;

/** Solves each artifact the way the brief tells the learner to. */
function solve(kind: string, artifact: Record<string, string>): string {
  switch (kind) {
    case 'b64': {
      let data = artifact.data ?? '';
      while (!data.startsWith('BASTION{')) data = Buffer.from(data, 'base64').toString();
      return data;
    }
    case 'xor': {
      const ct = Buffer.from(artifact.ciphertextHex ?? '', 'hex');
      const key = (ct[0] ?? 0) ^ 'B'.charCodeAt(0);
      return Buffer.from(ct.map((b) => b ^ key)).toString();
    }
    case 'hdr':
      return FLAG.exec(artifact.response ?? '')?.[0] ?? '';
    case 'jwt': {
      const payload = JSON.parse(Buffer.from((artifact.token ?? '').split('.')[1] ?? '', 'base64url').toString()) as { debug_note: string };
      return payload.debug_note;
    }
    default:
      throw new Error(kind);
  }
}

async function artifact(t: TestContext, s: Session, id: string) {
  const res = await t.http.get(`/v1/challenges/${id}`).set(s.auth).expect(200);
  return res.body as { artifact: Record<string, string>; solved: boolean };
}

const submit = (t: TestContext, s: Session, id: string, flag: string) => t.http.post(`/v1/challenges/${id}/submit`).set(s.auth).send({ flag });

describe('challenges: per-learner flags', () => {
  it('every artifact kind really hides the learner\'s own flag, and solving it scores', async () => {
    const t = ctx();
    const s = await newUser(t);
    for (const id of ['b64', 'xor', 'hdr', 'jwt']) {
      const flag = solve(id, (await artifact(t, s, id)).artifact);
      expect(flag).toMatch(FLAG);
      const res = await submit(t, s, id, flag).expect(200);
      expect(res.body).toMatchObject({ correct: true, alreadySolved: false });
    }
    const list = await t.http.get('/v1/challenges').set(s.auth).expect(200);
    expect(list.body.items.filter((c: { solved: boolean }) => c.solved)).toHaveLength(4);
  });

  it('artifacts are stable for one learner and different between learners', async () => {
    const t = ctx();
    const [a, b] = [await newUser(t), await newUser(t)];
    expect((await artifact(t, a, 'xor')).artifact).toEqual((await artifact(t, a, 'xor')).artifact);
    expect(solve('xor', (await artifact(t, a, 'xor')).artifact)).not.toBe(solve('xor', (await artifact(t, b, 'xor')).artifact));
  });

  it('a flag shared by another learner is refused, and attributed in the audit log', async () => {
    const t = ctx();
    const [alice, mallory] = [await newUser(t), await newUser(t)];
    const aliceFlag = solve('b64', (await artifact(t, alice, 'b64')).artifact);
    await submit(t, alice, 'b64', aliceFlag).expect(200);

    const res = await submit(t, mallory, 'b64', aliceFlag).expect(200);
    expect(res.body).toEqual({ correct: false }); // same answer as any wrong flag: no oracle on other accounts
    const shared = t.services.audit.list(100).find((r) => r.action === 'challenge.flag_shared');
    expect(shared?.actor_id).toBe(mallory.id);
    expect(JSON.parse(shared?.details ?? '{}')).toEqual({ owner: alice.id });
  });

  it('wrong flags fail without leaking anything, and are audited', async () => {
    const t = ctx();
    const s = await newUser(t);
    expect((await submit(t, s, 'b64', 'BASTION{00000000000000000000000000000000}').expect(200)).body).toEqual({ correct: false });
    expect((await submit(t, s, 'b64', "' OR 1=1 --").expect(200)).body).toEqual({ correct: false });
    expect(auditActions(t)).toContain('challenge.submit:failure');
  });

  it('solving twice scores once', async () => {
    const t = ctx();
    const s = await newUser(t);
    const flag = solve('b64', (await artifact(t, s, 'b64')).artifact);
    await submit(t, s, 'b64', flag).expect(200);
    expect((await submit(t, s, 'b64', flag).expect(200)).body).toMatchObject({ correct: true, alreadySolved: true });
    const board = await t.http.get('/v1/scoreboard').set(s.auth).expect(200);
    expect(board.body.me.score).toBe(50);
  });

  it('a locked challenge can neither be read nor submitted (server-side gating)', async () => {
    const t = ctx();
    const s = await newUser(t);
    await t.http.get('/v1/challenges/late').set(s.auth).expect(403);
    await submit(t, s, 'late', 'BASTION{00000000000000000000000000000000}').expect(403);
    const list = await t.http.get('/v1/challenges').set(s.auth).expect(200);
    expect(list.body.items.find((c: { id: string }) => c.id === 'late')).toMatchObject({ unlocked: false });
    // The list never carries artifacts or briefs.
    expect(JSON.stringify(list.body)).not.toMatch(/BASTION|artifact|brief/);

    await t.http.post('/v1/lessons/intro/complete').set(s.auth).send({}).expect(200);
    await t.http.get('/v1/challenges/late').set(s.auth).expect(200);
  });

  it('rejects unknown challenges, bad ids, extra fields and oversized flags', async () => {
    const t = ctx();
    const s = await newUser(t);
    await t.http.get('/v1/challenges/nope').set(s.auth).expect(404);
    await t.http.get('/v1/challenges/..%2F..%2Fetc').set(s.auth).expect(400);
    await t.http.post('/v1/challenges/b64/submit').set(s.auth).send({ flag: 'x', points: 1000 }).expect(400);
    await t.http.post('/v1/challenges/b64/submit').set(s.auth).send({ flag: 'x'.repeat(101) }).expect(400);
    await t.http.get('/v1/challenges').expect(401);
  });

  it('rate-limits flag guessing per account', async () => {
    const t = setup({ curriculum, rateLimits: { quiz: 3 } });
    const s = await newUser(t);
    for (let i = 0; i < 3; i++) await submit(t, s, 'b64', 'BASTION{nope}').expect(200);
    await submit(t, s, 'b64', 'BASTION{nope}').expect(429);
    // Another account is not affected.
    await submit(t, await newUser(t), 'b64', 'BASTION{nope}').expect(200);
  });
});

describe('scoreboard (opt-in, pseudonymous)', () => {
  it('lists only learners who chose a display name, with nothing but name and score', async () => {
    const t = ctx();
    const [alice, bob, carol] = [await newUser(t), await newUser(t), await newUser(t)];
    await t.http.put('/v1/me/profile').set(alice.auth).send({ displayName: 'Alice_42' }).expect(200);
    await t.http.put('/v1/me/profile').set(bob.auth).send({ displayName: 'Bob' }).expect(200);
    for (const s of [alice, bob, carol]) await t.http.post('/v1/lessons/intro/complete').set(s.auth).send({}).expect(200);
    await submit(t, alice, 'b64', solve('b64', (await artifact(t, alice, 'b64')).artifact)).expect(200);

    const res = await t.http.get('/v1/scoreboard').set(carol.auth).expect(200);
    expect(res.body.entries).toEqual([
      { rank: 1, displayName: 'Alice_42', score: 60 },
      { rank: 2, displayName: 'Bob', score: 10 },
    ]);
    // Carol sees her own score but has no rank: she did not opt in.
    expect(res.body.me).toEqual({ score: 10, rank: null, displayName: null });
    const text = JSON.stringify(res.body);
    for (const s of [alice, bob, carol]) {
      expect(text).not.toContain(s.id);
      expect(text).not.toContain(s.email);
    }
  });

  it('display names are unique (case-insensitive), validated, and can be withdrawn', async () => {
    const t = ctx();
    const [a, b] = [await newUser(t), await newUser(t)];
    await t.http.put('/v1/me/profile').set(a.auth).send({ displayName: 'Neo' }).expect(200);
    await t.http.put('/v1/me/profile').set(b.auth).send({ displayName: 'NEO' }).expect(409);
    for (const bad of ['<script>', 'ab', 'x'.repeat(25), 'a  b', 'name\u0000', 'a;DROP']) {
      await t.http.put('/v1/me/profile').set(b.auth).send({ displayName: bad }).expect(400);
    }
    await t.http.put('/v1/me/profile').set(b.auth).send({ displayName: 'Trinity', role: 'admin' }).expect(400);
    await t.http.put('/v1/me/profile').set(a.auth).send({ displayName: null }).expect(200);
    await t.http.put('/v1/me/profile').set(b.auth).send({ displayName: 'Neo' }).expect(200);
    expect((await t.http.get('/v1/me').set(b.auth).expect(200)).body.displayName).toBe('Neo');
  });
});

describe('challenge catalogue validation', () => {
  it('refuses unknown modules, unknown kinds and duplicates at startup', () => {
    const one = { id: 'c', title: 'C', moduleId: 'basics', points: 10, kind: 'base64-layers', brief: 'b' };
    expect(() => buildCurriculum(source({ challenges: [{ ...one, moduleId: 'ghost' }] }))).toThrow(CurriculumError);
    expect(() => buildCurriculum(source({ challenges: [{ ...one, kind: 'eval-js' }] }))).toThrow();
    expect(() => buildCurriculum(source({ challenges: [one, one] }))).toThrow(/duplicate challenge/);
    expect(() => buildCurriculum(source({ challenges: [{ ...one, points: 0 }] }))).toThrow();
  });
});
