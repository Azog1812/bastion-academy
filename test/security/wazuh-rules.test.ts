import { describe, expect, it } from 'vitest';
import { buildCurriculum } from '../../src/curriculum/catalog.js';
import { auditActions, newUser, setup, type Session, type TestContext } from '../helpers.js';

/** basics (mandatory) -> wazuh (optional): a Wazuh rule challenge; basics also holds a JSON detection challenge. */
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
  challenges: {
    challenges: [
      { id: 'wz-ssh', title: 'SSH', moduleId: 'wazuh', points: 300, wazuh: 'wazuh-ssh', brief: 'rules' },
      { id: 'wz-bastion', title: 'Bastion', moduleId: 'wazuh', points: 350, wazuh: 'wazuh-bastion', brief: 'rules' },
      { id: 'json-ssh', title: 'JSON', moduleId: 'basics', points: 250, detection: 'ssh-bruteforce', brief: 'detect' },
    ],
  },
});

const GOOD = `<group name="local,sshd,">
  <rule id="100100" level="10" frequency="8" timeframe="3600">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_srcip />
    <srcip>!10.0.5.20</srcip>
    <description>sshd : force brute depuis $(srcip)</description>
  </rule>
</group>`;
const WIDE = GOOD.replace('!10.0.5.20', '!10.0.5.0/24');

const ctx = (quiz = 10_000) => setup({ curriculum, rateLimits: { quiz } });
const detect = (t: TestContext, s: Session, id: string, rule: unknown) => t.http.post(`/v1/challenges/${id}/detect`).set(s.auth).send({ rule });
const ready = async (t: TestContext, s: Session) => {
  await t.http.put('/v1/me/modules/wazuh').set(s.auth).send({ added: true }).expect(200);
  await t.http.post('/v1/lessons/intro/complete').set(s.auth).send({}).expect(200);
};

describe('Wazuh rule challenges (ADR 0014)', () => {
  it('serve Wazuh-shaped alerts, the stock rules and the base rule, never the labels', async () => {
    const t = ctx();
    const s = await newUser(t);
    await ready(t, s);
    const res = await t.http.get('/v1/challenges/wz-bastion').set(s.auth).expect(200);
    expect(res.body.detection).toMatchObject({ format: 'wazuh', unit: 'event', minLevel: 10 });
    expect(res.body.detection.fields).toContain('action');
    const alerts = (res.body.artifact['alerts.json'] as string).split('\n');
    expect(alerts.length).toBe(res.body.detection.events);
    expect(JSON.parse(alerts[0] ?? '{}')).toMatchObject({ id: 'e001', rule: { id: '100000' }, decoder: { name: 'json' } });
    expect(res.body.artifact['Règle de base (fournie)']).toContain('<rule id="100000"');
    expect(JSON.stringify(res.body)).not.toMatch(/malicious|"bad"|label|BASTION\{/i);
    const ssh = await t.http.get('/v1/challenges/wz-ssh').set(s.auth).expect(200);
    expect(ssh.body.artifact['Règles déjà en place']).toContain('5716 (niveau 5)');
    expect(ssh.body.artifact).not.toHaveProperty('Règle de base (fournie)');
  });

  it('an imperfect rule gets feedback; a perfect one solves, once, and is audited', async () => {
    const t = ctx();
    const s = await newUser(t);
    await ready(t, s);
    expect((await detect(t, s, 'wz-ssh', WIDE).expect(200)).body).toMatchObject({ solved: false, points: 0, missed: 1, falsePositives: 0, examples: { missed: ['10.0.5.77'] } });
    expect((await detect(t, s, 'wz-ssh', GOOD).expect(200)).body).toMatchObject({ solved: true, points: 300, alreadySolved: false });
    expect((await detect(t, s, 'wz-ssh', GOOD).expect(200)).body).toMatchObject({ solved: true, alreadySolved: true });
    expect(auditActions(t).filter((a) => a.startsWith('challenge.submit'))).toEqual(['challenge.submit:failure', 'challenge.submit:success']);
  });

  it('stays closed until the optional module is added and unlocked', async () => {
    const t = ctx();
    const s = await newUser(t);
    await detect(t, s, 'wz-ssh', GOOD).expect(403);
    await t.http.get('/v1/challenges/wz-ssh').set(s.auth).expect(403);
    await t.http.put('/v1/me/modules/wazuh').set(s.auth).send({ added: true }).expect(200);
    await detect(t, s, 'wz-ssh', GOOD).expect(403); // prerequisites not done yet
    await t.http.post('/v1/lessons/intro/complete').set(s.auth).send({}).expect(200);
    await detect(t, s, 'wz-ssh', GOOD).expect(200);
    await t.http.post('/v1/challenges/wz-ssh/detect').send({ rule: GOOD }).expect(401);
  });

  it('rejects hostile XML with a 400 that says why, without leaking internals', async () => {
    const t = ctx();
    const s = await newUser(t);
    await ready(t, s);
    const xxe = '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><rule id="100100" level="10">&x;</rule>';
    const res = await detect(t, s, 'wz-ssh', xxe).expect(400);
    expect(res.body.message).toMatch(/DOCTYPE/);
    expect(JSON.stringify(res.body)).not.toMatch(/root:|stack|at \w+ \(/);
    expect((await detect(t, s, 'wz-ssh', '<rule id="100100" level="10"><if_sid>5716</if_sid><regex>(a+)+$</regex><description>x</description></rule>').expect(400)).body.message).toMatch(/expressions régulières/);
    await detect(t, s, 'wz-ssh', 'x'.repeat(8001)).expect(400);
    await detect(t, s, 'wz-ssh', '').expect(400);
  });

  it('each challenge takes its own rule format', async () => {
    const t = ctx();
    const s = await newUser(t);
    await ready(t, s);
    expect((await detect(t, s, 'wz-ssh', { match: { event: 'x' } }).expect(400)).body.message).toMatch(/XML/);
    expect((await detect(t, s, 'json-ssh', GOOD).expect(400)).body.message).toMatch(/JSON/);
    await t.http.post('/v1/challenges/wz-ssh/detect').set(s.auth).send({ rule: GOOD, extra: 1 }).expect(400);
  });

  it('is rate-limited per account like the JSON detection challenges', async () => {
    const t = ctx(2);
    const s = await newUser(t);
    await ready(t, s);
    for (let n = 0; n < 4; n++) await detect(t, s, 'wz-ssh', WIDE).expect(200);
    await detect(t, s, 'wz-ssh', WIDE).expect(429);
  });
});
