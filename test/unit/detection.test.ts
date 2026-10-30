import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { buildDataset, DATASET_KINDS, toJsonLines, type DatasetKind } from '../../src/detection/datasets.js';
import { ruleSchema, score, type Dataset, type Rule } from '../../src/detection/engine.js';

const rule = (dataset: Dataset, raw: unknown): Rule => ruleSchema(dataset.fields).parse(raw);
const run = (kind: DatasetKind, raw: unknown, seed = randomBytes(32)) => {
  const d = buildDataset(kind, seed);
  return score(rule(d, raw), d);
};

/** A rule a careful analyst would write: each dataset must admit one, on every seed. */
const REFERENCE: Record<DatasetKind, unknown> = {
  'web-sqli': {
    match: [
      { 'query|contains': ["' or ", 'union select', 'order by', 'sleep(', 'substr(', 'drop table', ' and 1=', "'--"] },
      { 'query|endswith': "'" },
    ],
  },
  'auth-spray': { match: { event_id: 4625 }, threshold: { groupBy: 'src_ip', distinct: 'user', min: 8, windowSeconds: 600 } },
  'process-lolbins': {
    match: [
      { 'image|endswith': 'powershell.exe', 'command_line|contains': ['-enc', 'downloadstring', 'iex'] },
      { 'image|endswith': ['certutil.exe', 'rundll32.exe', 'regsvr32.exe', 'bitsadmin.exe'], 'command_line|contains': ['-urlcache', 'javascript:', '/i:http', '/transfer'] },
      { 'image|endswith': 'mshta.exe', 'command_line|contains': 'http' },
      { 'parent_image|endswith': ['winword.exe', 'excel.exe'], 'image|endswith': ['cmd.exe', 'powershell.exe'] },
    ],
  },
  'ssh-bruteforce': {
    match: { event: ['failed_password', 'invalid_user'] },
    threshold: { groupBy: 'src_ip', min: 10, windowSeconds: 3600 },
  },
};

describe('detection datasets', () => {
  it.each(DATASET_KINDS)('%s: a careful rule catches every attack with no false positive, on any learner seed', (kind) => {
    for (let i = 0; i < 25; i++) {
      const s = run(kind, REFERENCE[kind]);
      expect(s, `seed #${String(i)}`).toMatchObject({ missed: 0, falsePositives: 0, perfect: true });
      expect(s.total).toBeGreaterThan(1);
    }
  });

  it('web-sqli: the lazy rules fall into the traps (apostrophes in names, "select" and "union" in searches)', () => {
    expect(run('web-sqli', { match: { 'query|contains': "'" } }).falsePositives).toBeGreaterThan(0); // O'Connor, rock'n'roll
    expect(run('web-sqli', { match: { 'query|contains': ['select', 'union'] } }).falsePositives).toBeGreaterThan(0);
    // Signature on the tool only: the attacker with a browser user agent walks through.
    expect(run('web-sqli', { match: { 'user_agent|contains': 'sqlmap' } }).missed).toBeGreaterThan(0);
  });

  it('auth-spray: counting failures flags the service account; counting users without filtering flags the terminal server', () => {
    expect(run('auth-spray', { match: { event_id: 4625 }, threshold: { groupBy: 'src_ip', min: 8, windowSeconds: 600 } }).falsePositives).toBeGreaterThan(0);
    expect(run('auth-spray', { match: { 'event_id|gte': 4624 }, threshold: { groupBy: 'src_ip', distinct: 'user', min: 8, windowSeconds: 600 } }).falsePositives).toBeGreaterThan(0);
  });

  it('process-lolbins: alerting on the binary name alone drowns the SOC in legitimate admin activity', () => {
    const byName = run('process-lolbins', { match: { 'image|endswith': ['certutil.exe', 'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'bitsadmin.exe'] } });
    expect(byName.falsePositives).toBeGreaterThan(0);
    expect(run('process-lolbins', { match: { 'command_line|contains': 'hidden' } }).falsePositives).toBeGreaterThan(0); // the monitoring agent
  });

  it('ssh-bruteforce: a short window misses the slow attacker; no event filter flags monitoring and the jump host', () => {
    expect(run('ssh-bruteforce', { match: { event: ['failed_password', 'invalid_user'] }, threshold: { groupBy: 'src_ip', min: 10, windowSeconds: 120 } }).missed).toBe(1);
    expect(run('ssh-bruteforce', { match: { program: 'sshd' }, threshold: { groupBy: 'src_ip', min: 10, windowSeconds: 3600 } }).falsePositives).toBeGreaterThan(0);
    // Too sensitive: the person who forgot their password is not an attacker.
    expect(run('ssh-bruteforce', { match: { event: 'failed_password' }, threshold: { groupBy: 'src_ip', min: 5, windowSeconds: 3600 } }).falsePositives).toBeGreaterThan(0);
  });

  it('is deterministic per learner and differs between learners; ids carry no hint', () => {
    const seed = randomBytes(32);
    for (const kind of DATASET_KINDS) {
      expect(toJsonLines(buildDataset(kind, seed))).toBe(toJsonLines(buildDataset(kind, seed)));
      expect(toJsonLines(buildDataset(kind, seed))).not.toBe(toJsonLines(buildDataset(kind, randomBytes(32))));
      const d = buildDataset(kind, seed);
      // Events are numbered in time order, so position says nothing about maliciousness.
      expect(d.events.map((e) => Number(e.ts))).toEqual([...d.events.map((e) => Number(e.ts))].sort((a, b) => a - b));
      expect(d.events.length).toBeLessThan(400);
    }
  });
});

describe('detection rule language', () => {
  const d = buildDataset('web-sqli', randomBytes(32));
  const parse = (raw: unknown) => ruleSchema(d.fields).safeParse(raw).success;

  it('accepts only dataset fields and known modifiers: no prototype keys, no regex', () => {
    expect(parse({ match: { 'query|contains': 'x' } })).toBe(true);
    expect(parse({ match: { __proto__: 'x' } })).toBe(false);
    expect(parse({ match: JSON.parse('{"__proto__": {"polluted": 1}}') as unknown })).toBe(false);
    // Rejected, not silently dropped, even next to a valid key.
    expect(parse({ match: JSON.parse('{"__proto__": "x", "query": "a"}') as unknown })).toBe(false);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(parse({ match: { constructor: 'x' } })).toBe(false);
    expect(parse({ match: { 'query|re': '(a+)+$' } })).toBe(false);
    expect(parse({ match: { 'query|contains|all': 'x' } })).toBe(false);
    expect(parse({ match: { password: 'x' } })).toBe(false);
    expect(parse({ match: {} })).toBe(false);
    expect(parse({ match: { query: 'x' }, extra: 1 })).toBe(false);
    expect(parse({ match: { query: 'x' }, threshold: { groupBy: 'nope', min: 2, windowSeconds: 1 } })).toBe(false);
  });

  it('caps every dimension', () => {
    const many = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [i % 2 ? 'query|contains' : `query|${['startswith', 'endswith'][i % 2] ?? ''}`, 'x']));
    expect(parse({ match: Array.from({ length: 11 }, () => ({ query: 'x' })) })).toBe(false);
    expect(parse({ match: { query: Array.from({ length: 21 }, () => 'x') } })).toBe(false);
    expect(parse({ match: { query: 'x'.repeat(201) } })).toBe(false);
    expect(parse({ match: many(2) })).toBe(true);
  });

  it('matches case-insensitively, compares numbers, and applies exclusions', () => {
    const one = (raw: unknown) => score(ruleSchema(d.fields).parse(raw), d).alerts;
    expect(one({ match: { 'query|contains': 'UNION SELECT' } })).toBe(one({ match: { 'query|contains': 'union select' } }));
    expect(one({ match: { 'status|gte': 500 } })).toBeGreaterThan(0);
    expect(one({ match: { 'status|lte': 99 } })).toBe(0);
    expect(one({ match: { 'path|startswith': '/' }, exclude: { 'path|startswith': '/' } })).toBe(0);
    expect(one({ match: { 'path|startswith': '/' } })).toBe(d.events.length);
  });
});
