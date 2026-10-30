import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildCurriculum, CurriculumError, loadCurriculum, type CurriculumSource } from '../../src/curriculum/catalog.js';
import { LAB_IDS } from '../../src/labs/catalog.js';

const quiz = [{ id: 'q1', prompt: 'p', choices: ['a', 'b'], answer: [0] }];

function source(modules: unknown[], overrides: Partial<CurriculumSource> = {}): CurriculumSource {
  return {
    index: { levels: [{ level: 1, title: 'L1', goal: 'g' }], paths: ['p1'] },
    path: () => ({ id: 'p1', title: 'P', summary: 's', level: 1, modules }),
    body: () => '# lesson',
    ...overrides,
  };
}

const mod = (id: string, prerequisites: string[] = [], lessonIds = [`${id}-l`]) => ({
  id,
  title: id,
  summary: 's',
  prerequisites,
  lessons: lessonIds.map((l) => ({ id: l, title: l, minutes: 5, quiz })),
});

describe('curriculum validation (fail closed at startup)', () => {
  it('builds lookups for a valid curriculum', () => {
    const c = buildCurriculum(source([mod('a'), mod('b', ['a'])]));
    expect(c.lessons.get('b-l')).toMatchObject({ moduleId: 'b', pathId: 'p1', body: '# lesson' });
    expect(c.modules.get('b')?.prerequisites).toEqual(['a']);
  });

  it('rejects ids that could traverse the file system', () => {
    for (const id of ['../etc', 'a/b', 'a\\b', 'A', '.hidden', '']) {
      expect(() => buildCurriculum(source([mod('a', [], [id])]))).toThrow();
    }
  });

  it.each([
    ['duplicate lesson', [mod('a', [], ['x']), mod('b', [], ['x'])], /duplicate lesson "x"/],
    ['duplicate module', [mod('a'), { ...mod('a'), lessons: [{ id: 'other', title: 't', minutes: 5 }] }], /duplicate module "a"/],
    ['unknown prerequisite', [mod('a', ['ghost'])], /unknown module "ghost"/],
    ['prerequisite cycle', [mod('a', ['c']), mod('b', ['a']), mod('c', ['b'])], /prerequisite cycle/],
    ['self prerequisite', [mod('a', ['a'])], /prerequisite cycle/],
  ])('rejects a %s', (_name, modules, error) => {
    expect(() => buildCurriculum(source(modules))).toThrow(error);
  });

  it('rejects inconsistent quizzes', () => {
    const bad = (q: unknown) => source([{ ...mod('a'), lessons: [{ id: 'l', title: 't', minutes: 5, quiz: [q] }] }]);
    expect(() => buildCurriculum(bad({ id: 'q', prompt: 'p', choices: ['a', 'b'], answer: [2] }))).toThrow(/out of range/);
    expect(() => buildCurriculum(bad({ id: 'q', prompt: 'p', choices: ['a', 'b'], answer: [0, 0] }))).toThrow(/duplicate answer/);
    expect(() => buildCurriculum(bad({ id: 'q', prompt: 'p', choices: ['a'], answer: [0] }))).toThrow();
    const twice = source([{ ...mod('a'), lessons: [{ id: 'l', title: 't', minutes: 5, quiz: [...quiz, ...quiz] }] }]);
    expect(() => buildCurriculum(twice)).toThrow(/duplicate question/);
  });

  it('rejects unknown fields, unknown levels, mismatched ids, empty bodies and non-https links', () => {
    expect(() => buildCurriculum(source([{ ...mod('a'), admin: true }]))).toThrow();
    expect(() => buildCurriculum(source([mod('a')], { path: () => ({ id: 'p1', title: 'P', summary: 's', level: 9, modules: [mod('a')] }) }))).toThrow(
      /unknown level 9/,
    );
    expect(() => buildCurriculum(source([mod('a')], { path: () => ({ id: 'other', title: 'P', summary: 's', level: 1, modules: [mod('a')] }) }))).toThrow(
      /declares id "other"/,
    );
    expect(() => buildCurriculum(source([mod('a')], { body: () => '   ' }))).toThrow(/empty or too long/);
    const link = (url: string) => source([{ ...mod('a'), lessons: [{ id: 'l', title: 't', minutes: 5, references: [{ label: 'x', url }] }] }]);
    expect(() => buildCurriculum(link('javascript:alert(1)'))).toThrow();
    expect(() => buildCurriculum(link('http://example.com'))).toThrow();
    expect(() => buildCurriculum(link('https://example.com'))).not.toThrow();
  });

  it('rejects duplicate paths and levels', () => {
    const dupPath = { levels: [{ level: 1, title: 'L', goal: 'g' }], paths: ['p1', 'p1'] };
    expect(() => buildCurriculum(source([mod('a')], { index: dupPath }))).toThrow(/duplicate path/);
    const dupLevel = { levels: [{ level: 1, title: 'L', goal: 'g' }, { level: 1, title: 'M', goal: 'g' }], paths: ['p1'] };
    expect(() => buildCurriculum(source([mod('a')], { index: dupLevel }))).toThrow(CurriculumError);
  });

  it('loads from disk and refuses a tree with a missing lesson file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'curriculum-'));
    try {
      mkdirSync(join(dir, 'p1'));
      const s = source([mod('a')]);
      writeFileSync(join(dir, 'index.json'), JSON.stringify(s.index));
      writeFileSync(join(dir, 'p1', 'path.json'), JSON.stringify(s.path('p1')));
      expect(() => loadCurriculum(dir)).toThrow(/ENOENT/);
      writeFileSync(join(dir, 'p1', 'a-l.md'), '# ok');
      expect(loadCurriculum(dir).lessons.size).toBe(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('the shipped content/ tree is valid', () => {
    const c = loadCurriculum();
    expect(c.lessons.size).toBeGreaterThan(0);
    expect(c.paths[0]?.level).toBe(1);
  });

  it('every lab in the catalog is offered by a shipped challenge (a lab left out would be silently unreachable)', () => {
    const offered = new Set([...loadCurriculum().challenges.values()].map((c) => c.lab).filter((l) => l !== undefined));
    expect([...offered].sort()).toEqual([...LAB_IDS].sort());
  });

  it('every shipped path directory is listed in index.json (a path left out would be silently invisible)', () => {
    const dirs = readdirSync('content', { withFileTypes: true })
      .filter((d) => d.isDirectory() && existsSync(join('content', d.name, 'path.json')))
      .map((d) => d.name);
    expect(dirs.length).toBeGreaterThan(0);
    expect(new Set(loadCurriculum().paths.map((p) => p.id))).toEqual(new Set(dirs));
  });
});
