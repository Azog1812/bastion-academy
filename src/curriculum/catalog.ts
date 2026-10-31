import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { CHALLENGE_KINDS } from '../challenges/generators.js';
import { DATASET_KINDS } from '../detection/datasets.js';
import { LAB_IDS } from '../labs/catalog.js';

/**
 * Curriculum as code (ADR 0006).
 *
 * Learning content lives in `content/` and ships through the same pipeline as
 * the code: pull request, CI, signed image. There is no admin endpoint that
 * writes content, so there is no CMS to compromise and no stored-XSS path from
 * an admin form. Content is validated at startup and the server refuses to
 * start on any inconsistency (fail closed, like the config).
 */

/**
 * Ids end up in URLs and file paths: no dot, no slash, no backslash, so path
 * traversal is impossible by construction. Linear regex (no nested quantifier).
 */
export const slug = z.string().max(64).regex(/^[a-z0-9][a-z0-9-]*$/, 'must be a lowercase slug');

const questionSchema = z
  .object({
    id: slug,
    prompt: z.string().min(1).max(500),
    choices: z.array(z.string().min(1).max(300)).min(2).max(6),
    /** Indexes of the correct choices. Never sent to the client. */
    answer: z.array(z.number().int().min(0)).min(1),
  })
  .strict()
  .refine((q) => q.answer.every((i) => i < q.choices.length), 'answer index out of range')
  .refine((q) => new Set(q.answer).size === q.answer.length, 'duplicate answer index');

const lessonSchema = z
  .object({
    id: slug,
    title: z.string().min(1).max(120),
    minutes: z.number().int().min(1).max(240),
    references: z
      .array(z.object({ label: z.string().min(1).max(120), url: z.url({ protocol: /^https$/ }) }).strict())
      .max(10)
      .default([]),
    quiz: z.array(questionSchema).max(20).default([]),
  })
  .strict();

const moduleSchema = z
  .object({
    id: slug,
    title: z.string().min(1).max(120),
    summary: z.string().min(1).max(500),
    /** Module ids that must be fully completed first (any path). */
    prerequisites: z.array(slug).max(10).default([]),
    /**
     * An optional module is off until the learner adds it to their training: it
     * may need more than their machine has (a SIEM, several containers).
     */
    optional: z.boolean().default(false),
    /** What the hands-on part needs, shown before the learner adds the module. */
    requirements: z
      .object({ docker: z.boolean().optional(), ramGb: z.number().int().min(1).max(64).optional() })
      .strict()
      .optional(),
    lessons: z.array(lessonSchema).min(1).max(30),
  })
  .strict();

const pathSchema = z
  .object({
    id: slug,
    title: z.string().min(1).max(120),
    summary: z.string().min(1).max(500),
    level: z.number().int().min(1),
    modules: z.array(moduleSchema).min(1).max(30),
  })
  .strict();

const indexSchema = z
  .object({
    levels: z
      .array(z.object({ level: z.number().int().min(1), title: z.string().min(1).max(80), goal: z.string().min(1).max(300) }).strict())
      .min(1),
    paths: z.array(slug).min(1),
  })
  .strict();

const challengeSchema = z
  .object({
    id: slug,
    title: z.string().min(1).max(120),
    /** Available once this module is unlocked, like its lessons. */
    moduleId: slug,
    points: z.number().int().min(10).max(1000),
    /** Either a generated artifact to analyse… */
    kind: z.enum(CHALLENGE_KINDS).optional(),
    /** …or a live, intentionally vulnerable service to attack (ADR 0009). Both are closed sets. */
    lab: z.enum(LAB_IDS).optional(),
    /** …or a log dataset to write a detection rule for (blue team, ADR 0010). */
    detection: z.enum(DATASET_KINDS).optional(),
    /** Markdown, rendered by the client like a lesson body. */
    brief: z.string().min(1).max(4000),
  })
  .strict()
  .refine((c) => [c.kind, c.lab, c.detection].filter((x) => x !== undefined).length === 1, 'a challenge needs exactly one of "kind", "lab" or "detection"');

const challengesSchema = z.object({ challenges: z.array(challengeSchema).max(200) }).strict();

export type Challenge = z.infer<typeof challengeSchema>;
export type Question = z.infer<typeof questionSchema>;
export type Level = z.infer<typeof indexSchema>['levels'][number];

export interface Lesson extends z.infer<typeof lessonSchema> {
  /** Markdown. Rendered by the client, which must sanitise it (it is never trusted as HTML). */
  body: string;
  moduleId: string;
  pathId: string;
}

export interface Module extends Omit<z.infer<typeof moduleSchema>, 'lessons'> {
  lessons: Lesson[];
  pathId: string;
}

export interface Path extends Omit<z.infer<typeof pathSchema>, 'modules'> {
  modules: Module[];
}

export interface Curriculum {
  levels: Level[];
  paths: Path[];
  modules: ReadonlyMap<string, Module>;
  lessons: ReadonlyMap<string, Lesson>;
  challenges: ReadonlyMap<string, Challenge>;
}

export class CurriculumError extends Error {
  constructor(message: string) {
    super(`invalid curriculum: ${message}`);
    this.name = 'CurriculumError';
  }
}

/** Raw sources, so validation can be unit-tested without touching the file system. */
export interface CurriculumSource {
  index: unknown;
  path: (pathId: string) => unknown;
  body: (pathId: string, lessonId: string) => string;
  /** content/challenges.json; optional so a curriculum can ship without challenges. */
  challenges?: unknown;
}

const MAX_BODY = 100_000;

export function buildCurriculum(src: CurriculumSource): Curriculum {
  const index = indexSchema.parse(src.index);
  const levels = new Set(index.levels.map((l) => l.level));
  if (levels.size !== index.levels.length) throw new CurriculumError('duplicate level');

  const paths: Path[] = [];
  const modules = new Map<string, Module>();
  const lessons = new Map<string, Lesson>();
  const pathIds = new Set<string>();

  for (const pathId of index.paths) {
    if (pathIds.has(pathId)) throw new CurriculumError(`duplicate path "${pathId}"`);
    pathIds.add(pathId);

    const raw = pathSchema.parse(src.path(pathId));
    if (raw.id !== pathId) throw new CurriculumError(`path file "${pathId}" declares id "${raw.id}"`);
    if (!levels.has(raw.level)) throw new CurriculumError(`path "${pathId}" uses unknown level ${raw.level}`);

    const path: Path = { ...raw, modules: [] };
    for (const m of raw.modules) {
      if (modules.has(m.id)) throw new CurriculumError(`duplicate module "${m.id}"`);
      const mod: Module = { ...m, pathId, lessons: [] };
      for (const l of m.lessons) {
        if (lessons.has(l.id)) throw new CurriculumError(`duplicate lesson "${l.id}"`);
        if (new Set(l.quiz.map((q) => q.id)).size !== l.quiz.length) {
          throw new CurriculumError(`duplicate question id in lesson "${l.id}"`);
        }
        const body = src.body(pathId, l.id);
        if (body.trim().length === 0 || body.length > MAX_BODY) {
          throw new CurriculumError(`lesson "${l.id}" body is empty or too long`);
        }
        const lesson: Lesson = { ...l, body, moduleId: m.id, pathId };
        lessons.set(l.id, lesson);
        mod.lessons.push(lesson);
      }
      modules.set(m.id, mod);
      path.modules.push(mod);
    }
    paths.push(path);
  }

  for (const m of modules.values()) {
    for (const p of m.prerequisites) {
      if (!modules.has(p)) throw new CurriculumError(`module "${m.id}" requires unknown module "${p}"`);
      // Leaving an optional module out must never lock the rest of the curriculum.
      if (!m.optional && modules.get(p)?.optional === true) {
        throw new CurriculumError(`mandatory module "${m.id}" cannot require optional module "${p}"`);
      }
    }
  }
  assertAcyclic(modules);

  const challenges = new Map<string, Challenge>();
  for (const c of src.challenges === undefined ? [] : challengesSchema.parse(src.challenges).challenges) {
    if (challenges.has(c.id)) throw new CurriculumError(`duplicate challenge "${c.id}"`);
    if (!modules.has(c.moduleId)) throw new CurriculumError(`challenge "${c.id}" uses unknown module "${c.moduleId}"`);
    challenges.set(c.id, c);
  }

  return { levels: index.levels, paths, modules, lessons, challenges };
}

/** A prerequisite cycle would lock its modules forever: reject it at startup. */
function assertAcyclic(modules: ReadonlyMap<string, Module>): void {
  const state = new Map<string, 'visiting' | 'done'>();
  const visit = (id: string, trail: string[]): void => {
    const s = state.get(id);
    if (s === 'done') return;
    if (s === 'visiting') throw new CurriculumError(`prerequisite cycle: ${[...trail, id].join(' -> ')}`);
    state.set(id, 'visiting');
    for (const p of modules.get(id)?.prerequisites ?? []) visit(p, [...trail, id]);
    state.set(id, 'done');
  };
  for (const id of modules.keys()) visit(id, []);
}

/** Resolves to `<repo>/content` from both `src/curriculum` (tsx) and `dist/curriculum` (build). */
export const DEFAULT_CONTENT_DIR = fileURLToPath(new URL('../../content/', import.meta.url));

export function loadCurriculum(dir: string = DEFAULT_CONTENT_DIR): Curriculum {
  // Only validated slugs reach these paths (see `slug`), so they cannot escape `dir`.
  const read = (...parts: string[]): string =>
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- slug-validated components under a fixed root
    readFileSync(join(dir, ...parts), 'utf8');
  return buildCurriculum({
    index: JSON.parse(read('index.json')) as unknown,
    path: (pathId) => JSON.parse(read(pathId, 'path.json')) as unknown,
    body: (pathId, lessonId) => read(pathId, `${lessonId}.md`),
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- fixed file name under a fixed root
    ...(existsSync(join(dir, 'challenges.json')) ? { challenges: JSON.parse(read('challenges.json')) as unknown } : {}),
  });
}
