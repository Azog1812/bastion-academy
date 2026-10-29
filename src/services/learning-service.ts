import type { AuditLog } from '../audit.js';
import type { Curriculum, Lesson, Module } from '../curriculum/catalog.js';
import type { Database } from '../db.js';
import { badRequest, forbidden, notFound } from '../errors.js';

export interface QuizAnswer {
  question: string;
  choices: number[];
}

export type CompletionResult =
  | { passed: true; completedAt: string; alreadyCompleted: boolean }
  | { passed: false; incorrect: string[] };

/**
 * Progress is always read and written for the authenticated user only:
 * every query is scoped by `user_id` in the SQL, there is no route that takes
 * a user id as input, so one learner can never read or forge another's
 * progress (same model as notes, see note-service.ts).
 *
 * Gating (prerequisites, quizzes) is enforced here, server-side. The client
 * only displays it: a learner who edits the front-end gains nothing.
 */
export class LearningService {
  constructor(
    private readonly db: Database,
    private readonly curriculum: Curriculum,
    private readonly audit: AuditLog,
  ) {}

  private completed(userId: string): Map<string, number> {
    const rows = this.db.prepare('SELECT lesson_id, completed_at FROM lesson_progress WHERE user_id = ?').all(userId) as {
      lesson_id: string;
      completed_at: number;
    }[];
    return new Map(rows.map((r) => [r.lesson_id, r.completed_at]));
  }

  private static moduleDone(m: Module, done: ReadonlyMap<string, number>): boolean {
    return m.lessons.every((l) => done.has(l.id));
  }

  private unlocked(m: Module, done: ReadonlyMap<string, number>): boolean {
    return m.prerequisites.every((p) => {
      const req = this.curriculum.modules.get(p);
      return req !== undefined && LearningService.moduleDone(req, done);
    });
  }

  private lesson(lessonId: string): Lesson {
    const lesson = this.curriculum.lessons.get(lessonId);
    if (!lesson) throw notFound('Lesson not found');
    return lesson;
  }

  private assertUnlocked(userId: string, lesson: Lesson, done: ReadonlyMap<string, number>, ip: string | null): void {
    const mod = this.curriculum.modules.get(lesson.moduleId);
    if (mod && this.unlocked(mod, done)) return;
    this.audit.record({ action: 'lesson.complete', outcome: 'denied', actorId: userId, target: lesson.id, ip, details: { reason: 'locked' } });
    throw forbidden('Complete the prerequisite modules first');
  }

  /** The whole catalogue with this user's progress. Quiz answers are never part of it. */
  overview(userId: string) {
    const done = this.completed(userId);
    let completed = 0;
    let total = 0;
    const paths = this.curriculum.paths.map((p) => ({
      id: p.id,
      title: p.title,
      summary: p.summary,
      level: p.level,
      modules: p.modules.map((m) => {
        const lessons = m.lessons.map((l) => {
          total++;
          if (done.has(l.id)) completed++;
          return { id: l.id, title: l.title, minutes: l.minutes, hasQuiz: l.quiz.length > 0, completed: done.has(l.id) };
        });
        return {
          id: m.id,
          title: m.title,
          summary: m.summary,
          prerequisites: m.prerequisites,
          unlocked: this.unlocked(m, done),
          completed: LearningService.moduleDone(m, done),
          lessons,
        };
      }),
    }));
    return { levels: this.curriculum.levels, paths, progress: { completed, total } };
  }

  getLesson(userId: string, lessonId: string, ip: string | null) {
    const lesson = this.lesson(lessonId);
    const done = this.completed(userId);
    this.assertUnlocked(userId, lesson, done, ip);
    const completedAt = done.get(lesson.id);
    return {
      id: lesson.id,
      pathId: lesson.pathId,
      moduleId: lesson.moduleId,
      title: lesson.title,
      minutes: lesson.minutes,
      body: lesson.body,
      references: lesson.references,
      // Explicit projection: `answer` must never reach the client.
      quiz: lesson.quiz.map((q) => ({ id: q.id, prompt: q.prompt, choices: q.choices, multiple: q.answer.length > 1 })),
      completed: completedAt !== undefined,
      completedAt: completedAt === undefined ? null : new Date(completedAt).toISOString(),
    };
  }

  complete(userId: string, lessonId: string, answers: QuizAnswer[], ip: string | null): CompletionResult {
    const lesson = this.lesson(lessonId);
    const done = this.completed(userId);
    this.assertUnlocked(userId, lesson, done, ip);

    const incorrect = grade(lesson, answers);
    if (incorrect.length > 0) {
      this.audit.record({
        action: 'lesson.complete',
        outcome: 'failure',
        actorId: userId,
        target: lesson.id,
        ip,
        details: { incorrect: incorrect.length, questions: lesson.quiz.length },
      });
      return { passed: false, incorrect };
    }

    // Idempotent: completing twice keeps the first timestamp (no score farming later).
    const now = Date.now();
    const row = this.db
      .prepare(
        `INSERT INTO lesson_progress (user_id, lesson_id, completed_at) VALUES (?, ?, ?)
         ON CONFLICT (user_id, lesson_id) DO UPDATE SET completed_at = completed_at
         RETURNING completed_at`,
      )
      .get(userId, lesson.id, now) as { completed_at: number };
    const alreadyCompleted = done.has(lesson.id);
    if (!alreadyCompleted) {
      this.audit.record({ action: 'lesson.complete', outcome: 'success', actorId: userId, target: lesson.id, ip });
    }
    return { passed: true, completedAt: new Date(row.completed_at).toISOString(), alreadyCompleted };
  }
}

/**
 * Returns the ids of wrongly answered questions. Every question must be
 * answered exactly once; an answer to an unknown question is a client bug or
 * a probe, and is rejected rather than ignored.
 */
function grade(lesson: Lesson, answers: QuizAnswer[]): string[] {
  const byId = new Map<string, number[]>();
  for (const a of answers) {
    if (byId.has(a.question)) throw badRequest(`Question "${a.question}" answered twice`);
    byId.set(a.question, a.choices);
  }
  const known = new Set(lesson.quiz.map((q) => q.id));
  for (const id of byId.keys()) {
    if (!known.has(id)) throw badRequest('Answer to an unknown question');
  }
  if (byId.size !== known.size) throw badRequest('Every question must be answered');

  return lesson.quiz
    .filter((q) => {
      const given = new Set(byId.get(q.id));
      return given.size !== q.answer.length || q.answer.some((i) => !given.has(i));
    })
    .map((q) => q.id);
}
