import { createHmac, timingSafeEqual } from 'node:crypto';
import type { AuditLog } from '../audit.js';
import { buildArtifact } from '../challenges/generators.js';
import { buildDataset, toJsonLines, type DatasetKind } from '../detection/datasets.js';
import { ruleSchema, score, type Dataset, type Score } from '../detection/engine.js';
import { scoreWazuh, WazuhRuleError, type WazuhDataset } from '../detection/wazuh.js';
import { BASTION_BASE_RULE, buildWazuhDataset, toAlertLines, type WazuhDatasetKind } from '../detection/wazuh-datasets.js';
import type { Challenge, Curriculum } from '../curriculum/catalog.js';
import type { Database } from '../db.js';
import { badRequest, forbidden, notFound } from '../errors.js';
import type { LearningService } from './learning-service.js';

/** Points per validated lesson, so learners who only read still show up on the scoreboard. */
export const LESSON_POINTS = 10;
const SCOREBOARD_SIZE = 50;
const FLAG_FORMAT = /^BASTION\{[0-9a-f]{32}\}$/;

export interface ScoreboardEntry {
  rank: number;
  displayName: string;
  score: number;
}

/**
 * Challenges with per-learner flags.
 *
 * flag = "BASTION{" + HMAC-SHA256(FLAG_HMAC_KEY, challenge || user)[:128 bits] + "}"
 *
 * - Nothing to store and nothing to leak from the database: flags are
 *   recomputed on demand from a key that lives only in the configuration.
 * - Sharing is useless: a flag is valid for one account only. Sharing is also
 *   visible: a submitted flag that matches another learner's is attributed to
 *   that learner in the audit log (`challenge.flag_shared`).
 * - Comparison is constant-time, and attempts are rate-limited per account.
 */
export class ChallengeService {
  constructor(
    private readonly db: Database,
    private readonly curriculum: Curriculum,
    private readonly learning: LearningService,
    private readonly audit: AuditLog,
    private readonly flagKey: Buffer,
  ) {}

  private mac(purpose: string, challengeId: string, userId: string): Buffer {
    return createHmac('sha256', this.flagKey).update(`bastion:${purpose}:v1:${challengeId}:${userId}`).digest();
  }

  flagFor(userId: string, challengeId: string): string {
    return `BASTION{${this.mac('flag', challengeId, userId).subarray(0, 16).toString('hex')}}`;
  }

  private challenge(id: string): Challenge {
    const c = this.curriculum.challenges.get(id);
    if (!c) throw notFound('Challenge not found');
    return c;
  }

  private solves(userId: string): Map<string, number> {
    const rows = this.db.prepare('SELECT challenge_id, solved_at FROM challenge_solves WHERE user_id = ?').all(userId) as {
      challenge_id: string;
      solved_at: number;
    }[];
    return new Map(rows.map((r) => [r.challenge_id, r.solved_at]));
  }

  private assertUnlocked(userId: string, c: Challenge, ip: string | null): void {
    if (this.learning.isModuleUnlocked(userId, c.moduleId)) return;
    this.audit.record({ action: 'challenge.submit', outcome: 'denied', actorId: userId, target: c.id, ip, details: { reason: 'locked' } });
    throw forbidden('Complete the prerequisite modules first');
  }

  list(userId: string) {
    const solved = this.solves(userId);
    const items = [...this.curriculum.challenges.values()].map((c) => {
      const at = solved.get(c.id);
      return {
        id: c.id,
        title: c.title,
        moduleId: c.moduleId,
        points: c.points,
        unlocked: this.learning.isModuleUnlocked(userId, c.moduleId),
        solved: at !== undefined,
        solvedAt: at === undefined ? null : new Date(at).toISOString(),
      };
    });
    return { items };
  }

  get(userId: string, challengeId: string, ip: string | null) {
    const c = this.challenge(challengeId);
    this.assertUnlocked(userId, c, ip);
    const at = this.solves(userId).get(c.id);
    return {
      id: c.id,
      title: c.title,
      moduleId: c.moduleId,
      points: c.points,
      brief: c.brief,
      // A lab challenge has no artifact: the flag lives inside the learner's own running lab.
      // A detection challenge has no flag at all: the learner's dataset is the artifact, a rule is the answer.
      artifact:
        c.kind !== undefined
          ? buildArtifact(c.kind, this.flagFor(userId, c.id), this.mac('artifact', c.id, userId))
          : c.detection !== undefined
            ? { events: toJsonLines(this.dataset(userId, c.id, c.detection)) }
            : c.wazuh !== undefined
              ? this.wazuhArtifact(this.wazuhDataset(userId, c.id, c.wazuh))
              : {},
      lab: c.lab ?? null,
      detection:
        c.detection !== undefined
          ? this.detectionInfo(this.dataset(userId, c.id, c.detection))
          : c.wazuh !== undefined
            ? this.wazuhInfo(this.wazuhDataset(userId, c.id, c.wazuh))
            : null,
      solved: at !== undefined,
      solvedAt: at === undefined ? null : new Date(at).toISOString(),
    };
  }

  submit(userId: string, challengeId: string, flag: string, ip: string | null) {
    const c = this.challenge(challengeId);
    this.assertUnlocked(userId, c, ip);

    if (safeEqual(flag, this.flagFor(userId, c.id))) {
      // Idempotent: a second correct submission keeps the first timestamp and scores nothing more.
      const inserted = this.db
        .prepare('INSERT INTO challenge_solves (user_id, challenge_id, points, solved_at) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING')
        .run(userId, c.id, c.points, Date.now());
      const firstSolve = Number(inserted.changes) === 1;
      if (firstSolve) this.audit.record({ action: 'challenge.submit', outcome: 'success', actorId: userId, target: c.id, ip, details: { points: c.points } });
      return { correct: true as const, points: c.points, alreadySolved: !firstSolve };
    }

    const owner = this.flagOwner(c.id, flag, userId);
    if (owner) {
      this.audit.record({ action: 'challenge.flag_shared', outcome: 'denied', actorId: userId, target: c.id, ip, details: { owner } });
    } else {
      this.audit.record({ action: 'challenge.submit', outcome: 'failure', actorId: userId, target: c.id, ip });
    }
    // Same answer either way: the submitter learns nothing about other accounts.
    return { correct: false as const };
  }

  private dataset(userId: string, challengeId: string, kind: DatasetKind): Dataset {
    return buildDataset(kind, this.mac('dataset', challengeId, userId));
  }

  private detectionInfo(d: Dataset) {
    return { format: 'json' as const, fields: d.fields, unit: d.unit, entityField: d.entityField ?? null, events: d.events.length, minLevel: null };
  }

  private wazuhDataset(userId: string, challengeId: string, kind: WazuhDatasetKind): WazuhDataset {
    return buildWazuhDataset(kind, this.mac('dataset', challengeId, userId));
  }

  private wazuhInfo(d: WazuhDataset) {
    return { format: 'wazuh' as const, fields: d.fields, unit: d.unit, entityField: d.entityField ?? null, events: d.events.length, minLevel: d.minLevel };
  }

  /** The alerts, the stock rules they reached (a learner rule must refine one), and the brief's base rule if any. */
  private wazuhArtifact(d: WazuhDataset): Record<string, string> {
    const stock = d.stock
      .map((r) => `${String(r.id)} (niveau ${String(r.level)}${r.parent === undefined ? '' : `, enfant de ${String(r.parent)}`}) ${r.description} · groupes : ${r.groups.join(', ')}`)
      .join('\n');
    return {
      'alerts.json': toAlertLines(d),
      'Règles déjà en place': stock,
      ...(d.decoder === 'json' ? { 'Règle de base (fournie)': BASTION_BASE_RULE } : {}),
    };
  }

  /**
   * Blue-team challenges: the learner's rule is evaluated against their own
   * labelled dataset. Solved when every attack is caught with no false
   * positive. The rule language is closed and bounded (ADR 0010); unknown
   * fields or modifiers are a 400 with the reason.
   */
  detect(userId: string, challengeId: string, rawRule: unknown, ip: string | null) {
    const c = this.challenge(challengeId);
    if (c.detection === undefined && c.wazuh === undefined) throw notFound('This challenge takes a flag, not a detection rule');
    this.assertUnlocked(userId, c, ip);
    let result: Score;
    if (c.wazuh !== undefined) {
      // Wazuh challenges take the XML text of local rules (ADR 0014), parsed by a closed reader.
      if (typeof rawRule !== 'string') throw badRequest('This challenge takes Wazuh XML rules, as text');
      try {
        result = scoreWazuh(rawRule, this.wazuhDataset(userId, c.id, c.wazuh));
      } catch (err) {
        if (err instanceof WazuhRuleError) throw badRequest(err.message);
        throw err;
      }
    } else {
      if (typeof rawRule !== 'object' || rawRule === null || Array.isArray(rawRule)) throw badRequest('This challenge takes a JSON detection rule');
      const dataset = this.dataset(userId, c.id, c.detection ?? 'web-sqli');
      result = score(ruleSchema(dataset.fields).parse(rawRule), dataset);
    }

    if (!result.perfect) {
      this.audit.record({ action: 'challenge.submit', outcome: 'failure', actorId: userId, target: c.id, ip, details: { detected: result.detected, falsePositives: result.falsePositives } });
      return { ...result, solved: false, points: 0, alreadySolved: false };
    }
    const inserted = this.db
      .prepare('INSERT INTO challenge_solves (user_id, challenge_id, points, solved_at) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING')
      .run(userId, c.id, c.points, Date.now());
    const firstSolve = Number(inserted.changes) === 1;
    if (firstSolve) this.audit.record({ action: 'challenge.submit', outcome: 'success', actorId: userId, target: c.id, ip, details: { points: c.points } });
    return { ...result, solved: true, points: c.points, alreadySolved: !firstSolve };
  }

  /** Whose flag is this? Only learners who solved the challenge can have leaked it. */
  private flagOwner(challengeId: string, flag: string, submitter: string): string | null {
    if (!FLAG_FORMAT.test(flag)) return null;
    // Cross-user by design: reads only ids of solvers, never returned to the client.
    const solvers = this.db
      .prepare('SELECT user_id FROM challenge_solves WHERE challenge_id = ? AND user_id != ?')
      .all(challengeId, submitter) as { user_id: string }[];
    return solvers.find((s) => safeEqual(flag, this.flagFor(s.user_id, challengeId)))?.user_id ?? null;
  }

  /**
   * Opt-in scoreboard: only learners who chose a display name appear, and only
   * that name and a score are published (no id, no e-mail). Ties go to whoever
   * got there first.
   */
  scoreboard(userId: string): { entries: ScoreboardEntry[]; me: { score: number; rank: number | null; displayName: string | null } } {
    // Aggregates over every learner on purpose: this is the one cross-user read,
    // and it projects nothing but the public pseudonym and the score.
    const rows = this.db
      .prepare(
        `SELECT u.id AS user_id, u.display_name AS display_name,
                COALESCE(lp.n, 0) * ? + COALESCE(cs.pts, 0) AS score,
                MAX(COALESCE(lp.last, 0), COALESCE(cs.last, 0)) AS last_at
         FROM users u
         LEFT JOIN (SELECT user_id, COUNT(*) AS n, MAX(completed_at) AS last FROM lesson_progress GROUP BY user_id) lp ON lp.user_id = u.id
         LEFT JOIN (SELECT user_id, SUM(points) AS pts, MAX(solved_at) AS last FROM challenge_solves GROUP BY user_id) cs ON cs.user_id = u.id
         WHERE u.display_name IS NOT NULL OR u.id = ?
         ORDER BY score DESC, last_at ASC`,
      )
      .all(LESSON_POINTS, userId) as { user_id: string; display_name: string | null; score: number; last_at: number }[];

    const ranked = rows.filter((r) => r.display_name !== null && r.score > 0);
    const entries = ranked.slice(0, SCOREBOARD_SIZE).map((r, i) => ({ rank: i + 1, displayName: r.display_name ?? '', score: r.score }));
    const mine = rows.find((r) => r.user_id === userId);
    const myRank = ranked.findIndex((r) => r.user_id === userId);
    return {
      entries,
      me: { score: mine?.score ?? 0, rank: myRank === -1 ? null : myRank + 1, displayName: mine?.display_name ?? null },
    };
  }
}

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
