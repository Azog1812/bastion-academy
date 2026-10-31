import { randomBytes } from 'node:crypto';
import type { AuditLog } from '../audit.js';
import type { Curriculum } from '../curriculum/catalog.js';
import type { Database } from '../db.js';
import { conflict, forbidden, notFound, unavailable } from '../errors.js';
import { labHostname, type LabId } from '../labs/catalog.js';
import type { ChallengeService } from './challenge-service.js';
import type { EnvironmentRunnerClient, EnvironmentStatus } from './environment-service.js';
import type { LearningService } from './learning-service.js';

export interface LabStart {
  instanceId: string;
  lab: LabId;
  flag: string;
  ttlSeconds: number;
}

/** What the platform needs from the lab runner. Injected, so tests use a fake. */
export interface LabRunnerClient {
  start(req: LabStart): Promise<void>;
  stop(instanceId: string): Promise<void>;
}

export class LabRunnerError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(`lab runner answered ${String(status)} ${code}`);
  }
}

/** HTTP client for the runner's internal API. The token never leaves this module. */
export function httpLabRunner(baseUrl: string, token: Buffer, timeoutMs = 60_000): LabRunnerClient & EnvironmentRunnerClient {
  const auth = `Bearer ${token.toString('base64')}`;
  const call = async (method: string, path: string, body?: unknown) => {
    const res = await fetch(new URL(path, baseUrl), {
      method,
      headers: { authorization: auth, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(timeoutMs),
      redirect: 'error',
    });
    if (!res.ok) {
      const code = ((await res.json().catch(() => ({}))) as { error?: unknown }).error;
      throw new LabRunnerError(res.status, typeof code === 'string' ? code : 'unknown');
    }
    return res.status === 204 ? undefined : await res.json();
  };
  // Only the two expected fields are kept from the runner's answer.
  const status = (body: unknown): EnvironmentStatus => {
    const b = (body ?? {}) as { state?: unknown; startedAt?: unknown };
    const state = b.state === 'missing' || b.state === 'stopped' || b.state === 'starting' || b.state === 'running' ? b.state : 'missing';
    return { state, startedAt: typeof b.startedAt === 'number' ? b.startedAt : null };
  };
  return {
    start: async (req) => {
      await call('POST', '/instances', req);
    },
    stop: async (id) => {
      await call('DELETE', `/instances/${id}`);
    },
    environmentStatus: async (id) => status(await call('GET', `/environments/${id}`)),
    startEnvironment: async (id) => status(await call('POST', `/environments/${id}/start`)),
    stopEnvironment: async (id) => {
      await call('POST', `/environments/${id}/stop`);
    },
  };
}

interface InstanceRow {
  id: string;
  challenge_id: string;
  expires_at: number;
}

interface ExpiredRow extends InstanceRow {
  user_id: string;
}

/**
 * Per-learner lab instances (ADR 0009).
 *
 * - The flag injected into a lab is that learner's flag for that challenge
 *   (same HMAC as every other challenge), so exploiting the lab is the only
 *   way to get it, and it is useless to anyone else.
 * - One running lab per learner (UNIQUE in the database), a TTL enforced here
 *   AND by the runner, and starts are rate-limited per account.
 * - Rows are always read and deleted with `user_id` in the SQL (no IDOR on
 *   someone else's lab); the instance id is 128 random bits.
 */
export class LabService {
  constructor(
    private readonly db: Database,
    private readonly curriculum: Curriculum,
    private readonly challenges: ChallengeService,
    private readonly learning: LearningService,
    private readonly audit: AuditLog,
    private readonly runner: LabRunnerClient | undefined,
    private readonly ttlSeconds: number,
    private readonly gatewayPort: number,
    private readonly now: () => number = Date.now,
  ) {}

  private labChallenge(userId: string, challengeId: string, ip: string | null): { id: string; lab: LabId } {
    const c = this.curriculum.challenges.get(challengeId);
    if (!c?.lab) throw notFound('Lab not found');
    if (!this.learning.isModuleUnlocked(userId, c.moduleId)) {
      this.audit.record({ action: 'lab.start', outcome: 'denied', actorId: userId, target: c.id, ip, details: { reason: 'locked' } });
      throw forbidden('Complete the prerequisite modules first');
    }
    return { id: c.id, lab: c.lab };
  }

  private mine(userId: string): InstanceRow | undefined {
    return this.db.prepare('SELECT id, challenge_id, expires_at FROM lab_instances WHERE user_id = ?').get(userId) as InstanceRow | undefined;
  }

  private publicView(row: InstanceRow) {
    return { url: `http://${labHostname(row.id)}:${String(this.gatewayPort)}/`, expiresAt: new Date(row.expires_at).toISOString() };
  }

  /** For the challenge page: is the feature on, and is my lab for this challenge running? */
  view(userId: string, challengeId: string) {
    const row = this.mine(userId);
    const live = row && row.challenge_id === challengeId && row.expires_at > this.now() ? row : undefined;
    return { enabled: this.runner !== undefined, ttlSeconds: this.ttlSeconds, instance: live ? this.publicView(live) : null };
  }

  async start(userId: string, challengeId: string, ip: string | null) {
    const c = this.labChallenge(userId, challengeId, ip);
    if (!this.runner) throw unavailable('Labs are not enabled on this installation');

    const existing = this.mine(userId);
    if (existing && existing.expires_at <= this.now()) await this.destroy(userId, existing, 'lab.expire', ip);
    else if (existing?.challenge_id === c.id) return this.publicView(existing);
    else if (existing) throw conflict('Stop your running lab before starting another one');

    // Claim the slot before any await (TOCTOU): the UNIQUE(user_id) constraint decides between concurrent starts.
    const row: InstanceRow = { id: randomBytes(16).toString('hex'), challenge_id: c.id, expires_at: this.now() + this.ttlSeconds * 1000 };
    try {
      this.db
        .prepare('INSERT INTO lab_instances (id, user_id, challenge_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
        .run(row.id, userId, row.challenge_id, this.now(), row.expires_at);
    } catch {
      throw conflict('A lab is already starting for this account');
    }

    try {
      await this.runner.start({ instanceId: row.id, lab: c.lab, flag: this.challenges.flagFor(userId, c.id), ttlSeconds: this.ttlSeconds });
    } catch (err) {
      this.db.prepare('DELETE FROM lab_instances WHERE id = ? AND user_id = ?').run(row.id, userId);
      const code = err instanceof LabRunnerError ? err.code : 'unreachable';
      this.audit.record({ action: 'lab.start', outcome: 'failure', actorId: userId, target: c.id, ip, details: { reason: code } });
      throw unavailable(
        code === 'lab_image_missing'
          ? 'This lab is not built yet: run "docker compose --profile labs build"'
          : 'The lab could not be started, try again in a moment',
      );
    }
    this.audit.record({ action: 'lab.start', outcome: 'success', actorId: userId, target: c.id, ip, details: { lab: c.lab } });
    return this.publicView(row);
  }

  async stop(userId: string, challengeId: string, ip: string | null): Promise<void> {
    const row = this.mine(userId);
    if (row?.challenge_id !== challengeId) throw notFound('No running lab for this challenge');
    await this.destroy(userId, row, 'lab.stop', ip);
  }

  /** Platform-side TTL. The runner has its own reaper too, so neither side alone keeps a lab alive. */
  async reap(): Promise<number> {
    // Cross-user on purpose: an operator job over expired rows, never exposed over HTTP.
    const expired = this.db
      .prepare('SELECT id, user_id, challenge_id, expires_at FROM lab_instances WHERE expires_at <= ?')
      .all(this.now()) as unknown as ExpiredRow[];
    for (const row of expired) await this.destroy(row.user_id, row, 'lab.expire', null);
    return expired.length;
  }

  private async destroy(userId: string, row: InstanceRow, action: 'lab.stop' | 'lab.expire', ip: string | null): Promise<void> {
    this.db.prepare('DELETE FROM lab_instances WHERE id = ? AND user_id = ?').run(row.id, userId);
    let outcome: 'success' | 'failure' = 'success';
    // If the runner is unreachable, its own TTL reaper removes the containers later.
    await this.runner?.stop(row.id).catch(() => {
      outcome = 'failure';
    });
    this.audit.record({ action, outcome, actorId: userId, target: row.challenge_id, ip });
  }
}
