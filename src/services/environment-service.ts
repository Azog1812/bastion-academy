import type { AuditLog } from '../audit.js';
import type { Curriculum } from '../curriculum/catalog.js';
import { forbidden, notFound, unavailable } from '../errors.js';
import { ENVIRONMENT_IDS, ENVIRONMENTS, type EnvironmentId, type EnvironmentState } from '../labs/environments.js';
import { LabRunnerError } from './lab-service.js';
import type { LearningService } from './learning-service.js';

export interface EnvironmentStatus {
  state: EnvironmentState;
  startedAt: number | null;
}

/** What the platform needs from the lab runner for shared environments. Injected, so tests use a fake. */
export interface EnvironmentRunnerClient {
  environmentStatus(id: EnvironmentId): Promise<EnvironmentStatus>;
  startEnvironment(id: EnvironmentId): Promise<EnvironmentStatus>;
  stopEnvironment(id: EnvironmentId): Promise<void>;
}

const isEnvironmentId = (id: string): id is EnvironmentId => (ENVIRONMENT_IDS as readonly string[]).includes(id);

/**
 * Shared environments (ADR 0013): one real Wazuh for the installation, started and
 * stopped from the web UI. A learner may act on it only with its optional module
 * added and unlocked (the same server-side gate as lessons and labs); every start and
 * stop is audited. Secrets never reach the browser: the login hint names the .env
 * variable, the password stays on the host.
 */
export class EnvironmentService {
  constructor(
    private readonly curriculum: Curriculum,
    private readonly learning: LearningService,
    private readonly audit: AuditLog,
    private readonly runner: EnvironmentRunnerClient | undefined,
  ) {}

  /** Environments whose module exists in this curriculum, with this learner's access and the live state. */
  async list(userId: string) {
    const ids = ENVIRONMENT_IDS.filter((id) => this.curriculum.modules.has(ENVIRONMENTS[id].moduleId));
    return Promise.all(ids.map((id) => this.view(userId, id)));
  }

  private async view(userId: string, id: EnvironmentId) {
    const spec = ENVIRONMENTS[id];
    const available = this.learning.isModuleUnlocked(userId, spec.moduleId);
    let status: EnvironmentStatus | null = null;
    // Locked learners learn nothing about the machine's containers.
    if (available && this.runner) status = await this.runner.environmentStatus(id).catch(() => null);
    const state = status?.state ?? 'unavailable';
    const startedAt = status?.startedAt ?? null;
    return {
      id,
      title: spec.title,
      moduleId: spec.moduleId,
      available,
      state,
      url: state === 'running' ? spec.url : null,
      login: available ? spec.login : null,
      stopsAt: startedAt === null ? null : new Date(startedAt + spec.maxRunSeconds * 1000).toISOString(),
    };
  }

  private gate(userId: string, rawId: string, action: 'environment.start' | 'environment.stop', ip: string | null): EnvironmentId {
    if (!isEnvironmentId(rawId) || !this.curriculum.modules.has(ENVIRONMENTS[rawId].moduleId)) throw notFound('Environment not found');
    if (!this.learning.isModuleUnlocked(userId, ENVIRONMENTS[rawId].moduleId)) {
      this.audit.record({ action, outcome: 'denied', actorId: userId, target: rawId, ip, details: { reason: 'locked' } });
      throw forbidden('Add the module to your training and complete its prerequisites first');
    }
    if (!this.runner) throw unavailable('Environments need the lab runner (docker compose up)');
    return rawId;
  }

  async start(userId: string, rawId: string, ip: string | null) {
    const id = this.gate(userId, rawId, 'environment.start', ip);
    try {
      await this.runner?.startEnvironment(id);
    } catch (err) {
      const code = err instanceof LabRunnerError ? err.code : 'unreachable';
      this.audit.record({ action: 'environment.start', outcome: 'failure', actorId: userId, target: id, ip, details: { reason: code } });
      throw unavailable(
        code === 'environment_missing'
          ? `Not installed yet: run "docker compose --profile ${id} up -d" once`
          : 'The environment could not be started, try again in a moment',
      );
    }
    this.audit.record({ action: 'environment.start', outcome: 'success', actorId: userId, target: id, ip });
    return this.view(userId, id);
  }

  async stop(userId: string, rawId: string, ip: string | null): Promise<void> {
    const id = this.gate(userId, rawId, 'environment.stop', ip);
    try {
      await this.runner?.stopEnvironment(id);
    } catch {
      this.audit.record({ action: 'environment.stop', outcome: 'failure', actorId: userId, target: id, ip });
      throw unavailable('The environment could not be stopped, try again in a moment');
    }
    this.audit.record({ action: 'environment.stop', outcome: 'success', actorId: userId, target: id, ip });
  }
}
