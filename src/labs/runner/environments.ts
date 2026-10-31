import type { Logger } from 'pino';
import { ENVIRONMENTS, type EnvironmentId, type EnvironmentState } from '../environments.js';
import type { DockerApi } from './docker.js';

export class EnvironmentMissing extends Error {}

export interface EnvironmentStatus {
  state: EnvironmentState;
  /** When the earliest container of a running environment started (ms since epoch). */
  startedAt: number | null;
}

interface Inspect {
  State?: { Running?: boolean; StartedAt?: string; Health?: { Status?: string } };
}

/**
 * Starts and stops shared environments (ADR 0013). The only Docker calls made here
 * are inspect, start and stop, on container names from the catalog: the runner gains
 * no way to create a container, mount a path or change an image through this code.
 */
export class EnvironmentController {
  constructor(
    private readonly docker: DockerApi,
    private readonly logger: Logger,
    private readonly now: () => number = Date.now,
  ) {}

  async status(id: EnvironmentId): Promise<EnvironmentStatus> {
    let missing = false;
    let running = 0;
    let ready = 0;
    let startedAt: number | null = null;
    const containers = ENVIRONMENTS[id].containers;
    for (const name of containers) {
      const res = await this.docker.call('GET', `/containers/${name}/json`);
      if (res.status === 404) {
        missing = true;
        continue;
      }
      this.expect(res.status, [200], 'inspect');
      const state = (res.body as Inspect).State ?? {};
      if (!state.Running) continue;
      running++;
      // No healthcheck counts as ready; "starting" or "unhealthy" does not.
      const health = state.Health?.Status;
      if (health === undefined || health === 'healthy') ready++;
      const t = Date.parse(state.StartedAt ?? '');
      if (Number.isFinite(t)) startedAt = startedAt === null ? t : Math.min(startedAt, t);
    }
    if (missing) return { state: 'missing', startedAt: null };
    if (running === 0) return { state: 'stopped', startedAt: null };
    return { state: ready === containers.length ? 'running' : 'starting', startedAt };
  }

  /** Idempotent: already running containers answer 304, which is fine. */
  async start(id: EnvironmentId): Promise<EnvironmentStatus> {
    for (const name of ENVIRONMENTS[id].containers) {
      const res = await this.docker.call('POST', `/containers/${name}/start`);
      if (res.status === 404) throw new EnvironmentMissing(id);
      this.expect(res.status, [204, 304], 'start');
    }
    this.logger.info({ environment: id }, 'environment started');
    return this.status(id);
  }

  /** Reverse order (the dashboard before what it reads from); stopped or absent is fine. */
  async stop(id: EnvironmentId): Promise<void> {
    for (const name of [...ENVIRONMENTS[id].containers].reverse()) {
      // t=10: Docker waits 10 s for a clean shutdown, under the socket client's timeout.
      const res = await this.docker.call('POST', `/containers/${name}/stop?t=10`);
      this.expect(res.status, [204, 304, 404], 'stop');
    }
    this.logger.info({ environment: id }, 'environment stopped');
  }

  /** Stops environments running for longer than their catalog limit. Returns how many. */
  async reap(): Promise<number> {
    let stopped = 0;
    for (const id of Object.keys(ENVIRONMENTS) as EnvironmentId[]) {
      try {
        const { state, startedAt } = await this.status(id);
        if (state === 'missing' || state === 'stopped' || startedAt === null) continue;
        if (this.now() - startedAt < ENVIRONMENTS[id].maxRunSeconds * 1000) continue;
        await this.stop(id);
        stopped++;
      } catch (err) {
        this.logger.warn({ err, environment: id }, 'environment reap failed');
      }
    }
    return stopped;
  }

  private expect(status: number, ok: number[], step: string): void {
    if (!ok.includes(status)) throw new Error(`docker environment ${step} failed with HTTP ${String(status)}`);
  }
}
