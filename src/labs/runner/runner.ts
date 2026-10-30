import type { Logger } from 'pino';
import { containerName, type LabId } from '../catalog.js';
import type { DockerApi } from './docker.js';
import { containerSpec, LABEL, LABEL_EXPIRES, LABEL_INSTANCE, networkSpec } from './spec.js';

export class LabImageMissing extends Error {}
export class LabAlreadyRunning extends Error {}

export interface StartRequest {
  instanceId: string;
  lab: LabId;
  flag: string;
  ttlSeconds: number;
}

/**
 * Creates and destroys lab instances. Inputs are already validated (closed lab
 * id, hex instance id, flag format); every Docker object name derives from the
 * instance id, so no request can name an image, a volume or a host path.
 */
export class LabRunner {
  constructor(
    private readonly docker: DockerApi,
    private readonly gateway: string,
    private readonly logger: Logger,
    private readonly runtime?: string,
    private readonly now: () => number = Date.now,
  ) {}

  async start({ instanceId, lab, flag, ttlSeconds }: StartRequest): Promise<{ expiresAt: number }> {
    const name = containerName(instanceId);
    const expiresAt = this.now() + ttlSeconds * 1000;
    const net = await this.docker.call('POST', '/networks/create', networkSpec(instanceId, expiresAt));
    if (net.status === 409) throw new LabAlreadyRunning();
    this.expect(net.status, [201], 'network create');
    try {
      const created = await this.docker.call('POST', `/containers/create?name=${name}`, containerSpec(lab, instanceId, flag, expiresAt, this.runtime));
      if (created.status === 404) throw new LabImageMissing(lab);
      if (created.status === 409) throw new LabAlreadyRunning();
      this.expect(created.status, [201], 'container create');
      this.expect((await this.docker.call('POST', `/networks/${name}/connect`, { Container: this.gateway })).status, [200], 'gateway connect');
      this.expect((await this.docker.call('POST', `/containers/${name}/start`)).status, [204, 304], 'container start');
    } catch (err) {
      // Never leave half an instance behind.
      await this.stop(instanceId).catch(() => undefined);
      throw err;
    }
    this.logger.info({ instanceId, lab, expiresAt }, 'lab started');
    return { expiresAt };
  }

  /** Idempotent: missing objects are fine, the goal is that nothing is left. */
  async stop(instanceId: string): Promise<void> {
    const name = containerName(instanceId);
    await this.docker.call('POST', `/networks/${name}/disconnect`, { Container: this.gateway, Force: true });
    this.expect((await this.docker.call('DELETE', `/containers/${name}?force=true&v=true`)).status, [204, 404], 'container remove');
    this.expect((await this.docker.call('DELETE', `/networks/${name}`)).status, [204, 404], 'network remove');
    this.logger.info({ instanceId }, 'lab stopped');
  }

  /**
   * TTL enforcement on the runner's side, independent of the platform: even if
   * the platform is down or its database is lost, expired labs disappear.
   *
   * Also re-attaches the gateway to every live lab network: after a restart of
   * the stack the gateway container is new and would otherwise reach no lab.
   */
  async reap(): Promise<number> {
    const filters = encodeURIComponent(JSON.stringify({ label: [`${LABEL}=1`] }));
    const expired = new Set<string>();
    const live = new Set<string>();
    const now = this.now();
    for (const path of [`/containers/json?all=true&filters=${filters}`, `/networks?filters=${filters}`]) {
      const res = await this.docker.call('GET', path);
      if (res.status !== 200 || !Array.isArray(res.body)) continue;
      const isNetwork = path.startsWith('/networks');
      for (const item of res.body as { Labels?: Record<string, string> }[]) {
        const id = item.Labels?.[LABEL_INSTANCE];
        if (!id || !/^[0-9a-f]{32}$/.test(id)) continue;
        if (Number(item.Labels?.[LABEL_EXPIRES]) > now) {
          if (isNetwork) live.add(id);
        } else expired.add(id);
      }
    }
    for (const id of expired) {
      live.delete(id);
      await this.stop(id).catch((err: unknown) => {
        this.logger.warn({ err, instanceId: id }, 'reap failed');
      });
    }
    // Already attached answers an error: harmless, that is the steady state.
    for (const id of live) await this.docker.call('POST', `/networks/${containerName(id)}/connect`, { Container: this.gateway }).catch(() => undefined);
    return expired.size;
  }

  private expect(status: number, ok: number[], step: string): void {
    if (!ok.includes(status)) throw new Error(`docker ${step} failed with HTTP ${String(status)}`);
  }
}
