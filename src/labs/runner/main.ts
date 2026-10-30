import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { base64Key, resolveFileSecrets } from '../../config.js';
import { createLogger } from '../../logger.js';
import { createRunnerApp } from './app.js';
import { dockerSocket } from './docker.js';
import { LabRunner } from './runner.js';

/**
 * Lab runner entry point. This process holds the Docker socket, which is
 * root-equivalent on the host: it must stay small, reachable only from the
 * platform, and never exposed (ADR 0009).
 */
const schema = z
  .object({
    HOST: z.string().default('0.0.0.0'),
    PORT: z.coerce.number().int().min(1).max(65535).default(4000),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
    LAB_RUNNER_TOKEN: base64Key(32),
    DOCKER_SOCKET: z.string().default('/var/run/docker.sock'),
    /** Container name of the lab gateway, attached to each instance network. */
    LAB_GATEWAY_CONTAINER: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$/).default('bastion-lab-gateway'),
    /** Optional OCI runtime for labs, e.g. "runsc" (gVisor) where installed. */
    LAB_RUNTIME: z.string().regex(/^[a-z0-9_-]{1,32}$/).optional(),
  })
  .strict();

const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => k in schema.shape));
// eslint-disable-next-line security/detect-non-literal-fs-filename -- path comes from operator config
const parsed = schema.safeParse(resolveFileSecrets(env, (p) => readFileSync(p, 'utf8'), ['LAB_RUNNER_TOKEN']));
if (!parsed.success) {
  // Which variables are wrong, never their values.
  console.error(`Invalid configuration, refusing to start:\n${parsed.error.issues.map((i) => `  - ${i.path.join('.')}: ${i.message}`).join('\n')}`);
  process.exit(1);
}
const config = parsed.data;
const logger = createLogger(config.LOG_LEVEL, 'lab-runner');
const runner = new LabRunner(dockerSocket(config.DOCKER_SOCKET), config.LAB_GATEWAY_CONTAINER, logger, config.LAB_RUNTIME);
const server = createRunnerApp(runner, config.LAB_RUNNER_TOKEN, logger).listen(config.PORT, config.HOST, () => {
  logger.info({ port: config.PORT, runtime: config.LAB_RUNTIME ?? 'default' }, 'lab runner listening');
});
server.headersTimeout = 15_000;
server.requestTimeout = 60_000;

const reap = () => {
  runner.reap().then(
    (n) => {
      if (n > 0) logger.info({ reaped: n }, 'expired labs removed');
    },
    (err: unknown) => {
      logger.warn({ err }, 'reaper failed');
    },
  );
};
// At start-up too: clean what expired while the stack was down, re-attach the gateway to the rest.
reap();
const reaper = setInterval(reap, 60_000);

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.on(signal, () => {
    clearInterval(reaper);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5_000).unref();
  });
}
