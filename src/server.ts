import { createServer } from 'node:http';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { openDatabase } from './db.js';
import { loadCurriculum } from './curriculum/catalog.js';
import { createLogger } from './logger.js';
import { metricsListener } from './http/metrics.js';
import { kmsFromConfig } from './crypto/kms-config.js';

const config = loadConfig();
const logger = createLogger(config.LOG_LEVEL);
const db = openDatabase(config.DATABASE_PATH);
// Invalid content stops the boot, like invalid config: fail closed.
const curriculum = loadCurriculum();
const { kms, vault } = kmsFromConfig(config);
// Fail closed (ADR 0019): with Vault, refuse to serve until the key exists and is safe
// (derived, not exportable, not deletable) and the token works. The orchestrator restarts us.
if (vault) {
  try {
    const { latestVersion } = await vault.check();
    logger.info({ kms: 'vault', key: config.VAULT_TRANSIT_KEY, version: latestVersion }, 'key service ready');
  } catch (err) {
    logger.fatal({ reason: err instanceof Error ? err.message : 'unknown' }, 'key service check failed, refusing to start');
    process.exit(1);
  }
}
const { app, services, metrics, siem } = createApp({ config, db, logger, curriculum, kms });

// Expired labs are destroyed even if nobody comes back to stop them (the runner reaps on its own too).
const labReaper = setInterval(() => {
  services.labs.reap().then(
    (n) => {
      if (n > 0) logger.info({ expired: n }, 'expired labs destroyed');
    },
    (err: unknown) => {
      logger.warn({ err }, 'lab reaper failed');
    },
  );
}, 60_000);
labReaper.unref();

const server = app.listen(config.PORT, config.HOST, () => {
  logger.info(
    { port: config.PORT, kms: config.KMS_PROVIDER, keyId: config.ACTIVE_KEY_ID, lessons: curriculum.lessons.size, labs: config.LAB_RUNNER_URL ? 'on' : 'off' },
    'bastion listening',
  );
});

// Metrics on their own listener (ADR 0011): the API port never serves them.
const metricsServer =
  config.METRICS_PORT !== undefined && config.METRICS_TOKEN
    ? createServer(metricsListener(metrics.registry, config.METRICS_TOKEN, logger)).listen(config.METRICS_PORT, config.METRICS_HOST, () => {
        logger.info({ port: config.METRICS_PORT, host: config.METRICS_HOST }, 'metrics listening');
      })
    : undefined;
if (metricsServer) {
  metricsServer.headersTimeout = 5_000;
  metricsServer.requestTimeout = 10_000;
}

// Defensive socket timeouts against slow-loris style resource exhaustion.
server.headersTimeout = 15_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 5_000;

/** Graceful shutdown: stop accepting, drain in-flight requests, close the DB cleanly. */
let stopping = false;
function shutdown(signal: string): void {
  if (stopping) return;
  stopping = true;
  logger.info({ signal }, 'shutting down');
  const force = setTimeout(() => process.exit(1), 10_000);
  force.unref();
  metricsServer?.close();
  server.close(() => {
    siem?.close();
    db.close();
    logger.info('bye');
    process.exit(0);
  });
}

process.on('SIGTERM', () => {
  shutdown('SIGTERM');
});
process.on('SIGINT', () => {
  shutdown('SIGINT');
});
process.on('unhandledRejection', (reason) => {
  logger.fatal({ reason }, 'unhandled rejection');
  shutdown('unhandledRejection');
});
