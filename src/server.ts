import { createServer } from 'node:http';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { connectDatabase } from './db.js';
import { RedisClient } from './redis.js';
import { loadCurriculum } from './curriculum/catalog.js';
import { createLogger } from './logger.js';
import { metricsListener } from './http/metrics.js';
import { kmsFromConfig } from './crypto/kms-config.js';

const config = loadConfig();
const logger = createLogger(config.LOG_LEVEL);
// Fail closed: an unreachable database or a wrong password stops the boot (the orchestrator restarts us).
const db = await connectDatabase(config, {
  as: 'app',
  onIdleError: (err) => {
    logger.warn({ reason: err.message }, 'idle database connection lost');
  },
}).catch((err: unknown) => {
  logger.fatal({ reason: err instanceof Error ? err.message : 'unknown' }, 'database unavailable, refusing to start');
  process.exit(1);
});
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
// Shared rate limits (ADR 0023). Checked at boot like the database: a wrong password or an
// unreachable server is a misconfiguration, not something to discover on the first login.
let redis: RedisClient | undefined;
if (config.REDIS_URL !== undefined) {
  redis = new RedisClient(config.REDIS_URL);
  try {
    await redis.command(['PING']);
  } catch (err) {
    logger.fatal({ reason: err instanceof Error ? err.message : 'unknown' }, 'rate-limit store unavailable, refusing to start');
    process.exit(1);
  }
} else if (config.DATABASE_URL !== undefined) {
  logger.warn('PostgreSQL without REDIS_URL: rate limits are counted per replica (N replicas allow N times the limit)');
}
const { app, services, metrics, siem } = createApp({ config, db, logger, curriculum, kms, ...(redis ? { redis: { client: redis } } : {}) });

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
    { port: config.PORT, database: db.dialect, rateLimits: redis ? 'redis' : 'memory', kms: config.KMS_PROVIDER, keyId: config.ACTIVE_KEY_ID, lessons: curriculum.lessons.size, labs: config.LAB_RUNNER_URL ? 'on' : 'off' },
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
    redis?.close();
    void db.close().finally(() => {
      logger.info('bye');
      process.exit(0);
    });
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
