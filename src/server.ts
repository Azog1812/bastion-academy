import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { openDatabase } from './db.js';
import { loadCurriculum } from './curriculum/catalog.js';
import { createLogger } from './logger.js';

const config = loadConfig();
const logger = createLogger(config.LOG_LEVEL);
const db = openDatabase(config.DATABASE_PATH);
// Invalid content stops the boot, like invalid config: fail closed.
const curriculum = loadCurriculum();
const { app, services } = createApp({ config, db, logger, curriculum });

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
    { port: config.PORT, keyId: config.ACTIVE_KEY_ID, lessons: curriculum.lessons.size, labs: config.LAB_RUNNER_URL ? 'on' : 'off' },
    'bastion listening',
  );
});

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
  server.close(() => {
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
