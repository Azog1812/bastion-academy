import { createLogger } from '../../logger.js';
import { createGateway } from './proxy.js';

const port = Number(process.env.PORT ?? 8088);
const logger = createLogger(process.env.LOG_LEVEL ?? 'info', 'lab-gateway');
const server = createGateway().listen(port, process.env.HOST ?? '0.0.0.0', () => {
  logger.info({ port }, 'lab gateway listening');
});
// Slow-loris protection, as on the platform.
server.headersTimeout = 15_000;
server.requestTimeout = 60_000;
server.keepAliveTimeout = 5_000;

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5_000).unref();
  });
}
