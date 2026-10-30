import { pino, type Logger } from 'pino';

/**
 * Structured JSON logs (ready for Loki / ELK / a SIEM). Secrets are redacted
 * at the logger level, so a careless `log.info(req.body)` cannot leak them.
 */
export function createLogger(level: string, service = 'bastion'): Logger {
  return pino({
    level,
    base: { service },
    timestamp: pino.stdTimeFunctions.isoTime,
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        'res.headers["set-cookie"]',
        '*.password',
        '*.currentPassword',
        '*.newPassword',
        '*.refreshToken',
        '*.accessToken',
        '*.token',
        '*.flag',
      ],
      censor: '[REDACTED]',
    },
  });
}
