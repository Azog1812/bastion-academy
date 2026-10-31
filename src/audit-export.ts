import { closeSync, fstatSync, openSync, renameSync, writeSync } from 'node:fs';
import type { Logger } from 'pino';
import type { AuditEvent } from './audit.js';

/**
 * Copy of the audit log for a SIEM (ADR 0015): one JSON object per line, appended to
 * a file that Wazuh's logcollector reads with `log_format json`.
 *
 * - The database stays the record: it is HMAC-chained and append-only; this file is a
 *   convenience copy. `seq` is the database sequence, so a gap shows a lost line.
 * - JSON.stringify escapes control characters: a newline in a URL or an e-mail cannot
 *   start a forged line (log injection, CWE-117).
 * - Written synchronously, like the database insert, so lines keep the chain's order.
 *   A failing write (disk full) is logged and counted, never thrown: losing the SIEM
 *   copy must not take the platform down, and `seq` makes the loss visible.
 * - Mode 0600: the file holds user ids and IP addresses. Only the SIEM's volume mount
 *   ever sees it.
 * - Rotated by size, like logrotate's copy-free rename: Wazuh notices the new file.
 */

export const SERVICE = 'bastion';

/** Keys of the line itself; details never overwrite them. */
const RESERVED = new Set(['ts', 'service', 'seq', 'action', 'outcome', 'actor', 'target', 'srcip']);

export function toSiemLine(event: AuditEvent, written: { seq: number; ts: number }): string {
  const details = Object.fromEntries(Object.entries(event.details ?? {}).filter(([k]) => !RESERVED.has(k)));
  const line = {
    ts: new Date(written.ts).toISOString(),
    service: SERVICE,
    seq: written.seq,
    action: event.action,
    outcome: event.outcome,
    ...(event.actorId ? { actor: event.actorId } : {}),
    ...(event.target ? { target: event.target } : {}),
    // "srcip" is what Wazuh's JSON decoder maps to its static srcip field (<srcip>, same_srcip).
    ...(event.ip ? { srcip: event.ip } : {}),
    ...details,
  };
  return `${JSON.stringify(line)}\n`;
}

export interface AuditExport {
  write(event: AuditEvent, written: { seq: number; ts: number }): void;
  close(): void;
}

/** `onFailure` feeds a metric and its alert (BastionAuditExportFailing): a silent SIEM is an outage. */
export function auditFileExport(path: string, logger: Logger, onFailure: () => void = () => undefined, maxBytes = 50 * 1024 * 1024): AuditExport {
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- operator-controlled config (AUDIT_EXPORT_FILE), not user input
  const open = () => openSync(path, 'a', 0o600);
  let fd = open();
  let size = fstatSync(fd).size;
  let rotateAt = maxBytes;
  const rotate = () => {
    closeSync(fd);
    try {
      // One previous file is kept: Wazuh has read it by then, the database keeps everything.
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- same operator-controlled path
      renameSync(path, `${path}.1`);
      rotateAt = maxBytes;
    } catch (err) {
      // Keep appending rather than drop lines; try again once the file has grown by maxBytes.
      onFailure();
      logger.error({ err }, 'audit export: rotation failed, still appending to the same file');
      rotateAt = size + maxBytes;
    } finally {
      fd = open();
      size = fstatSync(fd).size;
    }
  };
  return {
    write(event, written) {
      const line = Buffer.from(toSiemLine(event, written));
      try {
        if (size > 0 && size + line.length > rotateAt) rotate();
        writeSync(fd, line);
        size += line.length;
      } catch (err) {
        onFailure();
        logger.error({ err, seq: written.seq }, 'audit export: line not written to the SIEM file');
      }
    },
    close() {
      try {
        closeSync(fd);
      } catch {
        // already closed
      }
    },
  };
}
