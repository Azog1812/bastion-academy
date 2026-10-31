import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Database } from './db.js';

/**
 * Tamper-evident audit trail.
 *
 * Each entry stores HMAC(key, prev_hash || entry). Changing, deleting or
 * reordering any past row breaks every hash after it, and `verify()` points
 * to the first broken link. Because it is an HMAC (not a bare hash), an
 * attacker who can write to the database but does not hold AUDIT_HMAC_KEY
 * cannot recompute a valid chain. UPDATE and DELETE are additionally blocked
 * by SQLite triggers.
 */

export const AUDIT_ACTIONS = [
  'auth.register',
  'auth.login',
  'auth.logout',
  'auth.logout_all',
  'auth.refresh',
  'auth.refresh_reuse_detected',
  'auth.lockout',
  'auth.password_change',
  'auth.mfa',
  'auth.reauth',
  'mfa.setup',
  'mfa.enable',
  'mfa.disable',
  'mfa.recovery_code_used',
  'profile.update',
  'challenge.submit',
  'challenge.flag_shared',
  'lab.start',
  'lab.stop',
  'lab.expire',
  'note.create',
  'note.read',
  'note.update',
  'note.delete',
  'lesson.complete',
  'module.select',
  'authz.denied',
  'admin.audit_read',
  'admin.audit_verify',
  'admin.promote',
  'admin.key_rotation',
] as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[number];

export const AUDIT_OUTCOMES = ['success', 'failure', 'denied'] as const;

export interface AuditEvent {
  action: AuditAction;
  outcome: (typeof AUDIT_OUTCOMES)[number];
  actorId?: string | null;
  target?: string | null;
  ip?: string | null;
  details?: Record<string, string | number | boolean>;
}

export interface AuditRow {
  seq: number;
  ts: number;
  actor_id: string | null;
  action: string;
  target: string | null;
  ip: string | null;
  outcome: string;
  details: string;
  prev_hash: string;
  hash: string;
}

const GENESIS = '0'.repeat(64);

export class AuditLog {
  constructor(
    private readonly db: Database,
    private readonly key: Buffer,
    /** Called after each entry is written: metrics count security events from the one place that sees them all. */
    private readonly onRecord?: (event: AuditEvent) => void,
  ) {}

  private digest(prev: string, e: Omit<AuditRow, 'seq' | 'prev_hash' | 'hash'>): string {
    // Fixed field order → canonical serialisation, independent of object key order.
    const canonical = JSON.stringify([e.ts, e.actor_id, e.action, e.target, e.ip, e.outcome, e.details]);
    return createHmac('sha256', this.key).update(prev).update('\n').update(canonical).digest('hex');
  }

  record(event: AuditEvent): void {
    // DatabaseSync is synchronous and Node is single-threaded: there is no
    // await between reading the chain head and inserting, so no interleaving.
    const head = this.db.prepare('SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1').get() as { hash: string } | undefined;
    const prev = head?.hash ?? GENESIS;
    const entry = {
      ts: Date.now(),
      actor_id: event.actorId ?? null,
      action: event.action,
      target: event.target ?? null,
      ip: event.ip ?? null,
      outcome: event.outcome,
      details: JSON.stringify(event.details ?? {}),
    };
    this.db
      .prepare(
        `INSERT INTO audit_log (ts, actor_id, action, target, ip, outcome, details, prev_hash, hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(entry.ts, entry.actor_id, entry.action, entry.target, entry.ip, entry.outcome, entry.details, prev, this.digest(prev, entry));
    this.onRecord?.(event);
  }

  list(limit: number, beforeSeq?: number): AuditRow[] {
    const rows = beforeSeq
      ? this.db.prepare('SELECT * FROM audit_log WHERE seq < ? ORDER BY seq DESC LIMIT ?').all(beforeSeq, limit)
      : this.db.prepare('SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?').all(limit);
    return rows as unknown as AuditRow[];
  }

  verify(): { valid: boolean; checked: number; firstInvalidSeq: number | null } {
    let prev = GENESIS;
    let checked = 0;
    for (const raw of this.db.prepare('SELECT * FROM audit_log ORDER BY seq ASC').iterate()) {
      const row = raw as unknown as AuditRow;
      const expected = Buffer.from(this.digest(prev, row), 'hex');
      const actual = Buffer.from(row.hash, 'hex');
      const linked = row.prev_hash === prev;
      if (!linked || expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
        return { valid: false, checked, firstInvalidSeq: row.seq };
      }
      prev = row.hash;
      checked++;
    }
    return { valid: true, checked, firstInvalidSeq: null };
  }
}
