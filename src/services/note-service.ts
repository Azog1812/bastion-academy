import { randomUUID } from 'node:crypto';
import type { AuditLog } from '../audit.js';
import { open, rewrap, seal, type KeyRing } from '../crypto/envelope.js';
import type { Database } from '../db.js';
import { conflict, notFound } from '../errors.js';

interface NoteRow {
  id: string;
  owner_id: string;
  key_id: string;
  wrapped_dek: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
  ciphertext: Uint8Array;
  version: number;
  created_at: number;
  updated_at: number;
}

export interface NoteContent {
  title: string;
  body: string;
}

export interface Note extends NoteContent {
  id: string;
  version: number;
  createdAt: string;
  updatedAt: string;
}

/**
 * Authorization model: every query is scoped by `owner_id` inside the SQL
 * itself. There is no code path that loads a note by id alone and checks
 * ownership afterwards — that "fetch then check" pattern is where IDOR bugs
 * (OWASP API1:2023, Broken Object Level Authorization) usually come from.
 */
export class NoteService {
  constructor(
    private readonly db: Database,
    private readonly ring: KeyRing,
    private readonly audit: AuditLog,
  ) {}

  private decrypt(row: NoteRow): Note {
    const plaintext = open(
      this.ring,
      {
        keyId: row.key_id,
        wrappedDek: Buffer.from(row.wrapped_dek),
        iv: Buffer.from(row.iv),
        tag: Buffer.from(row.tag),
        ciphertext: Buffer.from(row.ciphertext),
      },
      row.id,
      row.owner_id,
    );
    const content = JSON.parse(plaintext) as NoteContent;
    return {
      id: row.id,
      title: content.title,
      body: content.body,
      version: row.version,
      createdAt: new Date(row.created_at).toISOString(),
      updatedAt: new Date(row.updated_at).toISOString(),
    };
  }

  private load(ownerId: string, noteId: string, ip: string | null): NoteRow {
    const row = this.db.prepare('SELECT * FROM notes WHERE id = ? AND owner_id = ?').get(noteId, ownerId) as NoteRow | undefined;
    if (!row) {
      // Record cross-tenant probing: someone asked for a note that exists but is not theirs.
      const exists = this.db.prepare('SELECT 1 AS x FROM notes WHERE id = ?').get(noteId);
      if (exists) {
        this.audit.record({ action: 'authz.denied', outcome: 'denied', actorId: ownerId, target: noteId, ip, details: { resource: 'note' } });
      }
      throw notFound('Note not found'); // identical response either way
    }
    return row;
  }

  create(ownerId: string, content: NoteContent, ip: string | null): Note {
    const id = randomUUID();
    const now = Date.now();
    const s = seal(this.ring, JSON.stringify(content), id, ownerId);
    this.db
      .prepare(
        `INSERT INTO notes (id, owner_id, key_id, wrapped_dek, iv, tag, ciphertext, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(id, ownerId, s.keyId, s.wrappedDek, s.iv, s.tag, s.ciphertext, now, now);
    this.audit.record({ action: 'note.create', outcome: 'success', actorId: ownerId, target: id, ip });
    return { id, ...content, version: 1, createdAt: new Date(now).toISOString(), updatedAt: new Date(now).toISOString() };
  }

  list(ownerId: string, limit: number, offset: number): { items: Omit<Note, 'body'>[]; total: number } {
    const rows = this.db
      .prepare('SELECT * FROM notes WHERE owner_id = ? ORDER BY updated_at DESC, id LIMIT ? OFFSET ?')
      .all(ownerId, limit, offset) as unknown as NoteRow[];
    const { n } = this.db.prepare('SELECT COUNT(*) AS n FROM notes WHERE owner_id = ?').get(ownerId) as { n: number };
    return {
      items: rows.map((r) => {
        const { body: _body, ...summary } = this.decrypt(r);
        return summary;
      }),
      total: n,
    };
  }

  get(ownerId: string, noteId: string, ip: string | null): Note {
    const note = this.decrypt(this.load(ownerId, noteId, ip));
    this.audit.record({ action: 'note.read', outcome: 'success', actorId: ownerId, target: noteId, ip });
    return note;
  }

  /** Optimistic concurrency: the client must send the version it last read (lost-update protection). */
  update(ownerId: string, noteId: string, expectedVersion: number, content: NoteContent, ip: string | null): Note {
    const row = this.load(ownerId, noteId, ip);
    if (row.version !== expectedVersion) throw conflict(`Version mismatch: current version is ${row.version}`);

    const s = seal(this.ring, JSON.stringify(content), noteId, ownerId);
    const now = Date.now();
    const result = this.db
      .prepare(
        `UPDATE notes SET key_id = ?, wrapped_dek = ?, iv = ?, tag = ?, ciphertext = ?, version = version + 1, updated_at = ?
         WHERE id = ? AND owner_id = ? AND version = ?`,
      )
      .run(s.keyId, s.wrappedDek, s.iv, s.tag, s.ciphertext, now, noteId, ownerId, expectedVersion);
    if (Number(result.changes) !== 1) throw conflict('Note was modified concurrently');

    this.audit.record({ action: 'note.update', outcome: 'success', actorId: ownerId, target: noteId, ip });
    return {
      id: noteId,
      ...content,
      version: expectedVersion + 1,
      createdAt: new Date(row.created_at).toISOString(),
      updatedAt: new Date(now).toISOString(),
    };
  }

  delete(ownerId: string, noteId: string, ip: string | null): void {
    this.load(ownerId, noteId, ip);
    this.db.prepare('DELETE FROM notes WHERE id = ? AND owner_id = ?').run(noteId, ownerId);
    this.audit.record({ action: 'note.delete', outcome: 'success', actorId: ownerId, target: noteId, ip });
  }

  /** KEK rotation: re-wrap every DEK still under an old key. Content is never decrypted. */
  rotateKeys(): { rewrapped: number } {
    const rows = this.db
      .prepare('SELECT id, key_id, wrapped_dek FROM notes WHERE key_id != ?')
      .all(this.ring.activeKeyId) as unknown as Pick<NoteRow, 'id' | 'key_id' | 'wrapped_dek'>[];
    // Operator-only maintenance task (CLI), intentionally spans all owners.
    // nosemgrep: bastion-note-query-without-owner
    const stmt = this.db.prepare('UPDATE notes SET key_id = ?, wrapped_dek = ? WHERE id = ? AND key_id = ?');
    for (const r of rows) {
      const { keyId, wrappedDek } = rewrap(this.ring, r.key_id, Buffer.from(r.wrapped_dek), r.id);
      stmt.run(keyId, wrappedDek, r.id, r.key_id);
    }
    return { rewrapped: rows.length };
  }
}
