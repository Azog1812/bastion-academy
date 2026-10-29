import { Router, type Request } from 'express';
import { rateLimit } from 'express-rate-limit';
import type { AuditLog } from '../audit.js';
import type { TokenSigner } from '../crypto/tokens.js';
import type { AuthService, RequestContext } from '../services/auth-service.js';
import type { NoteService } from '../services/note-service.js';
import { unauthorized } from '../errors.js';
import { authenticate, handler, parse, requireRole } from './middleware.js';
import {
  auditQuerySchema,
  changePasswordSchema,
  createNoteSchema,
  credentialsSchema,
  noteIdSchema,
  paginationSchema,
  refreshSchema,
  updateNoteSchema,
} from './schemas.js';

export interface RouteDeps {
  auth: AuthService;
  notes: NoteService;
  audit: AuditLog;
  signer: TokenSigner;
  rateLimits: { auth: number; refresh: number };
}

const ctx = (req: Request): RequestContext => ({ ip: req.ip ?? null });

/** The authenticated user id. Throws (fails closed) if a route was wired without `requireAuth`. */
const uid = (req: Request): string => {
  if (!req.principal) throw unauthorized();
  return req.principal.id;
};

const limiter = (limit: number, name: string) =>
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    identifier: name,
    message: { error: 'rate_limited', message: 'Too many requests, slow down' },
  });

export function buildRouter(d: RouteDeps): Router {
  const r = Router();
  const authLimiter = limiter(d.rateLimits.auth, 'auth');
  const refreshLimiter = limiter(d.rateLimits.refresh, 'refresh');
  const requireAuth = authenticate(d.signer, d.auth);

  /* ---------- authentication ---------- */

  r.post(
    '/auth/register',
    authLimiter,
    handler(async (req, res) => {
      const { email, password } = parse(credentialsSchema, req.body);
      const user = await d.auth.register(email, password, ctx(req));
      res.status(201).json(user);
    }),
  );

  r.post(
    '/auth/login',
    authLimiter,
    handler(async (req, res) => {
      const { email, password } = parse(credentialsSchema, req.body);
      res.json(await d.auth.login(email, password, ctx(req)));
    }),
  );

  r.post(
    '/auth/refresh',
    refreshLimiter,
    handler(async (req, res) => {
      const { refreshToken } = parse(refreshSchema, req.body);
      res.json(await d.auth.refresh(refreshToken, ctx(req)));
    }),
  );

  r.post(
    '/auth/logout',
    refreshLimiter,
    handler((req, res) => {
      const { refreshToken } = parse(refreshSchema, req.body);
      d.auth.logout(refreshToken, ctx(req));
      res.status(204).end();
    }),
  );

  /* ---------- current user ---------- */

  r.get(
    '/me',
    requireAuth,
    handler((req, res) => {
      res.json({ id: req.principal?.id, role: req.principal?.role });
    }),
  );

  r.post(
    '/me/password',
    requireAuth,
    authLimiter,
    handler(async (req, res) => {
      const { currentPassword, newPassword } = parse(changePasswordSchema, req.body);
      await d.auth.changePassword(uid(req), currentPassword, newPassword, ctx(req));
      res.status(204).end();
    }),
  );

  r.post(
    '/me/logout-all',
    requireAuth,
    handler((req, res) => {
      d.auth.logoutEverywhere(uid(req), ctx(req));
      res.status(204).end();
    }),
  );

  /* ---------- notes (owner-scoped) ---------- */

  r.get(
    '/notes',
    requireAuth,
    handler((req, res) => {
      const { limit, offset } = parse(paginationSchema, req.query);
      res.json({ ...d.notes.list(uid(req), limit, offset), limit, offset });
    }),
  );

  r.post(
    '/notes',
    requireAuth,
    handler((req, res) => {
      const note = d.notes.create(uid(req), parse(createNoteSchema, req.body), ctx(req).ip);
      res.status(201).location(`/v1/notes/${note.id}`).json(note);
    }),
  );

  r.get(
    '/notes/:id',
    requireAuth,
    handler((req, res) => {
      const { id } = parse(noteIdSchema, req.params);
      res.json(d.notes.get(uid(req), id, ctx(req).ip));
    }),
  );

  r.put(
    '/notes/:id',
    requireAuth,
    handler((req, res) => {
      const { id } = parse(noteIdSchema, req.params);
      const { version, ...content } = parse(updateNoteSchema, req.body);
      res.json(d.notes.update(uid(req), id, version, content, ctx(req).ip));
    }),
  );

  r.delete(
    '/notes/:id',
    requireAuth,
    handler((req, res) => {
      const { id } = parse(noteIdSchema, req.params);
      d.notes.delete(uid(req), id, ctx(req).ip);
      res.status(204).end();
    }),
  );

  /* ---------- administration ---------- */

  const adminOnly = [requireAuth, requireRole('admin', d.audit)];

  r.get(
    '/admin/audit',
    ...adminOnly,
    handler((req, res) => {
      const { limit, before } = parse(auditQuerySchema, req.query);
      d.audit.record({ action: 'admin.audit_read', outcome: 'success', actorId: uid(req), ip: ctx(req).ip });
      const items = d.audit.list(limit, before).map((row) => ({ ...row, details: JSON.parse(row.details) as unknown }));
      res.json({ items });
    }),
  );

  r.get(
    '/admin/audit/verify',
    ...adminOnly,
    handler((req, res) => {
      const result = d.audit.verify();
      d.audit.record({
        action: 'admin.audit_verify',
        outcome: result.valid ? 'success' : 'failure',
        actorId: uid(req),
        ip: ctx(req).ip,
        details: { checked: result.checked },
      });
      res.json(result);
    }),
  );

  return r;
}
