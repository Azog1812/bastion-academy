/**
 * API client. The access token lives in this module's memory only: never in
 * localStorage, sessionStorage or a readable cookie, where an XSS could take
 * it. On reload it is re-obtained from the HttpOnly refresh cookie, which
 * this code cannot read either (ADR 0007).
 */

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    /** Field-level reasons of a 400 validation error, when the server gives them. */
    readonly issues: { path: string; message: string }[] = [],
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

let accessToken: string | null = null;
let refreshing: Promise<boolean> | null = null;

const JSON_HEADERS = { 'content-type': 'application/json' };

async function call<T>(method: string, path: string, body?: unknown, auth = true): Promise<T> {
  const headers: Record<string, string> = body === undefined ? {} : { ...JSON_HEADERS };
  if (auth && accessToken) headers.authorization = `Bearer ${accessToken}`;
  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? null : JSON.stringify(body),
    credentials: 'same-origin',
    cache: 'no-store',
  });
  if (res.status === 204) return undefined as T;
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    const text = (v: unknown, fallback: string) => (typeof v === 'string' ? v : fallback);
    const issues = Array.isArray(data.issues)
      ? (data.issues as unknown[]).flatMap((i) =>
          typeof i === 'object' && i !== null ? [{ path: text((i as Record<string, unknown>).path, ''), message: text((i as Record<string, unknown>).message, '') }] : [],
        )
      : [];
    throw new ApiError(res.status, text(data.error, 'error'), text(data.message, res.statusText), issues);
  }
  return data as T;
}

/** Trades the HttpOnly refresh cookie for a new access token. Concurrent callers share one attempt (rotation is single-use). */
export function restoreSession(): Promise<boolean> {
  refreshing ??= call<{ accessToken: string }>('POST', '/v1/session/refresh', {}, false)
    .then((r) => {
      accessToken = r.accessToken;
      return true;
    })
    .catch(() => {
      accessToken = null;
      return false;
    })
    .finally(() => {
      refreshing = null;
    });
  return refreshing;
}

/** Authenticated request; on an expired access token, refresh once and retry. */
export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  try {
    return await call<T>(method, path, body);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401 && (await restoreSession())) return call<T>(method, path, body);
    throw err;
  }
}

/** Either logged in, or the password was right and a second factor is needed. */
export type LoginStep = { done: true } | { done: false; mfaToken: string };

export async function login(email: string, password: string): Promise<LoginStep> {
  const r = await call<{ accessToken?: string; mfaRequired?: boolean; mfaToken?: string }>(
    'POST',
    '/v1/session/login',
    { email, password },
    false,
  );
  if (r.mfaRequired && r.mfaToken) return { done: false, mfaToken: r.mfaToken };
  accessToken = r.accessToken ?? null;
  return { done: true };
}

export async function completeMfa(mfaToken: string, proof: { code: string } | { passkey: unknown }): Promise<void> {
  const r = await call<{ accessToken: string }>('POST', '/v1/session/mfa', { mfaToken, ...proof }, false);
  accessToken = r.accessToken;
}

/** Passkey challenge for the pending MFA step (ADR 0016). */
export const passkeyLoginOptions = <T>(mfaToken: string): Promise<T> => call<T>('POST', '/v1/auth/mfa/passkey/options', { mfaToken }, false);

export async function register(email: string, password: string): Promise<LoginStep> {
  await call('POST', '/v1/auth/register', { email, password }, false);
  return login(email, password);
}

export async function logout(): Promise<void> {
  accessToken = null;
  await call('POST', '/v1/session/logout', {}, false).catch(() => undefined);
}

export const isLoggedIn = (): boolean => accessToken !== null;

/* ---------- response shapes (see docs/openapi.yaml) ---------- */

export interface LessonSummary {
  id: string;
  title: string;
  minutes: number;
  hasQuiz: boolean;
  completed: boolean;
}

export interface ModuleView {
  id: string;
  title: string;
  summary: string;
  prerequisites: string[];
  /** Optional modules are off until the learner adds them (what their machine can run). */
  optional: boolean;
  requirements: { docker?: boolean; ramGb?: number };
  added: boolean;
  unlocked: boolean;
  completed: boolean;
  lessons: LessonSummary[];
}

export interface Curriculum {
  levels: { level: number; title: string; goal: string }[];
  paths: { id: string; title: string; summary: string; level: number; modules: ModuleView[] }[];
  progress: { completed: number; total: number };
}

export interface Lesson {
  id: string;
  pathId: string;
  moduleId: string;
  title: string;
  minutes: number;
  body: string;
  references: { label: string; url: string }[];
  quiz: { id: string; prompt: string; choices: string[]; multiple: boolean }[];
  completed: boolean;
  completedAt: string | null;
}

export type Completion = { passed: true; completedAt: string; alreadyCompleted: boolean } | { passed: false; incorrect: string[] };

export interface Me {
  id: string;
  role: 'user' | 'admin';
  displayName: string | null;
  /** Any second factor: TOTP or a passkey. */
  mfaEnabled: boolean;
  totpEnabled: boolean;
  passkeys: number;
}

export interface ChallengeSummary {
  id: string;
  title: string;
  moduleId: string;
  points: number;
  unlocked: boolean;
  solved: boolean;
  solvedAt: string | null;
}

/** A shared real tool (ADR 0013), started and stopped from its module. */
export interface EnvironmentView {
  id: string;
  title: string;
  moduleId: string;
  available: boolean;
  state: 'unavailable' | 'missing' | 'stopped' | 'starting' | 'running';
  url: string | null;
  login: string | null;
  stopsAt: string | null;
}

export interface LabInstance {
  url: string;
  expiresAt: string;
}

export interface LabState {
  id: string;
  enabled: boolean;
  ttlSeconds: number;
  instance: LabInstance | null;
}

export interface DetectionInfo {
  /** JSON rules (ADR 0010) or Wazuh XML rules (ADR 0014). */
  format: 'json' | 'wazuh';
  fields: string[];
  /** Wazuh challenges: an alert counts from this level. */
  minLevel: number | null;
  unit: 'event' | 'entity';
  entityField: string | null;
  events: number;
}

export interface DetectionResult {
  alerts: number;
  detected: number;
  missed: number;
  falsePositives: number;
  total: number;
  examples: { missed: string[]; falsePositives: string[] };
  solved: boolean;
  points: number;
  alreadySolved: boolean;
}

export interface Challenge extends ChallengeSummary {
  brief: string;
  artifact: Record<string, string>;
  lab: LabState | null;
  detection: DetectionInfo | null;
}

export type Submission = { correct: true; points: number; alreadySolved: boolean } | { correct: false };

export interface Scoreboard {
  entries: { rank: number; displayName: string; score: number }[];
  me: { score: number; rank: number | null; displayName: string | null };
}
