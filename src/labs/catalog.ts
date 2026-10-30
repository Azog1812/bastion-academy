/**
 * The closed set of labs. Content picks a lab by id; the image, port and limits
 * come from here, never from a request or from content/ (ADR 0009). Adding a lab
 * means a code review, not a JSON edit.
 */
export interface LabLimits {
  memoryMiB: number;
  pids: number;
  cpus: number;
}

/** What a lab gets unless the catalog says otherwise: enough for a small Node app. */
export const DEFAULT_LIMITS: LabLimits = { memoryMiB: 128, pids: 64, cpus: 0.5 };
/** Hard ceiling for any lab, checked by a test: a catalog typo cannot hand a lab the host. */
export const MAX_LIMITS: LabLimits = { memoryMiB: 768, pids: 512, cpus: 1 };

export const LABS = {
  'sqli-login': { image: 'bastion-lab-sqli-login:local', port: 8080 },
  'idor-invoices': { image: 'bastion-lab-idor-invoices:local', port: 8080 },
  'mass-assignment': { image: 'bastion-lab-mass-assignment:local', port: 8080 },
  'ssrf-preview': { image: 'bastion-lab-ssrf-preview:local', port: 8080 },
  'path-traversal': { image: 'bastion-lab-path-traversal:local', port: 8080 },
  /** Ships a shell on purpose: code execution is the lesson (ADR 0009). */
  'command-injection': { image: 'bastion-lab-command-injection:local', port: 8080 },
  'jwt-none': { image: 'bastion-lab-jwt-none:local', port: 8080 },
  /** Ships a headless Chromium as the victim: a browser needs more memory and processes. */
  /** Level 4: three flaws chained (path traversal → leaked JWT secret → forged admin token). */
  'chained-intranet': { image: 'bastion-lab-chained-intranet:local', port: 8080 },
  'xss-stored': { image: 'bastion-lab-xss-stored:local', port: 8080, limits: { memoryMiB: 512, pids: 256, cpus: 1 } },
} as const satisfies Record<string, { image: string; port: number; limits?: LabLimits }>;

export function labLimits(lab: keyof typeof LABS): LabLimits {
  const spec = LABS[lab];
  return 'limits' in spec ? spec.limits : DEFAULT_LIMITS;
}

export type LabId = keyof typeof LABS;
export const LAB_IDS = Object.keys(LABS) as [LabId, ...LabId[]];

/** 128 random bits, hex: an unguessable capability, and a valid DNS label once prefixed. */
export const INSTANCE_ID = /^[0-9a-f]{32}$/;

/** Docker object names and the gateway hostname are all derived from the instance id, nothing else. */
export const containerName = (instanceId: string) => `bastion-lab-${instanceId}`;
export const labHostname = (instanceId: string) => `l${instanceId}.lab.localhost`;
