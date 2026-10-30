/**
 * The closed set of labs. Content picks a lab by id; the image, port and limits
 * come from here, never from a request or from content/ (ADR 0009). Adding a lab
 * means a code review, not a JSON edit.
 */
export const LABS = {
  'sqli-login': { image: 'bastion-lab-sqli-login:local', port: 8080 },
  'idor-invoices': { image: 'bastion-lab-idor-invoices:local', port: 8080 },
  'mass-assignment': { image: 'bastion-lab-mass-assignment:local', port: 8080 },
  'ssrf-preview': { image: 'bastion-lab-ssrf-preview:local', port: 8080 },
  'path-traversal': { image: 'bastion-lab-path-traversal:local', port: 8080 },
  /** The only lab image with a shell, on purpose: code execution is the lesson (ADR 0009). */
  'command-injection': { image: 'bastion-lab-command-injection:local', port: 8080 },
  'jwt-none': { image: 'bastion-lab-jwt-none:local', port: 8080 },
} as const satisfies Record<string, { image: string; port: number }>;

export type LabId = keyof typeof LABS;
export const LAB_IDS = Object.keys(LABS) as [LabId, ...LabId[]];

/** 128 random bits, hex: an unguessable capability, and a valid DNS label once prefixed. */
export const INSTANCE_ID = /^[0-9a-f]{32}$/;

/** Docker object names and the gateway hostname are all derived from the instance id, nothing else. */
export const containerName = (instanceId: string) => `bastion-lab-${instanceId}`;
export const labHostname = (instanceId: string) => `l${instanceId}.lab.localhost`;
