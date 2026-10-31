/**
 * The closed set of shared environments (ADR 0013): heavy, real tools such as a
 * SIEM, installed once by the operator with `docker compose --profile <id> up -d`,
 * then started and stopped by learners from the web UI.
 *
 * Unlike labs, the runner never *creates* these containers: it may only start and
 * stop the ones named here, which Compose created from reviewed configuration. A
 * request carries an environment id, nothing else; names, order and URL come from
 * this file.
 */
export interface EnvironmentSpec {
  title: string;
  /** The optional module that opens it: a learner must have it added and unlocked. */
  moduleId: string;
  /** Start order; stopped in reverse. Fixed container_name values in docker-compose.yml. */
  containers: readonly string[];
  /** Where the learner opens it (published on 127.0.0.1 only). */
  url: string;
  /** How to log in, without ever sending the secret itself to the browser. */
  login: string;
  /** Stopped by the runner after this, so a forgotten SIEM does not hold 4 GiB forever. */
  maxRunSeconds: number;
}

export const ENVIRONMENTS = {
  wazuh: {
    title: 'Wazuh (SIEM)',
    moduleId: 'wazuh',
    containers: ['bastion-wazuh-indexer', 'bastion-wazuh-manager', 'bastion-wazuh-dashboard'],
    url: 'https://localhost:8443',
    login: 'Utilisateur admin, mot de passe WAZUH_ADMIN_PASSWORD de ton fichier .env',
    maxRunSeconds: 8 * 3600,
  },
} as const satisfies Record<string, EnvironmentSpec>;

export type EnvironmentId = keyof typeof ENVIRONMENTS;
export const ENVIRONMENT_IDS = Object.keys(ENVIRONMENTS) as [EnvironmentId, ...EnvironmentId[]];

/** What the runner reports. "missing": not installed yet (compose profile never run). */
export type EnvironmentState = 'missing' | 'stopped' | 'starting' | 'running';
