import type { Config } from '../config.js';
import { CompositeKms, LocalKms, VaultTransitKms, type Kms, type VaultAuth } from './kms.js';

export interface ConfiguredKms {
  kms: Kms;
  /** Set when the KEKs live in Vault: checked at boot. */
  vault?: VaultTransitKms;
}

/**
 * The KMS the configuration asks for (ADR 0019). With Vault, a configured local ring stays
 * readable (rows not yet re-wrapped) but is never used to wrap anything new.
 */
export function kmsFromConfig(config: Config, fetchImpl?: typeof fetch): ConfiguredKms {
  const local =
    config.ENCRYPTION_KEYS && config.ACTIVE_KEY_ID ? new LocalKms({ keys: config.ENCRYPTION_KEYS, activeKeyId: config.ACTIVE_KEY_ID }) : undefined;
  if (config.KMS_PROVIDER === 'local') {
    // The schema refuses KMS_PROVIDER=local without a ring: this is a type guard, not a branch.
    if (!local) throw new Error('KMS_PROVIDER=local needs ENCRYPTION_KEYS');
    return { kms: local };
  }
  const auth: VaultAuth | undefined = config.VAULT_TOKEN
    ? { token: config.VAULT_TOKEN }
    : config.VAULT_ROLE_ID && config.VAULT_SECRET_ID
      ? { roleId: config.VAULT_ROLE_ID, secretId: config.VAULT_SECRET_ID }
      : undefined;
  if (!config.VAULT_ADDR || !auth) throw new Error('KMS_PROVIDER=vault needs VAULT_ADDR and credentials');
  const vault = new VaultTransitKms({
    addr: config.VAULT_ADDR,
    auth,
    mount: config.VAULT_TRANSIT_MOUNT,
    key: config.VAULT_TRANSIT_KEY,
    ...(fetchImpl ? { fetch: fetchImpl } : {}),
  });
  return { kms: new CompositeKms(vault, local ? [local] : []), vault };
}
