import type { WazuhDatasetKind } from '../../src/detection/wazuh-datasets.js';

/** What a careful analyst would write: each dataset must admit one, on every seed. */
export const REFERENCE: Record<WazuhDatasetKind, string> = {
  'wazuh-ssh': `
<group name="local,sshd,">
  <rule id="100100" level="10" frequency="8" timeframe="3600">
    <if_matched_sid>5760</if_matched_sid>
    <same_srcip />
    <srcip negate="yes">10.0.5.20</srcip>
    <description>sshd : force brute sur les mots de passe depuis $(srcip)</description>
    <mitre><id>T1110</id></mitre>
  </rule>
  <rule id="100101" level="10" frequency="8" timeframe="3600">
    <if_matched_sid>5710</if_matched_sid>
    <same_srcip />
    <description>sshd : force brute sur des comptes inexistants depuis $(srcip)</description>
    <mitre><id>T1110</id></mitre>
  </rule>
</group>`,
  'wazuh-bastion': `
<group name="local,bastion,">
  <rule id="100010" level="12">
    <if_sid>100000</if_sid>
    <action type="osmatch">^auth.refresh_reuse_detected$|^challenge.flag_shared$</action>
    <description>Bastion : session volée ou drapeau partagé</description>
  </rule>
  <rule id="100011" level="10">
    <if_sid>100000</if_sid>
    <action type="osmatch">^authz.denied$</action>
    <description>Bastion : accès refusé à une ressource d'un autre</description>
  </rule>
  <rule id="100012" level="0">
    <if_sid>100011</if_sid>
    <srcip>10.0.9.50</srcip>
    <description>Scan DAST nocturne de la CI</description>
  </rule>
</group>`,
};
