import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { compileRules, evaluate, osMatch, parseXml, scoreWazuh, WazuhRuleError } from '../../src/detection/wazuh.js';
import { BASTION_BASE_RULE, buildWazuhDataset, toAlertLines, WAZUH_DATASET_KINDS, type WazuhDatasetKind } from '../../src/detection/wazuh-datasets.js';

const run = (kind: WazuhDatasetKind, xml: string, seed = randomBytes(32)) => scoreWazuh(xml, buildWazuhDataset(kind, seed));

/** What a careful analyst would write: each dataset must admit one, on every seed. */
const REFERENCE: Record<WazuhDatasetKind, string> = {
  'wazuh-ssh': `
<group name="local,sshd,">
  <rule id="100100" level="10" frequency="8" timeframe="3600">
    <if_matched_group>authentication_failed</if_matched_group>
    <same_srcip />
    <srcip>!10.0.5.20</srcip>
    <description>sshd : force brute depuis $(srcip)</description>
    <mitre><id>T1110</id></mitre>
  </rule>
</group>`,
  'wazuh-bastion': `
<group name="local,bastion,">
  <rule id="100010" level="12">
    <if_sid>100000</if_sid>
    <field name="action" type="osmatch">^auth.refresh_reuse_detected$|^challenge.flag_shared$</field>
    <description>Bastion : session volée ou drapeau partagé</description>
  </rule>
  <rule id="100011" level="10">
    <if_sid>100000</if_sid>
    <field name="action" type="osmatch">^authz.denied$</field>
    <description>Bastion : accès refusé à une ressource d'un autre</description>
  </rule>
  <rule id="100012" level="0">
    <if_sid>100011</if_sid>
    <srcip>10.0.9.50</srcip>
    <description>Scan DAST nocturne de la CI</description>
  </rule>
</group>`,
};

describe('Wazuh datasets', () => {
  it.each(WAZUH_DATASET_KINDS)('%s: the reference rules are perfect on any seed', (kind) => {
    for (let n = 0; n < 15; n++) {
      const s = run(kind, REFERENCE[kind]);
      expect(s, kind).toMatchObject({ perfect: true, missed: 0, falsePositives: 0 });
      expect(s.total).toBeGreaterThan(0);
    }
  });

  it('varies per learner, stays bounded, and never shows the labels', () => {
    for (const kind of WAZUH_DATASET_KINDS) {
      const a = toAlertLines(buildWazuhDataset(kind, randomBytes(32)));
      const b = toAlertLines(buildWazuhDataset(kind, randomBytes(32)));
      expect(a).not.toBe(b);
      const lines = a.split('\n');
      expect(lines.length).toBeLessThan(400);
      expect(a).not.toMatch(/malicious|"bad"|label/i);
      // Shaped like Wazuh's alerts.json: the stock rule reached, the decoded data, the raw line.
      expect(JSON.parse(lines[0] ?? '{}')).toMatchObject({ id: 'e001', rule: { id: expect.any(String) as string }, data: { srcip: expect.any(String) as string }, full_log: expect.any(String) as string });
    }
  });

  it('wazuh-ssh: each trap catches the naive rule', () => {
    const rule = (attrs: string, parent: string, extra = '') =>
      `<rule id="100100" level="10" ${attrs}>${parent}<same_srcip />${extra}<description>x</description></rule>`;
    const seed = randomBytes(32);
    const group = '<if_matched_group>authentication_failed</if_matched_group>';
    // Only 5716: the attacker who only tries non-existent users (5710) slips through.
    expect(run('wazuh-ssh', rule('frequency="8" timeframe="3600"', '<if_matched_sid>5716</if_matched_sid>', '<srcip>!10.0.5.20</srcip>'), seed).missed).toBeGreaterThan(0);
    // A short window misses the slow attacker.
    expect(run('wazuh-ssh', rule('frequency="8" timeframe="600"', group, '<srcip>!10.0.5.20</srcip>'), seed).missed).toBe(1);
    // A low threshold flags the user who forgot her password.
    expect(run('wazuh-ssh', rule('frequency="5" timeframe="3600"', group, '<srcip>!10.0.5.20</srcip>'), seed).examples.falsePositives).toContain('10.2.3.41');
    // No exclusion: the backup job's expired password.
    expect(run('wazuh-ssh', rule('frequency="8" timeframe="3600"', group), seed).examples.falsePositives).toContain('10.0.5.20');
    // Excluding the whole subnet hides the compromised neighbour.
    const wide = run('wazuh-ssh', rule('frequency="8" timeframe="3600"', group, '<srcip>!10.0.5.0/24</srcip>'), seed);
    expect(wide).toMatchObject({ missed: 1, falsePositives: 0 });
    expect(wide.examples.missed).toEqual(['10.0.5.77']);
  });

  it('wazuh-bastion: each trap catches the naive rule', () => {
    const one = (cond: string) => `<rule id="100010" level="10"><if_sid>100000</if_sid>${cond}<description>x</description></rule>`;
    const seed = randomBytes(32);
    // "refresh" also matches every normal token refresh.
    expect(run('wazuh-bastion', one('<match>refresh</match>'), seed).falsePositives).toBeGreaterThanOrEqual(40);
    // "denied" also matches learners clicking locked lessons.
    expect(run('wazuh-bastion', one('<field name="outcome" type="osmatch">^denied$</field>'), seed).falsePositives).toBeGreaterThan(10);
    // "admin" also matches the administrator's own work.
    expect(run('wazuh-bastion', one('<match>admin</match>'), seed).falsePositives).toBeGreaterThan(0);
    // Without the level 0 child, the nightly DAST scan pages the SOC.
    const noTuning = REFERENCE['wazuh-bastion'].replace(/<rule id="100012"[\s\S]*?<\/rule>/, '');
    expect(run('wazuh-bastion', noTuning, seed)).toMatchObject({ missed: 0, falsePositives: 9 });
  });

  it('only alerts from a learner rule at or above the paging level', () => {
    const low = REFERENCE['wazuh-ssh'].replace('level="10"', 'level="7"');
    expect(run('wazuh-ssh', low)).toMatchObject({ alerts: 0, missed: 4 });
  });
});

describe('Wazuh rule language: what the evaluator accepts', () => {
  const ssh = buildWazuhDataset('wazuh-ssh', randomBytes(32));
  const bastion = buildWazuhDataset('wazuh-bastion', randomBytes(32));
  const err = (xml: string, d = ssh) => {
    try {
      compileRules(xml, d);
    } catch (e) {
      expect(e).toBeInstanceOf(WazuhRuleError);
      return (e as Error).message;
    }
    throw new Error('expected a WazuhRuleError');
  };
  const rule = (body: string, attrs = 'id="100100" level="10"') => `<rule ${attrs}>${body}<description>x</description></rule>`;

  it('implements OS_Match: substrings, anchors, alternatives, case-insensitive', () => {
    const m = osMatch('^Failed|invalid user|ssh2$', 1);
    expect(m('Failed password for root')).toBe(true);
    expect(m('Jan 12 Invalid User x')).toBe(true);
    expect(m('... port 22 ssh2')).toBe(true);
    expect(m('Accepted publickey')).toBe(false);
    expect(osMatch('^root$', 1)('root')).toBe(true);
    expect(osMatch('^root$', 1)('rooted')).toBe(false);
    expect(() => osMatch('a||b', 3)).toThrow(/ligne 3/);
  });

  it('refuses DTDs, entity declarations, CDATA and processing instructions (XXE, billion laughs)', () => {
    const xxe = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><rule id="100100" level="10">&x;</rule>';
    expect(err(xxe)).toMatch(/DOCTYPE/);
    expect(err('<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><rule>&lol2;</rule>')).toMatch(/DOCTYPE/);
    expect(err(rule('<match><![CDATA[x]]></match>'))).toMatch(/CDATA/);
    expect(err(rule('<match>&#120;</match>'))).toMatch(/entité inconnue/);
    expect(err(rule('<match>&lol;</match>'))).toMatch(/entité inconnue/);
    // The five predefined entities are decoded.
    expect(compileRules(rule('<if_sid>5716</if_sid><match>&lt;&amp;&gt;</match>'), ssh)).toHaveLength(1);
  });

  it('bounds the input: size, depth, number of elements, rules and conditions', () => {
    expect(err(`<!-- ${'x'.repeat(8000)} -->`)).toMatch(/trop longues/);
    expect(err('<group><rule><mitre><id><x/></id></mitre></rule></group>')).toMatch(/profonde/);
    expect(err(`<group name="g">${'<rule/>'.repeat(301)}</group>`)).toMatch(/trop d'éléments/);
    const many = Array.from({ length: 11 }, (_, k) => rule('<if_sid>5716</if_sid>', `id="${String(100_100 + k)}" level="1"`)).join('');
    expect(err(many)).toMatch(/10 règles au plus/);
    const conds = Array.from({ length: 9 }, (_, k) => `<field name="${['action', 'outcome', 'actor', 'target', 'reason', 'required', 'resource', 'service', 'action'][k] ?? ''}" type="osmatch">a</field>`).join('');
    expect(err(rule(`<if_sid>100000</if_sid>${conds}`), bastion)).toMatch(/répété|conditions au plus/);
  });

  it('stays linear on hostile patterns (no regular expression ever runs)', () => {
    const evil = `<group name="g">${rule(`<if_sid>5716</if_sid><match>${'a|'.repeat(1000)}a</match>`)}</group>`;
    const start = performance.now();
    scoreWazuh(evil, ssh);
    expect(performance.now() - start).toBeLessThan(500);
    expect(err(rule('<if_sid>5716</if_sid><regex>^(a+)+$</regex>'))).toMatch(/expressions régulières/);
    expect(err(rule('<if_sid>5716</if_sid><pcre2>x</pcre2>'))).toMatch(/expressions régulières/);
  });

  it('only reads decoded fields of the dataset: no prototype keys', () => {
    for (const name of ['__proto__', 'constructor', 'toString', 'full_log']) {
      expect(err(rule(`<if_sid>100000</if_sid><field name="${name}" type="osmatch">x</field>`), bastion)).toMatch(/champ inconnu/);
    }
    expect(err(rule('<if_sid>100000</if_sid><field name="action">x</field>'), bastion)).toMatch(/type="osmatch"/);
  });

  it('keeps the rule tree acyclic and local: parents defined before, ids in the local range', () => {
    expect(err(rule('<if_sid>100101</if_sid>'))).toMatch(/n'existe pas/);
    expect(err(rule('<if_sid>100100</if_sid>'))).toMatch(/n'existe pas/); // itself
    expect(err(rule('<if_sid>5716</if_sid>', 'id="5717" level="10"'))).toMatch(/règles locales/);
    expect(err(rule('<if_sid>100000</if_sid>', 'id="100000" level="10"'), bastion)).toMatch(/déjà utilisé/);
    expect(err(rule('<if_sid>5716</if_sid>', 'id="100100" level="17"'))).toMatch(/level/);
  });

  it('explains what a Wazuh rule needs', () => {
    expect(err('<rule id="100100" level="10"><if_sid>5716</if_sid></rule>')).toMatch(/description/);
    expect(err(rule('<match>x</match>'))).toMatch(/précise une règle existante/);
    expect(err(rule('<if_sid>5716</if_sid><if_group>sshd</if_group>'))).toMatch(/une seule règle parente/);
    expect(err(rule('<if_matched_sid>5716</if_matched_sid>'))).toMatch(/frequency/);
    expect(err(rule('<if_sid>5716</if_sid>', 'id="100100" level="10" frequency="8" timeframe="60"'))).toMatch(/frequency/);
    expect(err(rule('<if_sid>5716</if_sid><same_srcip />'))).toMatch(/corrélation/);
    expect(err(rule('<if_sid>5716</if_sid>', 'id="100100" level="10" ignore="60"'))).toMatch(/ignore/);
    expect(err(rule('<if_sid>5716</if_sid><srcip>10.0.5.0/33</srcip>'))).toMatch(/CIDR/);
    expect(err(rule('<if_sid>5716</if_sid><decoded_as>json</decoded_as>'))).toMatch(/décodeur/);
    expect(err('<rule id="100100" level="10"><if_sid>5716</if_sid><description>x</description>')).toMatch(/jamais fermé/);
    expect(err('<rule id="100100" level="10"></group>')).toMatch(/ne ferme pas/);
    expect(err('texte <rule/>')).toMatch(/en dehors/);
    expect(err('<rule id=100100 />')).toMatch(/guillemets/);
    expect(err('<decoder name="x"></decoder>')).toMatch(/attendu <group> ou <rule>/);
    expect(err('')).toMatch(/aucune règle/);
  });

  it('walks the tree like Wazuh: a level 0 child silences its parent, negate inverts a test', () => {
    const xml = `${rule('<if_sid>5716</if_sid><user>root</user>', 'id="100100" level="10"')}${rule('<if_sid>100100</if_sid><srcip>192.0.2.0/24</srcip>', 'id="100101" level="0"')}`;
    const alerts = evaluate(compileRules(xml, ssh), ssh);
    expect(alerts.length).toBeGreaterThan(0);
    expect(alerts.every(({ event }) => event.user === 'root' && !event.srcip.startsWith('192.0.2.'))).toBe(true);
    const negated = evaluate(compileRules(rule('<if_sid>5716</if_sid><user negate="yes">root</user>'), ssh), ssh);
    expect(negated.length).toBeGreaterThan(0);
    expect(negated.every(({ event }) => event.user !== 'root')).toBe(true);
  });

  it('accepts the base rule given in the brief as XML, and comments', () => {
    expect(parseXml(BASTION_BASE_RULE)[0]?.children[0]?.attrs.get('id')).toBe('100000');
    expect(compileRules(`<!-- tuning -->${REFERENCE['wazuh-bastion']}`, bastion)).toHaveLength(3);
  });
});
