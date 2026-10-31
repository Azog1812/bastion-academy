/**
 * Differential check against the real Wazuh, step 1 (run.sh calls it): writes one
 * suite per Wazuh challenge (log lines, the reference rules, and what Bastion's own
 * evaluator says they alert on), for replay.sh to push through wazuh-logtest.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { compileRules, evaluate } from '../../src/detection/wazuh.js';
import { BASTION_BASE_RULE, buildWazuhDataset, WAZUH_DATASET_KINDS } from '../../src/detection/wazuh-datasets.js';
import { REFERENCE } from '../fixtures/wazuh-reference.js';
import { bastionAuditSuite } from './bastion-audit.js';

const out = process.argv[2];
if (!out) throw new Error('usage: prepare.ts <work directory>');
// The stock correlation rules (5712, 5720, 5763, 40111) are absent from the challenge's model.
const overrides = readFileSync(join(import.meta.dirname, 'disable-stock-correlation.xml'), 'utf8');

for (const kind of WAZUH_DATASET_KINDS) {
  const d = buildWazuhDataset(kind, createHash('sha256').update(`wazuh-real:${kind}`).digest());
  const rules = compileRules(REFERENCE[kind], d);
  const unitOf = (e: (typeof d.events)[number]) => (d.unit === 'entity' ? (d.entityField === 'user' ? e.user : e.srcip) : e.id);
  const dir = join(out, kind);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'lines.log'), `${d.events.map((e) => e.full_log).join('\n')}\n`);
  writeFileSync(join(dir, 'rules.xml'), `${d.decoder === 'json' ? BASTION_BASE_RULE : overrides}\n${REFERENCE[kind]}\n`);
  writeFileSync(
    join(dir, 'expected.json'),
    JSON.stringify({
      units: d.events.map(unitOf),
      alerted: [...new Set(evaluate(rules, d).map(({ event }) => unitOf(event)))].sort(),
      learnerIds: rules.map((r) => String(r.id)),
      minLevel: d.minLevel,
    }),
  );
  process.stdout.write(`${kind}: ${String(d.events.length)} lines\n`);
}

// The production rules for Bastion's own audit log (ADR 0015): an expected rule per line.
{
  const { lines, ids } = bastionAuditSuite();
  const dir = join(out, 'bastion-audit');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'lines.log'), `${lines.join('\n')}\n`);
  writeFileSync(join(dir, 'rules.xml'), readFileSync(join(import.meta.dirname, '../../deploy/wazuh/bastion_rules.xml'), 'utf8'));
  writeFileSync(join(dir, 'expected.json'), JSON.stringify({ ids }));
  process.stdout.write(`bastion-audit: ${String(lines.length)} lines\n`);
}
