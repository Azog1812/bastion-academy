/**
 * Differential check against the real Wazuh, step 3: what wazuh-logtest decided for
 * each line, against what Bastion's evaluator decided. Any difference fails, so the
 * challenges cannot drift away from Wazuh unnoticed.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const work = process.argv[2];
if (!work) throw new Error('usage: compare.ts <work directory>');

let failed = false;
for (const suite of readdirSync(work)) {
  const expected = JSON.parse(readFileSync(join(work, suite, 'expected.json'), 'utf8')) as { units: string[]; alerted: string[]; learnerIds: string[]; minLevel: number };
  const results = readFileSync(join(work, suite, 'result.txt'), 'utf8').trim().split('\n');
  if (results.length !== expected.units.length) {
    console.error(`${suite}: ${String(results.length)} results for ${String(expected.units.length)} lines`);
    failed = true;
    continue;
  }
  const real = new Set<string>();
  results.forEach((line, i) => {
    const [id = '', level = '0'] = line.split(' ');
    if (expected.learnerIds.includes(id) && Number(level) >= expected.minLevel) real.add(expected.units[i] ?? '');
  });
  const wazuh = [...real].sort();
  const missing = expected.alerted.filter((u) => !real.has(u));
  const extra = wazuh.filter((u) => !expected.alerted.includes(u));
  if (missing.length || extra.length) {
    console.error(`${suite}: Bastion alerts on ${String(expected.alerted.length)}, Wazuh on ${String(wazuh.length)}`);
    if (missing.length) console.error(`  only Bastion: ${missing.slice(0, 10).join(', ')}`);
    if (extra.length) console.error(`  only Wazuh:   ${extra.slice(0, 10).join(', ')}`);
    failed = true;
  } else {
    process.stdout.write(`${suite}: same ${String(wazuh.length)} alerts in Bastion's evaluator and in wazuh-logtest\n`);
  }
}
process.exit(failed ? 1 : 0);
