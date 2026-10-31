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
  const raw = JSON.parse(readFileSync(join(work, suite, 'expected.json'), 'utf8')) as Record<string, unknown>;
  const results = readFileSync(join(work, suite, 'result.txt'), 'utf8').trim().split('\n');

  // Production rules: the exact rule each line must end on.
  if (Array.isArray(raw.ids)) {
    const ids = raw.ids as string[];
    const got = results.map((l) => l.split(' ')[0] ?? '');
    const wrong = ids.flatMap((id, i) => (got[i] === id ? [] : [`line ${String(i + 1)}: expected ${id}, Wazuh says ${got[i] ?? 'nothing'}`]));
    if (got.length !== ids.length || wrong.length) {
      console.error(`${suite}: ${String(wrong.length)} lines differ (${String(got.length)} results for ${String(ids.length)} lines)`);
      for (const w of wrong.slice(0, 10)) console.error(`  ${w}`);
      failed = true;
    } else process.stdout.write(`${suite}: all ${String(ids.length)} lines reach the expected rule in wazuh-logtest\n`);
    continue;
  }

  const expected = raw as { units: string[]; alerted: string[]; learnerIds: string[]; minLevel: number };
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
