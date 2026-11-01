import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { AUDIT_ACTIONS, AUDIT_OUTCOMES } from '../../src/audit.js';
import { metricsListener } from '../../src/http/metrics.js';
import { createLogger } from '../../src/logger.js';
import { setup } from '../helpers.js';

/**
 * Alerts and dashboards are code (ADR 0011, 0018), so they get the test code gets. A query
 * on a metric that does not exist returns nothing, forever, without an error: an alert
 * that can never fire, a panel that always shows "no data". promtool and amtool check the
 * syntax; this checks that every name they use is one Bastion actually exports.
 */

const read = (path: string) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');
const ALERTS = read('deploy/prometheus/alerts.yml');
const DASHBOARD = JSON.parse(read('deploy/grafana/dashboards/bastion-overview.json')) as {
  uid: string;
  editable: boolean;
  panels: { title: string; type: string; datasource?: { uid: string }; targets?: { expr: string; datasource: { uid: string } }[] }[];
};
const DATASOURCES = read('deploy/grafana/provisioning/datasources/bastion.yml');
const RUNBOOK = read('docs/runbook.md');

const dashboardExprs = DASHBOARD.panels.flatMap((p) => (p.targets ?? []).map((t) => t.expr));
/** Each `expr:`, on one line or as a `|` block (the more-indented lines after it). */
function alertExpressions(yaml: string): string[] {
  const lines = yaml.split('\n');
  const out: string[] = [];
  lines.forEach((line, i) => {
    const m = /^(\s*)expr: (.*)$/.exec(line);
    if (!m) return;
    if (m[2] !== '|') {
      out.push(m[2] ?? '');
      return;
    }
    const indent = (m[1] ?? '').length;
    const block: string[] = [];
    for (let j = i + 1; j < lines.length && (lines[j] ?? '').search(/\S/) > indent; j++) block.push(lines[j] ?? '');
    out.push(block.join('\n'));
  });
  return out;
}
const alertExprs = alertExpressions(ALERTS);

/** Series that are not Bastion's: Prometheus and Alertmanager export them about themselves. */
const EXTERNAL = new Set(['ALERTS', 'up', 'prometheus_notifications_alertmanagers_discovered', 'alertmanager_notifications_failed_total']);

async function exportedNames(): Promise<Set<string>> {
  const t = setup();
  await t.http.get('/healthz'); // one request, so the HTTP histogram has a series
  const token = randomBytes(32);
  const text = (
    await request(createServer(metricsListener(t.metrics.registry, token, createLogger('silent'))))
      .get('/metrics')
      .set('Authorization', `Bearer ${token.toString('base64')}`)
      .expect(200)
  ).text;
  const names = new Set<string>();
  for (const [, name, type] of text.matchAll(/^# TYPE (\S+) (\S+)$/gm)) {
    if (!name) continue;
    names.add(name);
    if (type === 'histogram') for (const s of ['_bucket', '_sum', '_count']) names.add(name + s);
  }
  return names;
}

// Identifiers followed by a selector, a range or the end of a term; PromQL functions are followed by "(".
const metricNames = (expr: string) =>
  [...expr.replace(/"[^"]*"/g, '""').matchAll(/\b([A-Za-z_:][A-Za-z0-9_:]*)\b(?!\s*\()/g)]
    .map((m) => m[1] ?? '')
    .filter((n) => /^(bastion_|http_|nodejs_|process_|prometheus_|alertmanager_)|^(ALERTS|up)$/.test(n));

describe('alert rules and dashboards reference what exists', () => {
  it('uses only metrics Bastion exports (or Prometheus/Alertmanager about themselves)', async () => {
    const exported = await exportedNames();
    const used = new Set([...alertExprs, ...dashboardExprs].flatMap(metricNames));
    expect(used.size).toBeGreaterThan(8);
    const unknown = [...used].filter((n) => !exported.has(n) && !EXTERNAL.has(n));
    expect(unknown).toEqual([]);
  });

  it('filters audit events on actions and outcomes from the closed lists', () => {
    const exprs = [...alertExprs, ...dashboardExprs];
    const actions = exprs.flatMap((e) => [...e.matchAll(/action="([^"]+)"/g)].map((m) => m[1]));
    const outcomes = exprs.flatMap((e) => [...e.matchAll(/outcome="([^"]+)"/g)].map((m) => m[1]));
    expect(actions.length).toBeGreaterThan(5);
    for (const a of actions) expect(AUDIT_ACTIONS).toContain(a);
    for (const o of outcomes) expect(AUDIT_OUTCOMES).toContain(o);
  });

  it('points every alert to a runbook section that exists', () => {
    // GitHub's heading anchors: lower case, punctuation dropped, spaces to hyphens.
    const anchors = new Set(
      [...RUNBOOK.matchAll(/^#{2,3} (.+)$/gm)].map((m) =>
        (m[1] ?? '').toLowerCase().replace(/[^a-z0-9 _-]/g, '').replace(/ /g, '-'),
      ),
    );
    const links = [...ALERTS.matchAll(/runbook: docs\/runbook\.md#(\S+)/g)].map((m) => m[1]);
    expect(links.length).toBeGreaterThan(10);
    for (const link of links) expect(anchors, `missing runbook section #${String(link)}`).toContain(link);
  });

  it('gives every alert a severity the Alertmanager routes know', () => {
    const severities = [...ALERTS.matchAll(/severity: (\S+)/g)].map((m) => m[1]);
    expect(severities.length).toBe([...ALERTS.matchAll(/- alert: /g)].length);
    for (const s of severities) expect(['critical', 'warning', 'info', 'none']).toContain(s);
  });

  it('keeps the dashboard provisioned, read-only and on the provisioned data source', () => {
    expect(DASHBOARD.editable).toBe(false);
    const uids = [...DATASOURCES.matchAll(/uid: (\S+)/g)].map((m) => m[1]);
    for (const p of DASHBOARD.panels.filter((x) => x.type !== 'row')) {
      expect(uids, p.title).toContain(p.datasource?.uid);
      for (const t of p.targets ?? []) expect(uids, p.title).toContain(t.datasource.uid);
    }
  });
});
