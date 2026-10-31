import { describe, expect, it } from 'vitest';
import { MAX_SERIES, Registry } from '../../src/metrics.js';

describe('Prometheus exposition format', () => {
  it('renders counters with HELP, TYPE and labels', () => {
    const r = new Registry();
    const c = r.counter('demo_total', 'A demo counter.', ['kind']);
    c.inc({ kind: 'a' });
    c.inc({ kind: 'a' }, 2);
    c.inc({ kind: 'b' });
    const text = r.render();
    expect(text).toContain('# HELP demo_total A demo counter.\n# TYPE demo_total counter\n');
    expect(text).toContain('demo_total{kind="a"} 3\n');
    expect(text).toContain('demo_total{kind="b"} 1\n');
    expect(text.endsWith('\n')).toBe(true);
    expect(c.value({ kind: 'a' })).toBe(3);
    expect(c.value({ kind: 'never' })).toBe(0);
  });

  it('exports label-less counters and initialised series at 0', () => {
    const r = new Registry();
    r.counter('plain_total', 'No labels.');
    r.counter('known_total', 'Known labels.', ['kind']).init({ kind: 'a' });
    expect(r.render()).toContain('plain_total 0\n');
    expect(r.render()).toContain('known_total{kind="a"} 0\n');
  });

  it('escapes label values and help text, so a value cannot inject a fake sample', () => {
    const r = new Registry();
    r.counter('demo_total', 'line one\nline two \\ end', ['v']).inc({ v: 'x"} 999\nevil_total{a="' });
    const text = r.render();
    expect(text).toContain('# HELP demo_total line one\\nline two \\\\ end\n');
    expect(text).toContain('demo_total{v="x\\"} 999\\nevil_total{a=\\""} 1\n');
    expect(text.split('\n').filter((l) => l.startsWith('evil_total'))).toEqual([]);
  });

  it('renders histograms with cumulative buckets, +Inf, sum and count', () => {
    const r = new Registry();
    const h = r.histogram('demo_seconds', 'Latency.', ['route'], [0.1, 1]);
    h.observe({ route: '/x' }, 0.05);
    h.observe({ route: '/x' }, 0.5);
    h.observe({ route: '/x' }, 3);
    const text = r.render();
    expect(text).toContain('demo_seconds_bucket{route="/x",le="0.1"} 1\n');
    expect(text).toContain('demo_seconds_bucket{route="/x",le="1"} 2\n');
    expect(text).toContain('demo_seconds_bucket{route="/x",le="+Inf"} 3\n');
    expect(text).toContain('demo_seconds_sum{route="/x"} 3.55\n');
    expect(text).toContain('demo_seconds_count{route="/x"} 3\n');
  });

  it('reads gauges at scrape time, with constant labels', () => {
    const r = new Registry();
    let n = 1;
    r.gauge('demo_value', 'Live value.', () => n, { node_version: 'v1' });
    expect(r.render()).toContain('demo_value{node_version="v1"} 1\n');
    n = 7;
    expect(r.render()).toContain('demo_value{node_version="v1"} 7\n');
    r.gauge('demo_inf', 'Infinite.', () => Infinity);
    r.gauge('demo_nan', 'Not a number.', () => NaN);
    expect(r.render()).toContain('demo_inf +Inf\n');
    expect(r.render()).toContain('demo_nan NaN\n');
  });

  it('caps the number of series per metric and counts what it drops (cardinality DoS backstop)', () => {
    const r = new Registry();
    const c = r.counter('demo_total', 'Unbounded on purpose.', ['id']);
    for (let i = 0; i < MAX_SERIES + 50; i++) c.inc({ id: String(i) });
    const text = r.render();
    expect(text.split('\n').filter((l) => l.startsWith('demo_total{'))).toHaveLength(MAX_SERIES);
    expect(text).toContain('bastion_metrics_series_dropped_total 50\n');
    c.inc({ id: '0' }); // existing series still count
    expect(c.value({ id: '0' })).toBe(2);
    const h = r.histogram('demo_seconds', 'Also capped.', ['id'], [1]);
    for (let i = 0; i < MAX_SERIES + 1; i++) h.observe({ id: String(i) }, 0.5);
    expect(r.render()).toContain('bastion_metrics_series_dropped_total 51\n');
  });

  it('rejects invalid definitions and counters that go down', () => {
    const r = new Registry();
    expect(() => r.counter('bad-name', 'x')).toThrow('invalid metric name');
    expect(() => r.counter('ok_total', 'x', ['bad-label'])).toThrow('invalid label name');
    expect(() => r.histogram('h_seconds', 'x', ['le'], [1])).toThrow('invalid label name');
    expect(() => r.histogram('h2_seconds', 'x', [], [1, 1])).toThrow('strictly increasing');
    expect(() => {
      r.gauge('bad gauge', 'x', () => 1);
    }).toThrow('invalid metric name');
    r.counter('dup_total', 'x');
    expect(() => r.counter('dup_total', 'x')).toThrow('registered twice');
    expect(() => {
      r.counter('down_total', 'x').inc({}, -1);
    }).toThrow('only goes up');
  });
});
