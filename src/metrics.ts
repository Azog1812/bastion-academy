import { monitorEventLoopDelay } from 'node:perf_hooks';
import { AUDIT_ACTIONS, AUDIT_OUTCOMES } from './audit.js';
import type { Database } from './db.js';

/**
 * Prometheus metrics, text exposition format 0.0.4, on node: built-ins only.
 *
 * Why not prom-client: the format is a few lines of text and has been stable for
 * years; a dependency would add supply-chain surface (invariant 11) for code we
 * can test exhaustively ourselves.
 *
 * Label values must come from closed sets (route patterns, audit actions, status
 * codes), never from the request: a label fed by user input is both a privacy
 * leak (e-mails, IPs in a monitoring system with its own retention) and a memory
 * DoS (one new series per distinct value). The per-metric series cap below is
 * the backstop if that rule is ever broken.
 */

export type Labels = Readonly<Record<string, string>>;

/** Above this, new label combinations are dropped (and counted) instead of allocated. */
export const MAX_SERIES = 1000;

const METRIC_NAME = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
const LABEL_NAME = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

const escapeHelp = (s: string) => s.replaceAll('\\', '\\\\').replaceAll('\n', '\\n');
const escapeValue = (s: string) => s.replaceAll('\\', '\\\\').replaceAll('\n', '\\n').replaceAll('"', '\\"');
const formatNumber = (n: number) => (n === Infinity ? '+Inf' : n === -Infinity ? '-Inf' : Number.isNaN(n) ? 'NaN' : String(n));

function formatLabels(names: readonly string[], values: readonly string[], extra = ''): string {
  const parts = names.map((n, i) => `${n}="${escapeValue(values[i] ?? '')}"`);
  if (extra) parts.push(extra);
  return parts.length ? `{${parts.join(',')}}` : '';
}

abstract class Metric<S> {
  protected readonly series = new Map<string, { values: string[]; state: S }>();

  constructor(
    readonly name: string,
    readonly help: string,
    protected readonly labelNames: readonly string[],
    private readonly onDrop: () => void,
  ) {
    if (!METRIC_NAME.test(name)) throw new Error(`invalid metric name "${name}"`);
    for (const l of labelNames) if (!LABEL_NAME.test(l) || l === 'le') throw new Error(`invalid label name "${l}"`);
  }

  abstract readonly type: string;
  protected abstract initial(): S;
  protected abstract lines(labels: readonly string[], state: S): string[];

  /** The series for these labels, or undefined once the cap is reached (the sample is dropped). */
  protected get(labels: Labels): S | undefined {
    const values = this.labelNames.map((n) => (Object.hasOwn(labels, n) ? (labels[n] ?? '') : ''));
    const key = values.join('\u0000');
    const found = this.series.get(key);
    if (found) return found.state;
    if (this.series.size >= MAX_SERIES) {
      this.onDrop();
      return undefined;
    }
    const created = { values, state: this.initial() };
    this.series.set(key, created);
    return created.state;
  }

  render(): string {
    const out = [`# HELP ${this.name} ${escapeHelp(this.help)}`, `# TYPE ${this.name} ${this.type}`];
    for (const { values, state } of this.series.values()) out.push(...this.lines(values, state));
    return out.join('\n');
  }
}

export class Counter extends Metric<{ value: number }> {
  readonly type = 'counter';

  constructor(name: string, help: string, labelNames: readonly string[], onDrop: () => void) {
    super(name, help, labelNames, onDrop);
    // Exported at 0 from the start: increase() needs a sample before the first event,
    // or a series born at 1 never "increases" and its alert never fires.
    if (labelNames.length === 0) this.get({});
  }

  /** Exports a known label combination at 0 before anything happens (same reason). */
  init(labels: Labels): void {
    this.get(labels);
  }

  protected initial() {
    return { value: 0 };
  }
  protected lines(labels: readonly string[], s: { value: number }) {
    return [`${this.name}${formatLabels(this.labelNames, labels)} ${formatNumber(s.value)}`];
  }
  inc(labels: Labels = {}, by = 1): void {
    if (!(by >= 0)) throw new Error('a counter only goes up');
    const s = this.get(labels);
    if (s) s.value += by;
  }
  /** Current value, for tests and the CLI. */
  value(labels: Labels = {}): number {
    const values = this.labelNames.map((n) => (Object.hasOwn(labels, n) ? (labels[n] ?? '') : ''));
    return this.series.get(values.join('\u0000'))?.state.value ?? 0;
  }
}

interface HistogramState {
  counts: number[];
  sum: number;
  count: number;
}

export class Histogram extends Metric<HistogramState> {
  readonly type = 'histogram';
  constructor(
    name: string,
    help: string,
    labelNames: readonly string[],
    onDrop: () => void,
    private readonly buckets: readonly number[],
  ) {
    super(name, help, labelNames, onDrop);
    if (buckets.some((b, i) => i > 0 && b <= (buckets[i - 1] ?? -Infinity))) throw new Error('buckets must be strictly increasing');
  }
  protected initial(): HistogramState {
    return { counts: this.buckets.map(() => 0), sum: 0, count: 0 };
  }
  protected lines(labels: readonly string[], s: HistogramState) {
    // Prometheus buckets are cumulative: le="0.5" counts every observation <= 0.5.
    const out = this.buckets.map(
      (b, i) => `${this.name}_bucket${formatLabels(this.labelNames, labels, `le="${formatNumber(b)}"`)} ${String(s.counts[i] ?? 0)}`,
    );
    out.push(`${this.name}_bucket${formatLabels(this.labelNames, labels, 'le="+Inf"')} ${String(s.count)}`);
    out.push(`${this.name}_sum${formatLabels(this.labelNames, labels)} ${formatNumber(s.sum)}`);
    out.push(`${this.name}_count${formatLabels(this.labelNames, labels)} ${String(s.count)}`);
    return out;
  }
  observe(labels: Labels, value: number): void {
    const s = this.get(labels);
    if (!s) return;
    this.buckets.forEach((b, i) => {
      if (value <= b) s.counts[i] = (s.counts[i] ?? 0) + 1;
    });
    s.sum += value;
    s.count++;
  }
}

/** A value read at scrape time (a COUNT in the database, memory in use): never stale, never stored. */
class Gauge {
  readonly type = 'gauge';
  constructor(
    readonly name: string,
    readonly help: string,
    private readonly collect: () => number,
    private readonly constLabels = '',
  ) {
    if (!METRIC_NAME.test(name)) throw new Error(`invalid metric name "${name}"`);
  }
  render(): string {
    return [`# HELP ${this.name} ${escapeHelp(this.help)}`, `# TYPE ${this.name} gauge`, `${this.name}${this.constLabels} ${formatNumber(this.collect())}`].join(
      '\n',
    );
  }
}

export class Registry {
  private readonly metrics: { name: string; render(): string }[] = [];
  readonly dropped: Counter;

  constructor() {
    this.dropped = this.register(
      new Counter('bastion_metrics_series_dropped_total', 'Samples dropped because a metric reached its series cap.', [], () => undefined),
    );
  }

  private register<M extends { name: string; render(): string }>(m: M): M {
    if (this.metrics.some((x) => x.name === m.name)) throw new Error(`metric "${m.name}" registered twice`);
    this.metrics.push(m);
    return m;
  }

  counter(name: string, help: string, labelNames: readonly string[] = []): Counter {
    return this.register(
      new Counter(name, help, labelNames, () => {
        this.dropped.inc();
      }),
    );
  }

  histogram(name: string, help: string, labelNames: readonly string[], buckets: readonly number[]): Histogram {
    return this.register(
      new Histogram(
        name,
        help,
        labelNames,
        () => {
          this.dropped.inc();
        },
        buckets,
      ),
    );
  }

  gauge(name: string, help: string, collect: () => number, constLabels: Labels = {}): void {
    const names = Object.keys(constLabels);
    this.register(new Gauge(name, help, collect, formatLabels(names, names.map((n) => constLabels[n] ?? ''))));
  }

  /** The whole scrape body. A gauge that throws fails the scrape (Prometheus marks the target down) rather than lying. */
  render(): string {
    return this.metrics.map((m) => m.render()).join('\n') + '\n';
  }
}

export interface AppMetrics {
  registry: Registry;
  httpRequests: Counter;
  httpDuration: Histogram;
  auditEvents: Counter;
  integrityFailures: Counter;
}

/** Process-wide, so one sampler per process however many apps are created (tests create hundreds). */
let loopDelay: ReturnType<typeof monitorEventLoopDelay> | undefined;
function eventLoopDelay(): ReturnType<typeof monitorEventLoopDelay> {
  if (!loopDelay) {
    loopDelay = monitorEventLoopDelay({ resolution: 20 });
    loopDelay.enable();
  }
  return loopDelay;
}

const count = (db: Database, sql: string, ...params: number[]): number => (db.prepare(sql).get(...params) as { n: number }).n;

/** The platform's metrics. Security signals come from the audit log, so every audited event is countable. */
export function createMetrics(db: Database): AppMetrics {
  const registry = new Registry();
  eventLoopDelay(); // start sampling now, not at the first scrape

  const metrics: AppMetrics = {
    registry,
    httpRequests: registry.counter('http_requests_total', 'HTTP requests by method, route pattern and status code.', ['method', 'route', 'status']),
    httpDuration: registry.histogram(
      'http_request_duration_seconds',
      'HTTP request latency by method and route pattern.',
      ['method', 'route'],
      [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
    ),
    auditEvents: registry.counter(
      'bastion_audit_events_total',
      'Audited security events by action and outcome (one increment per audit log entry).',
      ['action', 'outcome'],
    ),
    integrityFailures: registry.counter(
      'bastion_integrity_failures_total',
      'Ciphertexts that failed authentication on decryption: the database was modified outside the application.',
    ),
  };

  for (const action of AUDIT_ACTIONS) for (const outcome of AUDIT_OUTCOMES) metrics.auditEvents.init({ action, outcome });

  registry.gauge('bastion_users', 'Registered accounts.', () => count(db, 'SELECT COUNT(*) AS n FROM users'));
  registry.gauge('bastion_mfa_enabled_users', 'Accounts with a second factor enabled.', () =>
    count(db, 'SELECT COUNT(*) AS n FROM user_mfa WHERE enabled_at IS NOT NULL'),
  );
  registry.gauge('bastion_labs_active', 'Lab instances not yet expired.', () =>
    count(db, 'SELECT COUNT(*) AS n FROM lab_instances WHERE expires_at > ?', Date.now()),
  );
  registry.gauge('process_resident_memory_bytes', 'Resident memory size in bytes.', () => process.memoryUsage().rss);
  registry.gauge('nodejs_heap_used_bytes', 'V8 heap in use, in bytes.', () => process.memoryUsage().heapUsed);
  registry.gauge('process_start_time_seconds', 'Start time of the process since the Unix epoch, in seconds.', () =>
    Math.round((Date.now() - process.uptime() * 1000) / 1000),
  );
  registry.gauge('nodejs_eventloop_delay_p99_seconds', 'Event loop delay, 99th percentile since the previous scrape.', () => {
    // A blocked event loop stalls every request at once (a synchronous hash, a huge JSON body).
    const h = eventLoopDelay();
    const p99 = h.percentile(99) / 1e9;
    h.reset();
    return p99;
  });
  registry.gauge('bastion_build_info', 'Always 1; labels identify the runtime.', () => 1, { node_version: process.version });

  return metrics;
}
