import { z } from 'zod';

/**
 * Detection-rule engine (ADR 0010). Learners write rules in a small,
 * Sigma-inspired JSON language; the server evaluates them against a labelled
 * dataset. This is the one place where learner input is *executed* by the
 * platform, so the language is deliberately small:
 *
 * - no regular expressions: a learner regex runs on the event loop, and one
 *   catastrophic pattern (ReDoS) would stall every user. Plain substring and
 *   prefix/suffix tests are linear and enough to teach detection;
 * - field names must be fields of the dataset (no `__proto__`, no lookups of
 *   anything that is not event data);
 * - every dimension is capped (blocks, fields, values, value length).
 */

export type FieldValue = string | number;
export type DetectionEvent = Readonly<Record<string, FieldValue>> & { readonly id: string };

const MODIFIERS = ['contains', 'startswith', 'endswith', 'gte', 'lte'] as const;
type Modifier = (typeof MODIFIERS)[number] | 'equals';

const value = z.union([z.string().min(1).max(200), z.number()]);
const values = z.union([value, z.array(value).min(1).max(20)]);

export function ruleSchema(fields: readonly string[]) {
  const validKey = (k: string) => {
    const [field, modifier, extra] = k.split('|');
    return extra === undefined && field !== undefined && fields.includes(field) && (modifier === undefined || (MODIFIERS as readonly string[]).includes(modifier));
  };
  const help = `use a field of this dataset (${fields.join(', ')}), optionally followed by |contains, |startswith, |endswith, |gte or |lte`;
  // Keys are checked on the RAW object, one by one: the learner is told which key is wrong, and a key
  // such as "__proto__", which rebuilding the object would silently drop, is rejected instead of ignored.
  const block = z
    .unknown()
    .superRefine((raw, ctx) => {
      if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return;
      const keys = Object.keys(raw);
      if (keys.length < 1 || keys.length > 10) ctx.addIssue({ code: 'custom', message: 'a block has 1 to 10 conditions' });
      for (const k of keys.filter((key) => !validKey(key))) ctx.addIssue({ code: 'custom', path: [k], message: help });
    })
    .pipe(z.record(z.string(), values));
  // A single block is a list of one: normalising first keeps validation messages precise (no opaque union error).
  const blocks = z.preprocess((v: unknown): unknown => (Array.isArray(v) ? v : [v]), z.array(block).min(1).max(10));
  const field = z.string().refine((f) => fields.includes(f), 'unknown field');
  return z
    .object({
      title: z.string().max(120).optional(),
      /** Selects events: every condition of a block must hold; any block may match. */
      match: blocks,
      /** Removes events that a block of `exclude` matches (known benign activity). */
      exclude: blocks.optional(),
      /** Behavioural detection: alert on a group with at least `min` events (or distinct values) within a window. */
      threshold: z
        .object({
          groupBy: field,
          distinct: field.optional(),
          min: z.number().int().min(2).max(1000),
          windowSeconds: z.number().int().min(1).max(86_400),
        })
        .strict()
        .optional(),
    })
    .strict();
}

export type Rule = z.infer<ReturnType<typeof ruleSchema>>;
type Block = Record<string, FieldValue | FieldValue[]>;

const lower = (v: FieldValue) => String(v).toLowerCase();

function test(actual: FieldValue | undefined, modifier: Modifier, expected: FieldValue): boolean {
  if (actual === undefined) return false;
  if (modifier === 'gte' || modifier === 'lte') {
    const a = Number(actual);
    const e = Number(expected);
    if (Number.isNaN(a) || Number.isNaN(e)) return false;
    return modifier === 'gte' ? a >= e : a <= e;
  }
  // Case-insensitive, as in Sigma: attackers vary case, rules should not have to.
  const a = lower(actual);
  const e = lower(expected);
  switch (modifier) {
    case 'contains':
      return a.includes(e);
    case 'startswith':
      return a.startsWith(e);
    case 'endswith':
      return a.endsWith(e);
    default:
      return a === e;
  }
}

function matchesBlock(event: DetectionEvent, block: Block): boolean {
  return Object.entries(block).every(([key, expected]) => {
    const [field, modifier = 'equals'] = key.split('|') as [string, Modifier | undefined];
    // Own data fields only: the schema already restricted `field` to the dataset's fields.
    const actual = Object.hasOwn(event, field) ? event[field] : undefined;
    return (Array.isArray(expected) ? expected : [expected]).some((e) => test(actual, modifier, e));
  });
}

const anyBlock = (event: DetectionEvent, blocks: Block | Block[]) => (Array.isArray(blocks) ? blocks : [blocks]).some((b) => matchesBlock(event, b));

/** The events a rule alerts on. With a threshold, only events inside a window that reached it. */
export function alertedEvents(rule: Rule, events: readonly DetectionEvent[]): DetectionEvent[] {
  const selected = events.filter((e) => anyBlock(e, rule.match) && !(rule.exclude && anyBlock(e, rule.exclude)));
  const t = rule.threshold;
  if (!t) return selected;

  const groups = new Map<string, DetectionEvent[]>();
  for (const e of selected) {
    const g = lower(e[t.groupBy] ?? '');
    const list = groups.get(g);
    if (list) list.push(e);
    else groups.set(g, [e]);
  }
  const alerted = new Set<DetectionEvent>();
  for (const group of groups.values()) {
    const sorted = [...group].sort((a, b) => Number(a.ts) - Number(b.ts));
    // Sliding window: for each start, the events within windowSeconds.
    for (let i = 0, j = 0; i < sorted.length; i++) {
      const start = Number(sorted[i]?.ts);
      while (j < sorted.length && Number(sorted[j]?.ts) - start <= t.windowSeconds) j++;
      const window = sorted.slice(i, j);
      const size = t.distinct === undefined ? window.length : new Set(window.map((e) => lower(e[t.distinct ?? ''] ?? ''))).size;
      if (size >= t.min) for (const e of window) alerted.add(e);
    }
  }
  return events.filter((e) => alerted.has(e));
}

export interface Dataset {
  /** Fields a rule may use. */
  fields: readonly string[];
  /** What counts as one detection: a single event, or an entity (e.g. an attacking IP). */
  unit: 'event' | 'entity';
  /** For `entity` datasets: the field naming the entity. */
  entityField?: string;
  events: readonly DetectionEvent[];
  /** Event ids (unit `event`) or entity values (unit `entity`) that are malicious. */
  malicious: ReadonlySet<string>;
}

export interface Score {
  alerts: number;
  detected: number;
  missed: number;
  falsePositives: number;
  total: number;
  /** A few examples to learn from (event ids or entities), never the full answer. */
  examples: { missed: string[]; falsePositives: string[] };
  perfect: boolean;
}

/** Precision and recall, in a SOC's words: every attack caught, and no analyst time wasted. */
export function score(rule: Rule, dataset: Dataset): Score {
  const unitOf = (e: DetectionEvent) => (dataset.unit === 'entity' ? lower(e[dataset.entityField ?? ''] ?? '') : e.id);
  const alerts = new Set(alertedEvents(rule, dataset.events).map(unitOf));
  const missed = [...dataset.malicious].filter((m) => !alerts.has(m));
  const falsePositives = [...alerts].filter((a) => !dataset.malicious.has(a));
  return {
    alerts: alerts.size,
    detected: dataset.malicious.size - missed.length,
    missed: missed.length,
    falsePositives: falsePositives.length,
    total: dataset.malicious.size,
    examples: { missed: missed.slice(0, 3), falsePositives: falsePositives.slice(0, 3) },
    perfect: missed.length === 0 && falsePositives.length === 0,
  };
}
