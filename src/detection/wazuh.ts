import type { Score } from './engine.js';

/**
 * Wazuh rule challenges (ADR 0014). Learners write real Wazuh XML rules, the kind
 * that goes into local_rules.xml; the server parses a closed subset and evaluates
 * it against a labelled dataset of Wazuh-shaped events. Nothing is handed to Wazuh
 * or to a general-purpose XML parser:
 *
 * - the XML reader below knows elements, attributes, text, comments and the five
 *   predefined entities, nothing else: a DOCTYPE, an entity declaration, CDATA or
 *   a processing instruction is refused, so XXE and entity expansion ("billion
 *   laughs") have nothing to work with;
 * - patterns are OS_Match (substring, ^ and $ anchors, | alternatives), linear in
 *   the input: no regular expression ever runs on learner input (ADR 0010);
 * - every dimension is capped (size, depth, nodes, rules, conditions), and a rule
 *   may only refer to rules defined before it, so the rule tree has no cycle.
 */

export class WazuhRuleError extends Error {}

/* ------------------------------------------------------------- XML reader */

const MAX_SOURCE = 8000;
const MAX_DEPTH = 4; // group > rule > mitre > id
const MAX_NODES = 300;

interface XmlNode {
  name: string;
  attrs: Map<string, string>;
  children: XmlNode[];
  text: string;
  line: number;
}

const ENTITIES: Readonly<Record<string, string>> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
const isNameChar = (c: string) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c === '_';
const isSpace = (c: string) => c === ' ' || c === '\t' || c === '\n' || c === '\r';

function lineAt(src: string, index: number): number {
  let n = 1;
  for (let k = 0; k < index; k++) if (src[k] === '\n') n++;
  return n;
}

/** Replaces the five predefined entities; any other `&` is an error (no numeric or declared entity). */
function decode(raw: string, line: number): string {
  let out = '';
  for (let k = 0; k < raw.length; k++) {
    const c = raw.charAt(k);
    if (c !== '&') {
      out += c;
      continue;
    }
    const end = raw.indexOf(';', k);
    const name = end === -1 ? '' : raw.slice(k + 1, end);
    if (!Object.hasOwn(ENTITIES, name)) throw new WazuhRuleError(`ligne ${String(line)} : entité inconnue (seules &lt; &gt; &amp; &quot; &apos; sont acceptées)`);
    out += ENTITIES[name] ?? '';
    k = end;
  }
  return out;
}

function parseTag(body: string, line: number): { name: string; attrs: Map<string, string> } {
  let j = 0;
  while (j < body.length && isNameChar(body.charAt(j))) j++;
  const name = body.slice(0, j);
  if (!name || !/^[a-z_]/i.test(name)) throw new WazuhRuleError(`ligne ${String(line)} : nom d'élément invalide`);
  const attrs = new Map<string, string>();
  for (;;) {
    const before = j;
    while (j < body.length && isSpace(body.charAt(j))) j++;
    if (j >= body.length) break;
    if (j === before) throw new WazuhRuleError(`ligne ${String(line)} : espace attendu avant un attribut`);
    const start = j;
    while (j < body.length && isNameChar(body.charAt(j))) j++;
    const attr = body.slice(start, j);
    while (j < body.length && isSpace(body.charAt(j))) j++;
    if (!attr || body.charAt(j) !== '=') throw new WazuhRuleError(`ligne ${String(line)} : attribut mal formé dans <${name}>`);
    j++;
    while (j < body.length && isSpace(body.charAt(j))) j++;
    const q = body.charAt(j);
    if (q !== '"' && q !== "'") throw new WazuhRuleError(`ligne ${String(line)} : la valeur de ${attr} doit être entre guillemets`);
    const end = body.indexOf(q, j + 1);
    if (end === -1) throw new WazuhRuleError(`ligne ${String(line)} : guillemet non fermé dans <${name}>`);
    if (attrs.has(attr)) throw new WazuhRuleError(`ligne ${String(line)} : attribut ${attr} répété`);
    attrs.set(attr, decode(body.slice(j + 1, end), line));
    j = end + 1;
  }
  return { name, attrs };
}

export function parseXml(src: string): XmlNode[] {
  if (src.length > MAX_SOURCE) throw new WazuhRuleError(`règles trop longues (${String(MAX_SOURCE)} caractères au plus)`);
  // XXE and entity expansion need a DTD; CDATA and processing instructions are not needed for rules.
  if (src.includes('<!DOCTYPE') || src.includes('<!ENTITY') || src.includes('<![CDATA[') || src.includes('<?')) {
    throw new WazuhRuleError('DOCTYPE, déclarations d’entités, CDATA et instructions de traitement sont refusés');
  }
  const roots: XmlNode[] = [];
  const stack: XmlNode[] = [];
  let nodes = 0;
  let i = 0;
  while (i < src.length) {
    const lt = src.indexOf('<', i);
    const text = src.slice(i, lt === -1 ? src.length : lt);
    const top = stack[stack.length - 1];
    if (top) top.text += decode(text, lineAt(src, i));
    else if (text.trim()) throw new WazuhRuleError(`ligne ${String(lineAt(src, i))} : texte en dehors de tout élément`);
    if (lt === -1) break;
    const line = lineAt(src, lt);
    if (src.startsWith('<!--', lt)) {
      const end = src.indexOf('-->', lt + 4);
      if (end === -1) throw new WazuhRuleError(`ligne ${String(line)} : commentaire non fermé`);
      i = end + 3;
      continue;
    }
    const gt = src.indexOf('>', lt);
    if (gt === -1) throw new WazuhRuleError(`ligne ${String(line)} : balise non fermée`);
    const tag = src.slice(lt + 1, gt);
    i = gt + 1;
    if (tag.startsWith('/')) {
      const name = tag.slice(1).trim();
      const open = stack.pop();
      if (open?.name !== name) throw new WazuhRuleError(`ligne ${String(line)} : </${name}> ne ferme pas <${open?.name ?? '…'}>`);
      continue;
    }
    const selfClosing = tag.endsWith('/');
    const { name, attrs } = parseTag(selfClosing ? tag.slice(0, -1).trimEnd() : tag, line);
    if (++nodes > MAX_NODES) throw new WazuhRuleError(`trop d'éléments (${String(MAX_NODES)} au plus)`);
    if (stack.length >= MAX_DEPTH) throw new WazuhRuleError(`ligne ${String(line)} : imbrication trop profonde`);
    const node: XmlNode = { name, attrs, children: [], text: '', line };
    if (top) top.children.push(node);
    else roots.push(node);
    if (!selfClosing) stack.push(node);
  }
  const open = stack.pop();
  if (open) throw new WazuhRuleError(`ligne ${String(open.line)} : <${open.name}> n'est jamais fermé`);
  return roots;
}

/* ----------------------------------------------------------- rule compiler */

/** OS_Match: case-insensitive substring tests, `^`/`$` anchors, `|` alternatives. Linear, no backtracking. */
export function osMatch(pattern: string, line: number): (value: string) => boolean {
  const alternatives = pattern.split('|').map((raw) => {
    const start = raw.startsWith('^');
    const body = start ? raw.slice(1) : raw;
    const end = body.endsWith('$');
    const text = (end ? body.slice(0, -1) : body).toLowerCase();
    if (!text) throw new WazuhRuleError(`ligne ${String(line)} : alternative vide dans « ${pattern} »`);
    return { text, start, end };
  });
  return (value) => {
    const v = value.toLowerCase();
    return alternatives.some(({ text, start, end }) =>
      start && end ? v === text : start ? v.startsWith(text) : end ? v.endsWith(text) : v.includes(text),
    );
  };
}

function ipv4(value: string): number | null {
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
    n = n * 256 + Number(p);
  }
  return n;
}

/** `<srcip>`: an IPv4 address or CIDR block, `!` negates (Wazuh syntax). */
function srcipTest(raw: string, line: number): (ip: string) => boolean {
  const negated = raw.startsWith('!');
  const [addr = '', bits = '32'] = (negated ? raw.slice(1) : raw).trim().split('/');
  const base = ipv4(addr);
  const prefix = Number(bits);
  if (base === null || !/^\d{1,2}$/.test(bits) || prefix > 32) throw new WazuhRuleError(`ligne ${String(line)} : <srcip> attend une adresse IPv4 ou un bloc CIDR, par exemple 10.0.5.20 ou !10.0.5.0/24`);
  const size = 2 ** (32 - prefix);
  const net = base - (base % size);
  return (ip) => {
    const v = ipv4(ip);
    const inside = v !== null && v >= net && v < net + size;
    return negated ? !inside : inside;
  };
}

export interface WazuhEvent {
  readonly id: string;
  readonly ts: number;
  /** The rule of the stock ruleset (or of the brief) that this event reached before any learner rule. */
  readonly sid: number;
  readonly srcip: string;
  readonly user: string;
  readonly program_name: string;
  readonly full_log: string;
  /** Fields extracted by the decoder (dynamic fields, `<field name="…">`). */
  readonly fields: Readonly<Record<string, string>>;
}

export interface StockRule {
  id: number;
  level: number;
  description: string;
  groups: readonly string[];
}

export interface WazuhDataset {
  decoder: string;
  /** Decoded field names a `<field>` may test. */
  fields: readonly string[];
  stock: readonly StockRule[];
  events: readonly WazuhEvent[];
  unit: 'event' | 'entity';
  entityField?: 'srcip' | 'user';
  malicious: ReadonlySet<string>;
  /** An alert counts from this level: below, the SOC is not paged. */
  minLevel: number;
}

type Parent = { kind: 'sid'; ids: number[] } | { kind: 'group'; name: string } | { kind: 'matched_sid'; id: number } | { kind: 'matched_group'; name: string };
type Condition = (e: WazuhEvent) => boolean;

export interface CompiledRule {
  id: number;
  level: number;
  description: string;
  groups: readonly string[];
  parent: Parent;
  conditions: Condition[];
  frequency?: { count: number; timeframe: number; sameSrcip: boolean; sameUser: boolean };
}

const MAX_RULES = 10;
const MAX_CONDITIONS = 8;
const RULE_ATTRS = new Set(['id', 'level', 'frequency', 'timeframe']);
const PARENTS = ['if_sid', 'if_group', 'if_matched_sid', 'if_matched_group'] as const;

function int(raw: string | undefined, min: number, max: number, what: string, line: number): number {
  const n = raw !== undefined && /^\d{1,6}$/.test(raw.trim()) ? Number(raw.trim()) : NaN;
  if (!(n >= min && n <= max)) throw new WazuhRuleError(`ligne ${String(line)} : ${what} doit être un entier de ${String(min)} à ${String(max)}`);
  return n;
}

function only(node: XmlNode, allowed: readonly string[]): void {
  for (const a of node.attrs.keys()) {
    if (!allowed.includes(a)) throw new WazuhRuleError(`ligne ${String(node.line)} : attribut ${a} non pris en charge sur <${node.name}>`);
  }
}

function negatable(node: XmlNode, test: Condition): Condition {
  const negate = node.attrs.get('negate');
  if (negate !== undefined && negate !== 'yes' && negate !== 'no') throw new WazuhRuleError(`ligne ${String(node.line)} : negate vaut "yes" ou "no"`);
  return negate === 'yes' ? (e) => !test(e) : test;
}

const UNSUPPORTED: Readonly<Record<string, string>> = {
  regex: 'les expressions régulières ne sont pas évaluées dans ces défis (ReDoS) : utilise <match> ou <field type="osmatch">',
  pcre2: 'les expressions régulières ne sont pas évaluées dans ces défis (ReDoS)',
  decoded_as: 'le décodeur est déjà fixé par le jeu de données : précise une règle avec <if_sid>',
};

function compileRule(node: XmlNode, inherited: readonly string[], known: Map<number, readonly string[]>, fields: readonly string[]): CompiledRule {
  const line = node.line;
  for (const a of node.attrs.keys()) if (!RULE_ATTRS.has(a)) throw new WazuhRuleError(`ligne ${String(line)} : attribut ${a} non pris en charge (id, level, frequency, timeframe)`);
  const id = int(node.attrs.get('id'), 100_000, 120_000, 'id (règles locales)', line);
  if (known.has(id)) throw new WazuhRuleError(`ligne ${String(line)} : l'identifiant ${String(id)} est déjà utilisé`);
  const level = int(node.attrs.get('level'), 0, 16, 'level', line);
  const hasFrequency = node.attrs.has('frequency') || node.attrs.has('timeframe');

  let parent: Parent | undefined;
  let description = '';
  const groups = [...inherited];
  const conditions: Condition[] = [];
  const seen = new Set<string>();
  let sameSrcip = false;
  let sameUser = false;

  const refer = (raw: string, l: number): number => {
    const sid = int(raw, 1, 120_000, 'une règle parente', l);
    if (!known.has(sid)) throw new WazuhRuleError(`ligne ${String(l)} : la règle ${String(sid)} n'existe pas ici (règles fournies ou définies plus haut)`);
    return sid;
  };

  for (const child of node.children) {
    const l = child.line;
    const text = child.text.trim();
    const once = (key: string) => {
      if (seen.has(key)) throw new WazuhRuleError(`ligne ${String(l)} : <${child.name}> répété dans la même règle`);
      seen.add(key);
    };
    if (child.children.length > 0 && child.name !== 'mitre') throw new WazuhRuleError(`ligne ${String(l)} : <${child.name}> ne contient que du texte`);
    if ((PARENTS as readonly string[]).includes(child.name)) {
      only(child, []);
      if (parent) throw new WazuhRuleError(`ligne ${String(l)} : une seule règle parente par règle (if_sid, if_group, if_matched_sid ou if_matched_group)`);
      if (child.name === 'if_sid') {
        const ids = text.split(/[\s,]+/).filter(Boolean);
        if (ids.length < 1 || ids.length > 10) throw new WazuhRuleError(`ligne ${String(l)} : <if_sid> cite de 1 à 10 règles`);
        parent = { kind: 'sid', ids: ids.map((s) => refer(s, l)) };
      } else if (child.name === 'if_matched_sid') parent = { kind: 'matched_sid', id: refer(text, l) };
      else {
        if (!text || text.length > 50) throw new WazuhRuleError(`ligne ${String(l)} : nom de groupe attendu`);
        parent = child.name === 'if_group' ? { kind: 'group', name: text } : { kind: 'matched_group', name: text };
      }
      continue;
    }
    switch (child.name) {
      case 'description':
        only(child, []);
        once('description');
        if (!text || text.length > 200) throw new WazuhRuleError(`ligne ${String(l)} : la description fait de 1 à 200 caractères`);
        description = text;
        break;
      case 'group':
        only(child, []);
        groups.push(...text.split(',').map((g) => g.trim()).filter(Boolean));
        break;
      case 'mitre':
        only(child, []);
        for (const m of child.children) {
          if (m.name !== 'id' || !/^T\d{4}$|^T\d{4}\.\d{3}$/.test(m.text.trim())) throw new WazuhRuleError(`ligne ${String(m.line)} : <mitre> contient des <id> de techniques, par exemple T1110`);
        }
        break;
      case 'same_srcip':
      case 'same_source_ip':
        only(child, []);
        once('same_srcip');
        sameSrcip = true;
        break;
      case 'same_user':
        only(child, []);
        once('same_user');
        sameUser = true;
        break;
      case 'match':
      case 'program_name':
      case 'user': {
        only(child, ['negate', 'type']);
        once(child.name);
        const type = child.attrs.get('type');
        if (type !== undefined && type !== 'osmatch') throw new WazuhRuleError(`ligne ${String(l)} : seul type="osmatch" est évalué ici`);
        const test = osMatch(text, l);
        const pick = child.name === 'match' ? (e: WazuhEvent) => e.full_log : child.name === 'user' ? (e: WazuhEvent) => e.user : (e: WazuhEvent) => e.program_name;
        conditions.push(negatable(child, (e) => test(pick(e))));
        break;
      }
      case 'srcip': {
        only(child, ['negate']);
        once('srcip');
        const test = srcipTest(text, l);
        conditions.push(negatable(child, (e) => test(e.srcip)));
        break;
      }
      case 'field': {
        only(child, ['name', 'type', 'negate']);
        const name = child.attrs.get('name') ?? '';
        if (!fields.includes(name)) throw new WazuhRuleError(`ligne ${String(l)} : champ inconnu « ${name} » (champs décodés : ${fields.join(', ') || 'aucun'})`);
        if (child.attrs.get('type') !== 'osmatch') {
          throw new WazuhRuleError(`ligne ${String(l)} : dans Wazuh, <field> est une expression régulière par défaut ; ajoute type="osmatch" (les expressions régulières ne sont pas évaluées ici)`);
        }
        once(`field:${name}`);
        const test = osMatch(text, l);
        // Own data fields only: the name was checked against the dataset's closed list.
        conditions.push(negatable(child, (e) => test(Object.hasOwn(e.fields, name) ? (e.fields[name] ?? '') : '')));
        break;
      }
      default:
        throw new WazuhRuleError(`ligne ${String(l)} : <${child.name}> non pris en charge${UNSUPPORTED[child.name] ? ` : ${UNSUPPORTED[child.name] ?? ''}` : ''}`);
    }
    if (conditions.length > MAX_CONDITIONS) throw new WazuhRuleError(`ligne ${String(l)} : ${String(MAX_CONDITIONS)} conditions au plus par règle`);
  }

  if (!parent) throw new WazuhRuleError(`ligne ${String(line)} : une règle locale précise une règle existante (<if_sid>, <if_group>, <if_matched_sid> ou <if_matched_group>)`);
  if (!description) throw new WazuhRuleError(`ligne ${String(line)} : <description> est obligatoire`);
  const matched = parent.kind === 'matched_sid' || parent.kind === 'matched_group';
  if (matched !== hasFrequency) {
    throw new WazuhRuleError(`ligne ${String(line)} : frequency et timeframe vont avec <if_matched_sid> ou <if_matched_group>, et réciproquement`);
  }
  if ((sameSrcip || sameUser) && !matched) throw new WazuhRuleError(`ligne ${String(line)} : <same_srcip /> et <same_user /> n'ont de sens que dans une règle de corrélation`);
  const rule: CompiledRule = { id, level, description, groups, parent, conditions };
  if (matched) {
    rule.frequency = {
      count: int(node.attrs.get('frequency'), 2, 9999, 'frequency', line),
      timeframe: int(node.attrs.get('timeframe'), 1, 86_400, 'timeframe', line),
      sameSrcip,
      sameUser,
    };
  }
  return rule;
}

/** Parses learner XML into rules. Errors carry a line number and say what to change. */
export function compileRules(src: string, dataset: Pick<WazuhDataset, 'stock' | 'fields'>): CompiledRule[] {
  const known = new Map<number, readonly string[]>(dataset.stock.map((s) => [s.id, s.groups]));
  const rules: CompiledRule[] = [];
  const add = (node: XmlNode, inherited: readonly string[]) => {
    if (rules.length >= MAX_RULES) throw new WazuhRuleError(`${String(MAX_RULES)} règles au plus`);
    const rule = compileRule(node, inherited, known, dataset.fields);
    known.set(rule.id, rule.groups);
    rules.push(rule);
  };
  for (const root of parseXml(src)) {
    if (root.name === 'rule') add(root, []);
    else if (root.name === 'group') {
      only(root, ['name']);
      const names = (root.attrs.get('name') ?? '').split(',').map((g) => g.trim()).filter(Boolean);
      for (const child of root.children) {
        if (child.name !== 'rule') throw new WazuhRuleError(`ligne ${String(child.line)} : <group> ne contient que des <rule>`);
        add(child, names);
      }
    } else throw new WazuhRuleError(`ligne ${String(root.line)} : attendu <group> ou <rule>, pas <${root.name}>`);
  }
  if (rules.length === 0) throw new WazuhRuleError('aucune règle trouvée');
  return rules;
}

/* -------------------------------------------------------------- evaluation */

interface Node {
  id: number;
  level: number;
  groups: readonly string[];
  learner: boolean;
}

const childOf = (rule: CompiledRule, node: Node) => {
  const p = rule.parent;
  switch (p.kind) {
    case 'sid':
      return p.ids.includes(node.id);
    case 'matched_sid':
      return p.id === node.id;
    case 'group':
    case 'matched_group':
      return node.groups.includes(p.name);
  }
};

/**
 * Walks each event down the rule tree as Wazuh does: from the stock rule it reached,
 * into the first child rule whose conditions hold, until none does. The last rule
 * reached decides the alert and its level (a level 0 child silences its parent).
 * Correlation rules count, within `timeframe`, the earlier events that reached the
 * rule or group they name, this one included.
 */
export function evaluate(rules: readonly CompiledRule[], dataset: WazuhDataset): { event: WazuhEvent; rule: CompiledRule }[] {
  const stock = new Map(dataset.stock.map((s) => [s.id, s]));
  const history = new Map<string, WazuhEvent[]>();
  const remember = (node: Node, e: WazuhEvent) => {
    for (const key of [`sid:${String(node.id)}`, ...node.groups.map((g) => `group:${g}`)]) {
      const list = history.get(key);
      if (list) list.push(e);
      else history.set(key, [e]);
    }
  };
  const frequencyHolds = (rule: CompiledRule, e: WazuhEvent) => {
    const f = rule.frequency;
    if (!f) return true;
    const p = rule.parent;
    const key = p.kind === 'matched_sid' ? `sid:${String(p.id)}` : p.kind === 'matched_group' ? `group:${p.name}` : '';
    const count = (history.get(key) ?? []).filter(
      (h) => h.ts <= e.ts && e.ts - h.ts <= f.timeframe && (!f.sameSrcip || h.srcip === e.srcip) && (!f.sameUser || h.user === e.user),
    ).length;
    return count >= f.count;
  };

  const alerts: { event: WazuhEvent; rule: CompiledRule }[] = [];
  for (const e of [...dataset.events].sort((a, b) => a.ts - b.ts)) {
    const base = stock.get(e.sid);
    if (!base) continue;
    let node: Node = { ...base, learner: false };
    let last: CompiledRule | undefined;
    remember(node, e);
    const visited = new Set<number>();
    for (;;) {
      const current = node;
      const next = rules.find((r) => !visited.has(r.id) && childOf(r, current) && r.conditions.every((c) => c(e)) && frequencyHolds(r, e));
      if (!next) break;
      visited.add(next.id);
      node = { id: next.id, level: next.level, groups: next.groups, learner: true };
      last = next;
      remember(node, e);
    }
    if (node.learner && last && last.level >= dataset.minLevel) alerts.push({ event: e, rule: last });
  }
  return alerts;
}

/** Same verdict as the JSON detection challenges: every attack, and no analyst time wasted. */
export function scoreWazuh(src: string, dataset: WazuhDataset): Score {
  const rules = compileRules(src, dataset);
  const unitOf = (e: WazuhEvent) => (dataset.unit === 'entity' ? (dataset.entityField === 'user' ? e.user : e.srcip) : e.id);
  const alerts = new Set(evaluate(rules, dataset).map(({ event }) => unitOf(event)));
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
