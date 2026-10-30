/**
 * Markdown → syntax tree, for the subset used in content/ (ADR 0007).
 *
 * The parser never produces HTML. It returns a tree that render.ts turns into
 * DOM nodes with textContent, so lesson text can never become markup, and raw
 * HTML in a lesson is shown as text. Pure functions: no DOM, unit-tested in Node.
 */

export type Inline =
  | { t: 'text'; v: string }
  | { t: 'code'; v: string }
  | { t: 'strong'; c: Inline[] }
  | { t: 'em'; c: Inline[] }
  | { t: 'link'; href: string; c: Inline[] };

export type Block =
  | { t: 'heading'; level: 1 | 2 | 3; c: Inline[] }
  | { t: 'paragraph'; c: Inline[] }
  | { t: 'code'; lang: string; v: string }
  | { t: 'list'; ordered: boolean; start: number; items: Inline[][] }
  | { t: 'quote'; c: Block[] }
  | { t: 'table'; head: Inline[][]; rows: Inline[][][] };

/** Only absolute https links and in-app hash routes are kept; anything else (javascript:, data:, http:) becomes text. */
export function safeHref(href: string): string | null {
  if (href.startsWith('#/')) return href;
  try {
    const url = new URL(href);
    return url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}

export function parseInline(src: string): Inline[] {
  const out: Inline[] = [];
  let text = '';
  const flush = () => {
    if (text) out.push({ t: 'text', v: text });
    text = '';
  };

  let i = 0;
  while (i < src.length) {
    const ch = src.charAt(i);
    if (ch === '`') {
      const end = src.indexOf('`', i + 1);
      if (end > i) {
        flush();
        out.push({ t: 'code', v: src.slice(i + 1, end) });
        i = end + 1;
        continue;
      }
    } else if (src.startsWith('**', i)) {
      const end = src.indexOf('**', i + 2);
      if (end > i + 2) {
        flush();
        out.push({ t: 'strong', c: parseInline(src.slice(i + 2, end)) });
        i = end + 2;
        continue;
      }
    } else if (ch === '*') {
      const end = src.indexOf('*', i + 1);
      if (end > i + 1 && src[end + 1] !== '*') {
        flush();
        out.push({ t: 'em', c: parseInline(src.slice(i + 1, end)) });
        i = end + 1;
        continue;
      }
    } else if (ch === '[') {
      const close = src.indexOf('](', i + 1);
      const end = close === -1 ? -1 : src.indexOf(')', close + 2);
      if (close > i && end > close) {
        const label = parseInline(src.slice(i + 1, close));
        const href = safeHref(src.slice(close + 2, end).trim());
        flush();
        out.push(href ? { t: 'link', href, c: label } : { t: 'em', c: label });
        i = end + 1;
        continue;
      }
    }
    text += ch;
    i++;
  }
  flush();
  return out;
}

const splitRow = (line: string): string[] =>
  line
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map((c) => c.trim());

/** `|---|:--:|` and friends. Character-class check: linear time, no backtracking. */
const isSeparatorRow = (line: string): boolean => /^[|:\s-]+$/.test(line) && line.includes('---');

export function parseMarkdown(src: string): Block[] {
  const lines = src.replace(/\r\n?/g, '\n').split('\n');
  const blocks: Block[] = [];
  let i = 0;
  const at = (k: number): string => lines[k] ?? '';

  while (i < lines.length) {
    const line = at(i);

    if (line.trim() === '') {
      i++;
      continue;
    }

    // Fences may be indented by up to 3 spaces (CommonMark), e.g. inside a list item.
    const fence = /^( {0,3})```(\w*)\s*$/.exec(line);
    if (fence) {
      const indent = ' '.repeat((fence[1] ?? '').length);
      const body: string[] = [];
      i++;
      while (i < lines.length && !/^ {0,3}```/.test(at(i))) {
        const l = at(i++);
        body.push(l.startsWith(indent) ? l.slice(indent.length) : l.trimStart());
      }
      i++; // closing fence (or end of input)
      blocks.push({ t: 'code', lang: fence[2] ?? '', v: body.join('\n') });
      continue;
    }

    const heading = /^(#{1,3})\s+(.*)$/.exec(line);
    if (heading) {
      blocks.push({ t: 'heading', level: (heading[1] ?? '#').length as 1 | 2 | 3, c: parseInline(heading[2] ?? '') });
      i++;
      continue;
    }

    if (line.startsWith('|') && isSeparatorRow(at(i + 1))) {
      const head = splitRow(line).map(parseInline);
      const rows: Inline[][][] = [];
      i += 2;
      while (i < lines.length && at(i).startsWith('|')) rows.push(splitRow(at(i++)).map(parseInline));
      blocks.push({ t: 'table', head, rows });
      continue;
    }

    if (line.startsWith('>')) {
      const inner: string[] = [];
      while (i < lines.length && at(i).startsWith('>')) inner.push(at(i++).replace(/^>\s?/, ''));
      blocks.push({ t: 'quote', c: parseMarkdown(inner.join('\n')) });
      continue;
    }

    const bullet = /^(\s*)(-|\d+\.)\s+/;
    const first = bullet.exec(line);
    if (first) {
      const ordered = first[2] !== '-';
      // Keeps numbering when a list resumes after a code block ("2." after "1.").
      const start = ordered ? Number.parseInt(first[2] ?? '1', 10) : 1;
      const items: string[] = [];
      while (i < lines.length && at(i).trim() !== '') {
        const m = bullet.exec(at(i));
        if (m) items.push(at(i).slice(m[0].length));
        else if (items.length > 0) items.push(`${items.pop() ?? ''} ${at(i).trim()}`); // wrapped item
        i++;
      }
      blocks.push({ t: 'list', ordered, start, items: items.map(parseInline) });
      continue;
    }

    const para: string[] = [];
    while (i < lines.length && at(i).trim() !== '' && !/^(#{1,3}\s| {0,3}```|>|\||(-|\d+\.)\s)/.test(at(i))) {
      para.push(at(i++).trim());
    }
    if (para.length === 0) {
      // A line no rule consumed (e.g. a lone "|"): keep it as text rather than loop forever.
      para.push(at(i++).trim());
    }
    blocks.push({ t: 'paragraph', c: parseInline(para.join(' ')) });
  }
  return blocks;
}
