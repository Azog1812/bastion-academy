import type { Block, Inline } from './markdown.js';

type Child = Node | string | null | undefined | false;
type Attrs = Record<string, string | boolean | undefined>;

/**
 * The only way the front-end builds UI: createElement + text nodes.
 * Strings always become text, never markup. Event handlers are passed as
 * functions, never as attribute strings (`on*` attributes are refused).
 */
export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (name.toLowerCase().startsWith('on')) throw new Error(`refusing inline handler attribute "${name}"`);
    el.setAttribute(name, value === true ? '' : value);
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    el.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return el;
}

function inline(nodes: Inline[]): Node[] {
  return nodes.map((n): Node => {
    switch (n.t) {
      case 'text':
        return document.createTextNode(n.v);
      case 'code':
        return h('code', {}, n.v);
      case 'strong':
        return h('strong', {}, ...inline(n.c));
      case 'em':
        return h('em', {}, ...inline(n.c));
      case 'link':
        // href was filtered by safeHref(); external links cannot reach back into this page.
        return n.href.startsWith('#/')
          ? h('a', { href: n.href }, ...inline(n.c))
          : h('a', { href: n.href, target: '_blank', rel: 'noopener noreferrer' }, ...inline(n.c));
    }
  });
}

export function renderBlocks(blocks: Block[]): Node[] {
  return blocks.map((b): Node => {
    switch (b.t) {
      case 'heading':
        // Lesson headings start at h2: the page title is the only h1.
        return h(b.level === 1 ? 'h2' : b.level === 2 ? 'h3' : 'h4', {}, ...inline(b.c));
      case 'paragraph':
        return h('p', {}, ...inline(b.c));
      case 'code':
        return h('pre', {}, h('code', b.lang ? { 'data-lang': b.lang } : {}, b.v));
      case 'list':
        return h(
          b.ordered ? 'ol' : 'ul',
          b.ordered && b.start !== 1 ? { start: String(b.start) } : {},
          ...b.items.map((item) => h('li', {}, ...inline(item))),
        );
      case 'quote':
        return h('blockquote', {}, ...renderBlocks(b.c));
      case 'table':
        return h(
          'div',
          { class: 'table-wrap' },
          h(
            'table',
            {},
            h('thead', {}, h('tr', {}, ...b.head.map((c) => h('th', {}, ...inline(c))))),
            h('tbody', {}, ...b.rows.map((r) => h('tr', {}, ...r.map((c) => h('td', {}, ...inline(c)))))),
          ),
        );
    }
  });
}
