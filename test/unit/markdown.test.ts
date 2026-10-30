import { describe, expect, it } from 'vitest';
import { loadCurriculum } from '../../src/curriculum/catalog.js';
import { parseInline, parseMarkdown, safeHref, type Block, type Inline } from '../../web/src/markdown.js';

const text = (nodes: Inline[]): string =>
  nodes.map((n) => (n.t === 'text' || n.t === 'code' ? n.v : text(n.c))).join('');

/** Prose only: inline code legitimately contains `**`, `<jeton>`, etc. */
const prose = (nodes: Inline[]): string =>
  nodes.map((n) => (n.t === 'text' ? n.v : n.t === 'code' ? '' : prose(n.c))).join('');

function inlinesOf(blocks: Block[]): Inline[][] {
  return blocks.flatMap((b): Inline[][] => {
    switch (b.t) {
      case 'heading':
      case 'paragraph':
        return [b.c];
      case 'list':
        return b.items;
      case 'quote':
        return inlinesOf(b.c);
      case 'table':
        return [...b.head, ...b.rows.flat()];
      case 'code':
        return [];
    }
  });
}

describe('markdown parser (front-end, no HTML ever produced)', () => {
  it('parses the block subset used by lessons', () => {
    const blocks = parseMarkdown(
      [
        '# Title',
        '',
        'A **bold** and *em* line',
        'continued here.',
        '',
        '```bash',
        'curl -i http://localhost:3000',
        '```',
        '',
        '- one',
        '  wrapped',
        '- two',
        '',
        '1. first',
        '2. second',
        '',
        '> quoted **text**',
        '',
        '| A | B |',
        '|---|:--:|',
        '| `x` | y |',
      ].join('\n'),
    );
    expect(blocks.map((b) => b.t)).toEqual(['heading', 'paragraph', 'code', 'list', 'list', 'quote', 'table']);
    expect(blocks[1]).toEqual({
      t: 'paragraph',
      c: [{ t: 'text', v: 'A ' }, { t: 'strong', c: [{ t: 'text', v: 'bold' }] }, { t: 'text', v: ' and ' }, { t: 'em', c: [{ t: 'text', v: 'em' }] }, { t: 'text', v: ' line continued here.' }],
    });
    expect(blocks[2]).toEqual({ t: 'code', lang: 'bash', v: 'curl -i http://localhost:3000' });
    expect(blocks[3]).toMatchObject({ ordered: false, items: [[{ t: 'text', v: 'one wrapped' }], [{ t: 'text', v: 'two' }]] });
    expect(blocks[4]).toMatchObject({ ordered: true, start: 1 });
    expect(blocks[6]).toMatchObject({ t: 'table', head: [[{ t: 'text', v: 'A' }], [{ t: 'text', v: 'B' }]], rows: [[[{ t: 'code', v: 'x' }], [{ t: 'text', v: 'y' }]]] });
  });

  it('handles code fences indented inside a list, and resumed numbering', () => {
    const blocks = parseMarkdown(['1. **First** step:', '', '   ```ts', '   const x = 1;', '     nested();', '   ```', '', '2. Second step'].join('\n'));
    expect(blocks.map((b) => b.t)).toEqual(['list', 'code', 'list']);
    expect(blocks[1]).toEqual({ t: 'code', lang: 'ts', v: 'const x = 1;\n  nested();' });
    expect(blocks[2]).toMatchObject({ ordered: true, start: 2 });
  });

  it('keeps raw HTML as plain text', () => {
    const payload = '<img src=x onerror=alert(1)><script>alert(1)</script>';
    const [p] = parseMarkdown(payload);
    expect(p).toEqual({ t: 'paragraph', c: [{ t: 'text', v: payload }] });
    expect(parseMarkdown('```\n<script>alert(1)</script>\n```')[0]).toEqual({ t: 'code', lang: '', v: '<script>alert(1)</script>' });
  });

  it('only keeps https and in-app links; dangerous schemes degrade to text', () => {
    for (const href of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'data:text/html,<script>', 'http://evil.test', 'vbscript:x', '//evil.test', '/v1/admin/audit']) {
      expect(safeHref(href)).toBeNull();
      const nodes = parseInline(`[click](${href})`);
      expect(nodes.some((n) => n.t === 'link')).toBe(false);
      expect(nodes[0]).toEqual({ t: 'em', c: [{ t: 'text', v: 'click' }] });
    }
    expect(parseInline('[OWASP](https://owasp.org/x)')).toEqual([{ t: 'link', href: 'https://owasp.org/x', c: [{ t: 'text', v: 'OWASP' }] }]);
    expect(safeHref('#/lecon/idor-comprendre')).toBe('#/lecon/idor-comprendre');
  });

  it('terminates on unbalanced or pathological input', () => {
    expect(text(parseInline('**open `tick [x]('))).toBe('**open `tick [x](');
    const long = '*'.repeat(10_000) + '`'.repeat(10_000) + '['.repeat(10_000);
    const start = performance.now();
    parseMarkdown(`${long}\n|\n> \n- \n\`\`\``);
    expect(performance.now() - start).toBeLessThan(2000);
  });

  it('every shipped lesson only uses supported syntax', () => {
    for (const lesson of loadCurriculum().lessons.values()) {
      const blocks = parseMarkdown(lesson.body);
      // An empty inline code span means a malformed fence was read as backticks in prose.
      expect(JSON.stringify(blocks), `lesson ${lesson.id}`).not.toContain('{"t":"code","v":""}');
      for (const line of inlinesOf(blocks)) {
        // Leftover markers mean the author used syntax the renderer would show raw.
        expect(prose(line), `lesson ${lesson.id}`).not.toMatch(/\]\(|\*\*|^#|<\/?[a-z]|```/i);
      }
    }
  });
});
