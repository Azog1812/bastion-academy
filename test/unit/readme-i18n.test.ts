import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The repository's front page is a language picker; the explanations live in
 * docs/i18n/README.<lang>.md, with English as the reference. Translations drift silently:
 * a section added in English and forgotten elsewhere, a link that breaks after a file is
 * renamed. This checks what can be checked mechanically: every link resolves, every
 * language links to every other, and each translation has the same links, tables and
 * code blocks as the English page.
 */

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const LANGS = ['en', 'fr', 'es', 'de', 'pt-BR', 'zh-CN'] as const;
const pagePath = (lang: string) => resolve(ROOT, 'docs/i18n', `README.${lang}.md`);
const read = (path: string) => readFileSync(path, 'utf8');

/** Markdown link targets `](target)`, outside fenced code blocks. */
function links(markdown: string): string[] {
  const prose = markdown.replace(/^```[\s\S]*?^```/gm, '');
  return [...prose.matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1] ?? '');
}

/** GitHub's heading slug: lower case, punctuation dropped, spaces to dashes. */
function slug(heading: string): string {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s-]/gu, '')
    .replace(/\s/g, '-');
}

function hasAnchor(markdown: string, anchor: string): boolean {
  if (markdown.includes(`id="${anchor}"`)) return true;
  return [...markdown.matchAll(/^#{1,6}\s+(.+)$/gm)].some((m) => slug(m[1] ?? '') === anchor);
}

/** Every relative link of `file` that does not resolve to a file (and anchor, if any). */
function brokenLinks(file: string): string[] {
  const markdown = read(file);
  return links(markdown).filter((target) => {
    if (/^https?:\/\//.test(target)) return false;
    const [path = '', anchor] = target.split('#');
    const resolved = path === '' ? file : resolve(dirname(file), path);
    if (!existsSync(resolved)) return true;
    if (anchor === undefined || !resolved.endsWith('.md')) return false;
    return !hasAnchor(path === '' ? markdown : read(resolved), anchor);
  });
}

/** The shape a translation must keep: link targets, table rows, code blocks. */
function shape(markdown: string) {
  return {
    links: links(markdown).filter((l) => !l.startsWith('README.')),
    tableRows: markdown.split('\n').filter((line) => line.startsWith('|')).length,
    codeBlocks: (markdown.match(/^```/gm) ?? []).length,
  };
}

describe('README language picker', () => {
  const home = read(resolve(ROOT, 'README.md'));

  it('offers every language, and only those', () => {
    const offered = links(home)
      .map((l) => /^docs\/i18n\/README\.(.+)\.md$/.exec(l)?.[1])
      .filter((l) => l !== undefined);
    expect(offered.sort()).toEqual([...LANGS].sort());
  });

  it('has working links, including the credits anchor the pages point to', () => {
    expect(brokenLinks(resolve(ROOT, 'README.md'))).toEqual([]);
    expect(hasAnchor(home, 'credits')).toBe(true);
  });
});

describe.each(LANGS)('docs/i18n/README.%s.md', (lang) => {
  const markdown = read(pagePath(lang));

  it('has no broken relative link or anchor', () => {
    expect(brokenLinks(pagePath(lang))).toEqual([]);
  });

  it('links to every other language and back to the picker', () => {
    const targets = links(markdown);
    for (const other of LANGS.filter((l) => l !== lang)) expect(targets).toContain(`README.${other}.md`);
    expect(targets).toContain('../../README.md');
  });

  it('keeps the shape of the English reference', () => {
    expect(shape(markdown)).toEqual(shape(read(pagePath('en'))));
  });
});
