import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Marked } from 'marked';
import { articles } from './catalog';

function escapeHtml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function getArticle(slug: string) {
  const entry = articles.find((a) => a.slug === slug);
  if (!entry) return null;
  const source = readFileSync(
    join(process.cwd(), 'content', 'articles', `${entry.slug}.md`),
    'utf8',
  );
  const headings: { id: string; title: string }[] = [];
  const used = new Map<string, number>();
  const renderer = new Marked({
    renderer: {
      html({ text }) {
        return escapeHtml(text);
      },
      heading({ tokens, depth, text }) {
        const base = text
          .toLowerCase()
          .replace(/[^a-z0-9\s-]/g, '')
          .trim()
          .replace(/\s+/g, '-');
        const count = used.get(base) ?? 0;
        used.set(base, count + 1);
        const id = count ? `${base}-${count}` : base;
        if (depth === 2) headings.push({ id, title: text });
        return `<h${depth} id="${id}">${this.parser.parseInline(tokens)}</h${depth}>`;
      },
    },
  });
  const html = renderer.parse(source, { async: false });
  return {
    ...entry,
    html,
    headings,
    minutes: Math.max(1, Math.ceil(source.split(/\s+/).length / 220)),
  };
}
