import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import assert from 'node:assert/strict';
const root = 'out';
const base = process.env.SITE_BASE_PATH ?? '/secret_exposure';
const walk = (dir) =>
  readdirSync(dir).flatMap((f) =>
    statSync(join(dir, f)).isDirectory() ? walk(join(dir, f)) : [join(dir, f)],
  );
assert(existsSync(join(root, 'index.html')), 'Static index is missing');
const files = walk(root).filter((f) => f.endsWith('.html'));
const articles = readdirSync('content/articles').filter((f) =>
  f.endsWith('.md'),
);
for (const file of articles) {
  const slug = file.slice(0, -3);
  const output = join(root, 'articles', slug, 'index.html');
  assert(existsSync(output), `Missing exported article ${slug}`);
  const html = readFileSync(output, 'utf8');
  assert.equal(
    (html.match(/<h1\b/g) || []).length,
    1,
    `Expected one article title: ${slug}`,
  );
  assert(
    (html.match(/<h2\b/g) || []).length >= 4,
    `Article body incomplete: ${slug}`,
  );
  assert(html.includes('In this article'), `Missing contents: ${slug}`);
  const title = html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/)?.[1];
  assert(
    title && html.includes(`<title>${title}`),
    `Metadata title differs: ${slug}`,
  );
}
let checked = 0;
for (const file of files) {
  const html = readFileSync(file, 'utf8');
  assert(
    !html.includes('Your site is taking shape'),
    `Starter content: ${file}`,
  );
  for (const match of html.matchAll(/(?:href|src)="([^"<>]+)"/g)) {
    const url = match[1].replaceAll('&amp;', '&');
    if (/^(https?:|data:|mailto:|javascript:|\/\/)/.test(url)) continue;
    const [pathname, hash] = url.split('#');
    let target = file;
    if (pathname) {
      const clean = pathname.split('?')[0];
      assert(
        clean.startsWith(base + '/'),
        `Link outside base path: ${url} in ${relative(root, file)}`,
      );
      target = join(root, decodeURIComponent(clean.slice(base.length)));
      if (existsSync(target) && statSync(target).isDirectory())
        target = join(target, 'index.html');
      assert(
        existsSync(target),
        `Missing local target: ${url} in ${relative(root, file)}`,
      );
    }
    if (hash && target.endsWith('.html'))
      assert(
        readFileSync(target, 'utf8').includes(`id="${hash}"`),
        `Missing anchor ${url}`,
      );
    checked++;
  }
}
console.log(
  `Verified ${articles.length} articles, ${files.length} HTML pages, and ${checked} internal links/assets.`,
);
