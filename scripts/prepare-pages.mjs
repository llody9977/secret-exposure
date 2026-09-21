import { cpSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const base = process.env.SITE_BASE_PATH ?? '/secret-exposure';
if (base && !/^\/[a-zA-Z0-9_-]+$/.test(base))
  throw new Error('Use an empty base path or one repository path segment');
const source = join('dist/client', base);
if (!existsSync(join(source, 'index.html')))
  throw new Error(`Missing export at ${source}`);
// GitHub Pages adds the repository URL prefix itself. Vinext exports under
// that prefix, so publish its contents at the artifact root without rewriting URLs.
rmSync('out', { recursive: true, force: true });
mkdirSync('out');
cpSync(source, 'out', { recursive: true });
if (existsSync('dist/client/404.html'))
  cpSync('dist/client/404.html', 'out/404.html');
writeFileSync('out/.nojekyll', '');
