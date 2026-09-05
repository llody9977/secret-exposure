import { path } from '@/lib/site';
export default function NotFound() {
  return (
    <main id="main" className="references">
      <p className="eyebrow">Page not found</p>
      <h1>That page is not here.</h1>
      <p>The article may have moved, or the address may be incorrect.</p>
      <a href={path('/')}>Return to the overview →</a>
    </main>
  );
}
