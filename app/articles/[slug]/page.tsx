import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { articles } from '@/lib/catalog';
import { getArticle } from '@/lib/articles';
import { path } from '@/lib/site';
export function generateStaticParams() {
  return articles.map((a) => ({ slug: a.slug }));
}
export const dynamicParams = false;
export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  const { slug } = await params;
  const a = articles.find((a) => a.slug === slug);
  return a
    ? {
        title: a.title,
        description: a.description,
        alternates: { canonical: path(`/articles/${slug}/`) },
        openGraph: {
          title: a.title,
          description: a.description,
          type: 'article',
        },
      }
    : {};
}
export default async function Article({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const a = getArticle(slug);
  if (!a) notFound();
  const index = articles.findIndex((item) => item.slug === slug);
  const next = articles[index + 1];
  return (
    <main id="main" className="article-shell">
      <header className="article-heading">
        <a className="back-link" href={path('/')}>
          ← Overview
        </a>
        <p className="eyebrow">{a.topic}</p>
        <h1>{a.title}</h1>
        <p className="dek">{a.description}</p>
        <p className="meta">{a.minutes} min read · Updated 5 September 2026</p>
      </header>
      <div className="article-layout">
        <aside className="contents">
          <details open>
            <summary>Contents</summary>
            <nav aria-label="Article contents">
              <ol>
                {a.headings.map((h) => (
                  <li key={h.id}>
                    <a href={`#${h.id}`}>{h.title}</a>
                  </li>
                ))}
              </ol>
            </nav>
          </details>
        </aside>
        <div>
          <article
            className="prose"
            dangerouslySetInnerHTML={{ __html: a.html }}
          />
          <a
            className="next-article"
            href={next ? path(`/articles/${next.slug}/`) : path('/')}
          >
            <span>{next ? 'Next' : 'Overview'}</span>
            <strong>{next ? next.title : 'Return to my notes'} →</strong>
          </a>
        </div>
      </div>
    </main>
  );
}
