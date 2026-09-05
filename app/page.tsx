import { articles } from '@/lib/catalog';
import { path } from '@/lib/site';
export default function Home() {
  return (
    <main id="main" className="overview">
      <section className="intro">
        <p className="eyebrow">
          Business risk · Security architecture · Governance
        </p>
        <h1>Secret exposure.</h1>
        <p className="standfirst">
          Thinking through the risk.
          <br />
          Keeping the reasoning.
        </p>
        <p className="intro-copy">
          My notes on secret exposure and the decisions it raises. I keep the
          reasoning here so I can return to what matters and why.
        </p>
      </section>
      <section className="series" aria-labelledby="series-title">
        <div className="section-heading">
          <h2 id="series-title">My notes</h2>
          <p>The questions I want to come back to.</p>
        </div>
        <div className="article-grid">
          {articles.map((a) => (
            <a
              className="article-card"
              key={a.slug}
              href={path(`/articles/${a.slug}/`)}
            >
              <span className="eyebrow">{a.topic}</span>
              <h3>{a.title}</h3>
              <p>{a.description}</p>
              <span className="read-link">
                Read note <span aria-hidden="true">↗</span>
              </span>
            </a>
          ))}
        </div>
      </section>
      <section className="thesis">
        <h2>
          Scanning is a sensor.
          <br />
          Risk reduction takes more.
        </h2>
        <p>
          Finding a credential is the beginning. I also want to understand its
          authority, how to stop its use, and what needs to change so the same
          exposure does not keep happening.
        </p>
      </section>
    </main>
  );
}
