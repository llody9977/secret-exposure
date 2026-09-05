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
          Understand the risk.
          <br />
          Design for less of it.
        </p>
        <p className="intro-copy">
          Practical articles on the credentials that connect your business: why
          exposure matters, what to change, and how to know your controls work.
        </p>
      </section>
      <section className="series" aria-labelledby="series-title">
        <div className="section-heading">
          <h2 id="series-title">The articles</h2>
          <p>Read in sequence, or start with the decision in front of you.</p>
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
                Read article <span aria-hidden="true">↗</span>
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
          Prevent avoidable exposure. Limit what a credential can do. Detect
          what escapes. Revoke access, investigate its use, and remove the
          conditions that let the same failure happen again.
        </p>
      </section>
    </main>
  );
}
