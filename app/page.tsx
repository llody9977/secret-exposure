import { foundationArticles, technicalArticles } from '@/lib/catalog';
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
          Understanding the risk.
          <br />
          Making the response work.
        </p>
        <p className="intro-copy">
          An exposed credential can connect a small technical finding to a
          significant business consequence. The response depends on its
          authority and the service behind it.
        </p>
      </section>
      {[
        {
          id: 'foundations',
          title: 'Foundations',
          articles: foundationArticles,
        },
        {
          id: 'technical-practice',
          title: 'Technical practice',
          articles: technicalArticles,
        },
      ].map((series) => (
        <section key={series.id} className="series" aria-labelledby={series.id}>
          <div className="section-heading">
            <h2 id={series.id}>{series.title}</h2>
          </div>
          <div className="article-grid">
            {series.articles.map((a) => (
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
      ))}
      <section className="thesis">
        <h2>
          Scanning is a sensor.
          <br />
          Risk reduction takes more.
        </h2>
        <p>
          Finding a credential is the beginning. Its authority needs to be
          understood, exposed access needs to be stopped, and the cause needs to
          be addressed so the same exposure does not keep happening.
        </p>
      </section>
      <section className="thesis">
        <h2>A laboratory for the complete lifecycle</h2>
        <p>
          The local POC connects Vault, service records, incident handling, and
          three application patterns. It records scenario evidence for the
          lifecycle, but it is an integration demonstration rather than a
          scanner benchmark or a production-readiness claim.{' '}
          <a href="https://github.com/llody9977/secret_exposure/blob/main/poc/README.md">
            Read the laboratory guide
          </a>
          .
        </p>
      </section>
    </main>
  );
}
