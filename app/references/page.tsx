import type { Metadata } from 'next';
import { path } from '@/lib/site';
export const metadata: Metadata = {
  title: 'References and how I keep these notes',
  description:
    'The sources and evidence boundaries I want to retain when I revisit my notes on secret exposure.',
  alternates: { canonical: path('/references/') },
};
const sources = [
  [
    'OWASP Secrets Management Cheat Sheet',
    'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
    'I use the lifecycle view to keep finding a secret connected to its creation, use, and retirement.',
  ],
  [
    'GitHub secret scanning detection scope',
    'https://docs.github.com/en/code-security/reference/secret-security/secret-scanning-scope',
    'I refer to the documented coverage when distinguishing push protection from background detection.',
  ],
  [
    'GitHub OpenID Connect',
    'https://docs.github.com/en/actions/concepts/security/openid-connect',
    'This explains the exchange of workflow identity for temporary provider access and the trust conditions behind it.',
  ],
  [
    'AWS security best practices in IAM',
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
    'I refer to this guidance for temporary workload credentials and permissions that fit the intended task.',
  ],
  [
    'Kubernetes good practices for Secrets',
    'https://kubernetes.io/docs/concepts/security/secrets-good-practices/',
    'This helps me separate storage, retrieval, and runtime protection. Base64 encoding does not provide confidentiality.',
  ],
  [
    'GitHub guidance on remediating a leaked secret',
    'https://docs.github.com/en/code-security/tutorials/remediate-leaked-secrets/remediating-a-leaked-secret',
    'I use this when thinking through replacement and revocation where availability also matters.',
  ],
  [
    'GitHub guidance on removing sensitive data',
    'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository',
    'I want to retain the priority of revocation and the limitations of repository history cleanup.',
  ],
  [
    'GitHub advisory for CVE-2025-30066',
    'https://github.com/advisories/GHSA-mrrh-fwg8-r2c3',
    'The March 2025 compromise provides an example of secrets moving from runtime memory into logs. I do not equate use of the action with confirmed credential loss.',
  ],
  [
    'CircleCI January 2023 incident report',
    'https://circleci.com/blog/jan-4-2023-incident-report/',
    'The provider report helps me follow the response into credentials and connected systems.',
  ],
  [
    'NIST Cybersecurity Framework 2.0',
    'https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20',
    'I use the framework to organise risk outcomes. My capability profile and planning sequence are proposed approaches rather than requirements prescribed by NIST.',
  ],
];
export default function References() {
  return (
    <main id="main" className="references">
      <p className="eyebrow">Sources I return to</p>
      <h1>References.</h1>
      <div className="reference-grid">
        <div className="prose">
          <h2 id="editorial-approach">How I keep these notes</h2>
          <p>
            I keep the reasoning here so I can return to it later. I want to
            remember what matters, how I reached a conclusion, and what I would
            check before acting on it.
          </p>
          <p>
            I distinguish my interpretation from the facts supported by a
            source. An imagined situation helps me work through an idea. It is
            not a claim that I personally handled that incident.
          </p>
          <p>
            I keep uncertainty beside the conclusion it affects. A documented
            failure tells me how something happened in that situation. It does
            not establish how often the same thing happens elsewhere.
          </p>
          <p>
            My capability profile and 90 day sequence help organise my thinking.
            They are not universal standards or regulatory requirements.
          </p>
          <h2>What I need to recheck</h2>
          <p>
            The sources were checked on 5 September 2026. Product behaviour can
            change, so I would return to the current documentation before
            implementation.
          </p>
          <p>
            I would also check the requirements that apply to the particular
            entity and service before making a regulatory claim. Detailed
            cryptographic recovery and supplier limitations need their own
            assessment.
          </p>
          <p>
            I keep corrections and proposed changes in the{' '}
            <a href="https://github.com/llody9977/secret_exposure/issues">
              repository
            </a>
            , together with supporting evidence. Live credentials do not belong
            in those records.
          </p>
        </div>
        <ol className="reference-list">
          {sources.map(([title, url, note]) => (
            <li key={url}>
              <a href={url}>{title} ↗</a>
              <p>{note}</p>
            </li>
          ))}
        </ol>
      </div>
    </main>
  );
}
