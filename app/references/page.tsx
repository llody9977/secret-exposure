import type { Metadata } from 'next';
import { path } from '@/lib/site';
export const metadata: Metadata = {
  title: 'References and evidence',
  description:
    'Primary sources and evidence boundaries for secret exposure guidance.',
  alternates: { canonical: path('/references/') },
};
const sources = [
  [
    'OWASP Secrets Management Cheat Sheet',
    'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
    'Secret management spans creation, use, and retirement as well as discovery.',
  ],
  [
    'GitHub secret scanning detection scope',
    'https://docs.github.com/en/code-security/reference/secret-security/secret-scanning-scope',
    'Documented coverage distinguishes push protection from background detection.',
  ],
  [
    'GitHub OpenID Connect',
    'https://docs.github.com/en/actions/concepts/security/openid-connect',
    'This explains the exchange of workflow identity for temporary provider access and the trust conditions behind it.',
  ],
  [
    'AWS security best practices in IAM',
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
    'Provider guidance covers temporary workload credentials and permissions appropriate to the task.',
  ],
  [
    'Kubernetes good practices for Secrets',
    'https://kubernetes.io/docs/concepts/security/secrets-good-practices/',
    'Storage, retrieval, and runtime protection have distinct boundaries. Base64 encoding does not provide confidentiality.',
  ],
  [
    'GitHub guidance on remediating a leaked secret',
    'https://docs.github.com/en/code-security/tutorials/remediate-leaked-secrets/remediating-a-leaked-secret',
    'Replacement and revocation need sequencing that accounts for both exposure and availability.',
  ],
  [
    'GitHub guidance on removing sensitive data',
    'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository',
    'Revocation takes priority over cleanup. Removing repository history also has operational and coverage limits.',
  ],
  [
    'GitHub advisory for CVE-2025-30066',
    'https://github.com/advisories/GHSA-mrrh-fwg8-r2c3',
    'The March 2025 compromise exposed secrets through workflow logs. Use of the action does not establish confirmed credential loss.',
  ],
  [
    'CircleCI January 2023 incident report',
    'https://circleci.com/blog/jan-4-2023-incident-report/',
    'The provider report documents response extending to credentials and connected systems.',
  ],
  [
    'NIST Cybersecurity Framework 2.0',
    'https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20',
    'The framework organizes risk outcomes. It does not prescribe the capability profile or planning sequence used here.',
  ],
];
export default function References() {
  return (
    <main id="main" className="references">
      <p className="eyebrow">Primary sources</p>
      <h1>References.</h1>
      <div className="reference-grid">
        <div className="prose">
          <h2 id="editorial-approach">Evidence and interpretation</h2>
          <p>
            Technical claims link to their supporting sources. Hypothetical
            examples and proposed operating approaches remain distinct from
            documented incidents and external requirements.
          </p>
          <p>
            An incident establishes a particular failure path. It does not
            establish how often that path occurs elsewhere or the loss every
            organization should expect. Limitations that affect a conclusion
            remain beside it.
          </p>
          <p>
            The capability profile and 90 day planning sequence are proposed
            aids for assessment and delivery. They are not universal maturity
            standards or regulatory requirements.
          </p>
          <h2>Review before implementation</h2>
          <p>
            The sources were checked on 21 September 2026. Product behavior can
            change, so implementation needs to be checked against current
            documentation.
          </p>
          <p>
            Regulatory claims need an assessment of the requirements applicable
            to the particular entity and service. Detailed cryptographic
            recovery and supplier limitations also need their own assessment.
          </p>
          <p>
            Corrections and proposed changes can be raised in the{' '}
            <a href="https://github.com/llody9977/secret-exposure/issues">
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
