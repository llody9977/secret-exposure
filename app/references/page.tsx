import type { Metadata } from 'next';
import { path } from '@/lib/site';
export const metadata: Metadata = {
  title: 'References and editorial approach',
  description:
    'Primary sources, evidence boundaries, and editorial principles behind the Secret Exposure articles.',
  alternates: { canonical: path('/references/') },
};
const sources = [
  [
    'OWASP — Secrets Management Cheat Sheet',
    'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
    'Lifecycle guidance. Used for the distinction between finding a secret and managing its creation, use, and retirement.',
  ],
  [
    'GitHub — Secret scanning detection scope',
    'https://docs.github.com/en/code-security/reference/secret-security/secret-scanning-scope',
    'Product coverage and limitations. Supports the distinction between push protection and background detection.',
  ],
  [
    'GitHub — OpenID Connect',
    'https://docs.github.com/en/actions/concepts/security/openid-connect',
    'How workflow identity can be exchanged for temporary provider access, with explicit trust conditions.',
  ],
  [
    'AWS — Security best practices in IAM',
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
    'Provider guidance on temporary workload credentials and least-privilege access.',
  ],
  [
    'Kubernetes — Good practices for Secrets',
    'https://kubernetes.io/docs/concepts/security/secrets-good-practices/',
    'Storage, access, and runtime boundaries. Base64 is encoding, not encryption.',
  ],
  [
    'GitHub — Remediating a leaked secret',
    'https://docs.github.com/en/code-security/tutorials/remediate-leaked-secrets/remediating-a-leaked-secret',
    'Operational sequencing for replacement and revocation when availability matters.',
  ],
  [
    'GitHub — Removing sensitive data from a repository',
    'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository',
    'Revocation before cleanup, and the limits and disruption of repository history removal.',
  ],
  [
    'GitHub advisory — CVE-2025-30066',
    'https://github.com/advisories/GHSA-mrrh-fwg8-r2c3',
    'March 2025 workflow compromise. Used to illustrate runtime-to-log exposure, without equating adoption with confirmed credential loss.',
  ],
  [
    'CircleCI — January 2023 incident report',
    'https://circleci.com/blog/jan-4-2023-incident-report/',
    'First-party historical incident evidence showing why response extends to credentials and connected systems.',
  ],
  [
    'NIST — Cybersecurity Framework 2.0',
    'https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20',
    'An outcome-oriented framework for risk communication. The series does not claim NIST prescribes its capability profile or roadmap.',
  ],
];
export default function References() {
  return (
    <main id="main" className="references">
      <p className="eyebrow">Evidence and method</p>
      <h1>References.</h1>
      <div className="reference-grid">
        <div className="prose">
          <h2 id="editorial-approach">Editorial approach</h2>
          <p>
            Lead with the decision and its business consequence. Explain
            technical mechanisms where they change that decision. Keep the
            writing direct, practical, and free of unsupported claims.
          </p>
          <p>
            Primary-source facts are linked where they appear. Proposed
            operating practices, the capability profile, and the 90-day sequence
            are editorial recommendations. They are not universal standards or
            regulatory requirements.
          </p>
          <p>
            Examples are labelled as illustrative. A documented incident
            establishes a particular failure path; it does not establish how
            often that path occurs or the loss every organisation should expect.
          </p>
          <p>
            Caveats that change a claim stay beside it. Source context and
            method belong here. Sources were checked on 5 September 2026;
            product behaviour should be rechecked before implementation.
          </p>
          <h2>Scope</h2>
          <p>
            The series covers credentials and key material across development,
            delivery, runtime, and operational workflows. Detailed cryptographic
            key recovery, product comparisons, and entity-specific regulatory
            mappings require separate treatment.
          </p>
          <p>
            Corrections and article proposals can be raised in the{' '}
            <a href="https://github.com/llody9977/secret_exposure/issues">
              repository
            </a>
            . Include the claim, supporting evidence, and the change proposed.
            Never include a live credential.
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
