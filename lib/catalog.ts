export const foundationArticles = [
  {
    slug: 'business-risk',
    topic: 'Business',
    title: 'Why secret exposure matters to the business',
    description:
      'The business consequence depends on what a credential permits and how safely that access can be stopped.',
  },
  {
    slug: 'action-plan',
    updated: '6 September 2026',
    topic: 'Action',
    title: 'Where to start and who needs to own it',
    description:
      'A defined service connects the purpose, scope, ownership, timing, and practical steps needed to reduce exposure.',
  },
  {
    slug: 'security-architecture',
    updated: '6 September 2026',
    topic: 'Architecture',
    title: 'Designing for the moment a credential escapes',
    description:
      'Storage, execution boundaries, permissions, and recovery determine what happens after a credential escapes.',
  },
  {
    slug: 'implementation',
    updated: '6 September 2026',
    topic: 'Implementation',
    title: 'Why good practices become difficult to implement',
    description:
      'Application behavior, supplier constraints, and delivery pressure determine whether good practices can be sustained.',
  },
  {
    slug: 'incident-response',
    updated: '6 September 2026',
    topic: 'Response',
    title: 'Responding when a secret is exposed',
    description:
      'Containment needs to stop usable access while investigation and recovery account for the affected service.',
  },
  {
    slug: 'governance',
    updated: '6 September 2026',
    topic: 'Governance',
    title: 'Giving GRC a clear view of credential risk',
    description:
      'Ownership, coverage, exceptions, and evidence make reporting useful for risk decisions.',
  },
  {
    slug: 'what-good-looks-like',
    updated: '6 September 2026',
    topic: 'Assurance',
    title: 'Recognizing good control through evidence',
    description:
      'Effective access boundaries and tested recovery provide stronger assurance than a clean alert queue.',
  },
  {
    slug: 'path-forward',
    updated: '6 September 2026',
    topic: 'Direction',
    title: 'Moving towards fewer persistent credentials',
    description:
      'A phased approach connects immediate containment to supported identity patterns and the retirement of old access.',
  },
] as const;

export const technicalArticles = [
  {
    slug: 'attacker-access-paths',
    updated: '6 September 2026',
    topic: 'Threats',
    title: 'How exposed credentials become usable access',
    description:
      'Exposure paths, attacker use, and target authority explain what detection must connect to.',
  },
  {
    slug: 'scanner-capabilities',
    updated: '6 September 2026',
    topic: 'Detection',
    title: 'What secret scanners detect and where coverage stops',
    description:
      'Detection methods, validation, and enforcement placement need separate evidence.',
  },
  {
    slug: 'choosing-a-scanner',
    updated: '6 September 2026',
    topic: 'Tool selection',
    title: 'Choosing a scanner against actual requirements',
    description:
      'Coverage, operating responsibility, and integration needs provide a practical basis for selection.',
  },
  {
    slug: 'pipeline-lifecycle',
    updated: '6 September 2026',
    topic: 'Integration',
    title: 'Connecting detection to a working response',
    description:
      'Intake records and approved workflows connect a finding to containment and application recovery.',
  },
  {
    slug: 'workload-identity-lab',
    updated: '6 September 2026',
    topic: 'Identity',
    title: 'Replacing persistent credentials with workload identity',
    description:
      'Legacy applications, dynamic credentials, and attested identities need different recovery paths.',
  },
] as const;

export const articles = [...foundationArticles, ...technicalArticles] as const;
