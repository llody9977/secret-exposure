export const articles = [
  {
    slug: 'business-risk',
    topic: 'Business',
    title: 'Why secret exposure is a business problem',
    description:
      'Connect a leaked credential to operational disruption, customer harm, and decisions leaders can make.',
  },
  {
    slug: 'action-plan',
    topic: 'Action',
    title: 'What to do, who owns it, and where to start',
    description:
      'A practical 5W1H plan that turns concern into accountable work.',
  },
  {
    slug: 'security-architecture',
    topic: 'Architecture',
    title: 'Design for the moment a credential escapes',
    description:
      'Understand trust boundaries, runtime access, and the failure modes a vault cannot solve.',
  },
  {
    slug: 'implementation',
    topic: 'Implementation',
    title: 'Make good practices work in real systems',
    description:
      'Handle legacy applications, noisy scans, fragile rotation, and delivery pressure.',
  },
  {
    slug: 'incident-response',
    topic: 'Response',
    title: 'An exposed secret needs an access decision',
    description:
      'Contain access, recover safely, and investigate beyond the original alert.',
  },
  {
    slug: 'governance',
    topic: 'Governance',
    title: 'Give GRC visibility into risk, not just activity',
    description:
      'Govern ownership, exceptions, coverage, and evidence that controls actually work.',
  },
  {
    slug: 'what-good-looks-like',
    topic: 'Assurance',
    title: 'What good looks like—and how to prove it',
    description:
      'Assess capabilities separately and test the outcomes that matter.',
  },
  {
    slug: 'path-forward',
    topic: 'Direction',
    title: 'Move towards fewer persistent secrets',
    description:
      'A phased roadmap to bounded access, workload identity, and durable improvement.',
  },
] as const;
