export const articles = [
  {
    slug: 'business-risk',
    topic: 'Business',
    title: 'Why secret exposure matters to the business',
    description:
      'The business consequence depends on what a credential permits and how safely that access can be stopped.',
  },
  {
    slug: 'action-plan',
    topic: 'Action',
    title: 'Where I would start and who needs to own it',
    description:
      'I use 5W1H to work through one service before trying to solve the whole estate.',
  },
  {
    slug: 'security-architecture',
    topic: 'Architecture',
    title: 'How I think about designing for exposure',
    description:
      'I want the design to explain what happens after a credential leaves its intended boundary.',
  },
  {
    slug: 'implementation',
    topic: 'Implementation',
    title: 'Why good practices become difficult to implement',
    description:
      'I look at the dependencies that make straightforward advice difficult to put into practice.',
  },
  {
    slug: 'incident-response',
    topic: 'Response',
    title: 'What I would focus on when a secret is exposed',
    description:
      'My first concern is whether the access still works and what it would take to stop it.',
  },
  {
    slug: 'governance',
    topic: 'Governance',
    title: 'What I would want GRC to see',
    description:
      'I want reporting that makes ownership, uncertainty, and the next decision clear.',
  },
  {
    slug: 'what-good-looks-like',
    topic: 'Assurance',
    title: 'How I would recognise good control',
    description:
      'I look for capabilities that can be demonstrated and keep the gaps visible.',
  },
  {
    slug: 'path-forward',
    topic: 'Direction',
    title: 'The direction I would take from here',
    description:
      'I want less persistent authority to manage and a practical way to decide what to change next.',
  },
] as const;
