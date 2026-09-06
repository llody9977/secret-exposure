# Secret Exposure

A personal journal of reasoning about secret exposure, kept for reference and recap. White background, blue and teal accents, and a fluid responsive layout.

**Read:** https://llody9977.github.io/secret_exposure/

## Articles

- [Why secret exposure matters to the business](content/articles/business-risk.md)
- [Where to start and who needs to own it](content/articles/action-plan.md)
- [How I think about designing for exposure](content/articles/security-architecture.md)
- [Why good practices become difficult to implement](content/articles/implementation.md)
- [What I would focus on when a secret is exposed](content/articles/incident-response.md)
- [What I would want GRC to see](content/articles/governance.md)
- [How I would recognise good control](content/articles/what-good-looks-like.md)
- [The direction I would take from here](content/articles/path-forward.md)

## Write and publish

1. Edit an article in `content/articles/`. These Markdown files are the single source for the published article bodies.
2. For a new article, add a Markdown file and its slug, title, topic, and description in `lib/catalog.ts`. Catalog order sets the reading sequence. Update this index.
3. Follow [EDITORIAL.md](EDITORIAL.md). Use `##` headings for the generated contents navigation; the page supplies the title.
4. Run `npm ci`, then `npm run check` on Node 22.13 or newer. Run `npm run dev` for a local preview at the URL printed by the server.
5. Push to `main`. The GitHub Actions workflow checks and publishes the static output to GitHub Pages. Pull requests build and validate without deployment.

Repository Pages settings must use **GitHub Actions**. The workflow deploys only a successful build, with separate build and deployment permissions. It does not require stored cloud credentials.

## Implementation

React and Vinext static export from the Sites starter. The build normalises the repository-prefixed export into `out/` for Pages. GitHub Pages serves HTML and assets; there is no production application server, database, tracking, or user-submitted content. Article HTML is rendered only from trusted, repository-reviewed Markdown. Do not use this renderer for untrusted input without sanitisation.

`SITE_BASE_PATH` defaults to `/secret_exposure`. Changing the repository name or using a custom domain also requires updating the origin/repository links in `lib/site.ts`, the layout, references, README, and workflow base path. Run the full check after such a change.

The layout uses fractional grids, viewport-aware spacing and type, and mobile breakpoints. Article contents remain visible on desktop and can collapse on mobile. Reduced-motion and print styles are included. No fixed-width page wrapper is used.

`npm run check` type-checks the source, creates the static export, and verifies article routes, titles, heading anchors, internal links, and referenced local assets. It checks generated HTML, not browser rendering. No claim of visual browser testing is made.

## Contributions

Open an issue or pull request with a specific proposed correction and a primary source where applicable. Do not submit actual secrets, internal incident data, or confidential documents. Dependency updates should be reviewed and validated before publishing.
