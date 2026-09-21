import type { Metadata } from 'next';
import { path, origin } from '@/lib/site';
import './globals.css';
export const metadata: Metadata = {
  metadataBase: new URL(origin),
  title: {
    default: 'Secret Exposure | Business, architecture and governance',
    template: '%s | Secret Exposure',
  },
  description:
    'Secret exposure and its implications for business risk, security architecture, response, and governance.',
  icons: { icon: path('/favicon.svg') },
};
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <a className="skip-link" href="#main">
          Skip to content
        </a>
        <header className="site-header">
          <a className="wordmark" href={path('/')}>
            Secret Exposure
            <span className="brand-dot" aria-hidden="true">
              .
            </span>
          </a>
          <nav aria-label="Main navigation">
            <a href={path('/')}>Overview</a>
            <a href={path('/references/')}>References</a>
            <a href="https://github.com/llody9977/secret-exposure">
              GitHub <span aria-hidden="true">↗</span>
            </a>
          </nav>
        </header>
        {children}
        <footer className="site-footer">
          <span>Secret Exposure</span>

          <a href={path('/references/#editorial-approach')}>
            Editorial approach
          </a>
        </footer>
      </body>
    </html>
  );
}
