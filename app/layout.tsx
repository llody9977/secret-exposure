import type { Metadata } from 'next';
import { path, origin } from '@/lib/site';
import './globals.css';
export const metadata: Metadata = {
  metadataBase: new URL(origin),
  title: {
    default: 'Secret Exposure | Notes and reflections',
    template: '%s | Secret Exposure',
  },
  description:
    'Personal notes on secret exposure, business risk, security architecture, response, and governance.',
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
            <a href="https://github.com/llody9977/secret_exposure">
              GitHub <span aria-hidden="true">↗</span>
            </a>
          </nav>
        </header>
        {children}
        <footer className="site-footer">
          <span>Secret Exposure</span>
          <p>Thoughts to return to.</p>
          <a href={path('/references/#editorial-approach')}>
            How I keep these notes
          </a>
        </footer>
      </body>
    </html>
  );
}
