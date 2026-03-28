import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'AegisVault',
  description: 'Zero-knowledge personal secret vault',
  robots: {
    // Never index vault pages — secrets should never appear in search engines
    index:  false,
    follow: false,
    nocache: true,
    googleBot: { index: false, follow: false },
  },
  // Prevent caching of any vault pages
  other: {
    'Cache-Control': 'no-store, no-cache, must-revalidate',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        {/* Prevent search engine caching of any vault content */}
        <meta name="robots" content="noindex, nofollow, noarchive, nosnippet" />
        {/* Prevent iOS from detecting phone numbers (could reveal secrets) */}
        <meta name="format-detection" content="telephone=no, date=no, email=no, address=no" />
        {/* Prevent app from being added to iOS home screen (security) */}
        <meta name="mobile-web-app-capable" content="no" />
      </head>
      <body className="min-h-screen bg-aegis-bg text-aegis-text">
        {children}
      </body>
    </html>
  );
}
