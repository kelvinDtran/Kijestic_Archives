import type { NextConfig } from 'next';

const isDev = process.env.NODE_ENV === 'development';

// Content Security Policy — defense-in-depth against XSS
// Tighten these in production; 'unsafe-eval' is only needed for some WASM loaders in dev
const ContentSecurityPolicy = `
  default-src 'self';
  script-src 'self' ${isDev ? "'unsafe-eval' 'unsafe-inline'" : ""};
  style-src 'self' 'unsafe-inline';
  img-src 'self' blob: data:;
  font-src 'self';
  connect-src 'self';
  media-src 'none';
  object-src 'none';
  child-src 'none';
  frame-src 'none';
  frame-ancestors 'none';
  form-action 'self';
  base-uri 'self';
  worker-src 'self' blob:;
  upgrade-insecure-requests;
`
  .replace(/\s{2,}/g, ' ')
  .trim();

const securityHeaders = [
  // Strict CSP
  {
    key: 'Content-Security-Policy',
    value: ContentSecurityPolicy,
  },
  // Prevent clickjacking
  {
    key: 'X-Frame-Options',
    value: 'DENY',
  },
  // Prevent MIME sniffing
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff',
  },
  // Force HTTPS — 2 years with subdomain and preload in production
  {
    key: 'Strict-Transport-Security',
    value: isDev
      ? 'max-age=0'
      : 'max-age=63072000; includeSubDomains; preload',
  },
  // Control referrer information
  {
    key: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin',
  },
  // Restrict browser features
  {
    key: 'Permissions-Policy',
    value: [
      'camera=()',
      'microphone=()',
      'geolocation=()',
      'payment=()',
      'usb=()',
      'serial=()',
      // Allow clipboard-write for copy-to-clipboard feature
      'clipboard-write=(self)',
      // Allow publickey-credentials for WebAuthn
      'publickey-credentials-get=(self)',
      'publickey-credentials-create=(self)',
    ].join(', '),
  },
  // Prevent cross-origin information leaks
  {
    key: 'Cross-Origin-Embedder-Policy',
    value: 'require-corp',
  },
  {
    key: 'Cross-Origin-Opener-Policy',
    value: 'same-origin',
  },
  {
    key: 'Cross-Origin-Resource-Policy',
    value: 'same-origin',
  },
  // Disable DNS prefetching (privacy)
  {
    key: 'X-DNS-Prefetch-Control',
    value: 'off',
  },
];

const nextConfig: NextConfig = {
  // Apply security headers to all routes
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ];
  },

  // Disable powered-by header
  poweredByHeader: false,

  // Compress responses
  compress: true,

  // Strict mode for catching bugs early
  reactStrictMode: true,

  // Allow WASM for hash-wasm (Argon2id)
  webpack(config) {
    config.experiments = {
      ...config.experiments,
      asyncWebAssembly: true,
    };
    return config;
  },
};

export default nextConfig;
