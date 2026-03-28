/**
 * AegisVault — Next.js Middleware
 *
 * Runs on every request before the page/API handler.
 * Responsibilities:
 *   1. Protect vault routes — redirect unauthenticated users to /login
 *   2. Redirect authenticated users away from auth pages
 *   3. Add security headers (backup, primary headers are in next.config.ts)
 *
 * IMPORTANT: This middleware only checks the access token cookie.
 * The vault remains "locked" (no master key) even after authentication.
 * The vault lock state is managed entirely client-side.
 */

import { NextRequest, NextResponse } from 'next/server';
import { jwtVerify } from 'jose';

const ACCESS_SECRET = new TextEncoder().encode(
  process.env.JWT_ACCESS_SECRET ?? 'INSECURE_DEV_SECRET_CHANGE_IN_PRODUCTION',
);

// Routes that require authentication
const PROTECTED_PREFIXES = ['/dashboard', '/vault', '/settings', '/sessions', '/audit'];

// Routes only accessible when NOT authenticated
const AUTH_ONLY_PATHS = ['/login', '/register', '/onboarding'];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // ── Check auth status ────────────────────────────────────────────────────────
  const accessToken = request.cookies.get('aegis_access')?.value;
  let isAuthenticated = false;

  if (accessToken) {
    try {
      await jwtVerify(accessToken, ACCESS_SECRET);
      isAuthenticated = true;
    } catch {
      // Token invalid or expired — treat as unauthenticated
      isAuthenticated = false;
    }
  }

  // ── Route protection ──────────────────────────────────────────────────────────

  // Redirect unauthenticated users from protected routes to login
  if (PROTECTED_PREFIXES.some((p) => pathname.startsWith(p))) {
    if (!isAuthenticated) {
      const loginUrl = new URL('/login', request.url);
      loginUrl.searchParams.set('from', pathname);
      return NextResponse.redirect(loginUrl);
    }
  }

  // Redirect authenticated users from auth-only pages to dashboard
  if (AUTH_ONLY_PATHS.some((p) => pathname === p)) {
    if (isAuthenticated) {
      return NextResponse.redirect(new URL('/dashboard', request.url));
    }
  }

  // ── Security headers (belt-and-suspenders alongside next.config.ts) ───────────
  const response = NextResponse.next();

  // Cache control for vault pages — never cache authenticated content
  if (PROTECTED_PREFIXES.some((p) => pathname.startsWith(p))) {
    response.headers.set(
      'Cache-Control',
      'no-store, no-cache, must-revalidate, proxy-revalidate',
    );
    response.headers.set('Pragma', 'no-cache');
    response.headers.set('Expires', '0');
  }

  return response;
}

export const config = {
  // Run on all routes except static files and Next.js internals
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};
