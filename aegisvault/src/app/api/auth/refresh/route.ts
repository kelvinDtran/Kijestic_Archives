/**
 * POST /api/auth/refresh
 *
 * Exchange a valid refresh token for a new access + refresh token pair.
 * Implements refresh token rotation — the old token is invalidated immediately.
 *
 * The refresh token cookie is scoped to this path only (path=/api/auth/refresh).
 */

import { NextRequest, NextResponse } from 'next/server';
import { getRefreshTokenFromCookies, setAuthCookies, clearAuthCookies } from '@/lib/auth/jwt';
import { refreshSession } from '@/lib/server/session';
import { db } from '@/lib/server/db';

export async function POST(_req: NextRequest) {
  const refreshToken = await getRefreshTokenFromCookies();
  if (!refreshToken) {
    return NextResponse.json(
      { success: false, error: 'No refresh token', code: 'UNAUTHENTICATED' },
      { status: 401 },
    );
  }

  // Get user email for token re-signing
  // We need the email to include it in the new access token
  const { hashToken } = await import('@/lib/auth/jwt');
  const tokenHash = hashToken(refreshToken);

  const session = await db.session.findUnique({
    where: { refreshTokenHash: tokenHash },
    include: { user: { select: { email: true } } },
  });

  if (!session) {
    await clearAuthCookies();
    return NextResponse.json(
      { success: false, error: 'Invalid session', code: 'UNAUTHENTICATED' },
      { status: 401 },
    );
  }

  const tokens = await refreshSession(refreshToken, session.user.email);

  if (!tokens) {
    await clearAuthCookies();
    return NextResponse.json(
      { success: false, error: 'Session expired or revoked', code: 'SESSION_EXPIRED' },
      { status: 401 },
    );
  }

  await setAuthCookies(
    tokens.accessToken,
    tokens.refreshToken,
    tokens.accessTokenExpiresAt,
    tokens.refreshTokenExpiresAt,
  );

  return NextResponse.json({
    success: true,
    data: {
      expiresAt: tokens.accessTokenExpiresAt.getTime(),
    },
  });
}
