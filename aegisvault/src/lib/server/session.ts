/**
 * AegisVault — Session Management (Server-Side)
 *
 * Sessions are database-backed with:
 *   - Refresh token rotation on every use
 *   - Hashed token storage (raw refresh tokens never in DB)
 *   - Device fingerprinting for anomaly detection
 *   - Absolute expiry + last-used tracking
 */

import { db } from './db';
import {
  generateRefreshToken,
  signAccessToken,
  hashToken,
  refreshTokenExpiresAt,
  setAuthCookies,
} from '../auth/jwt';
import type { Session } from '@prisma/client';

// ── Session Creation ──────────────────────────────────────────────────────────

export interface CreateSessionOptions {
  userId:    string;
  email:     string;
  userAgent?: string;
  ip?:        string;
}

export interface SessionTokens {
  accessToken:         string;
  refreshToken:        string;
  accessTokenJti:      string;
  accessTokenExpiresAt: Date;
  refreshTokenExpiresAt: Date;
}

/**
 * Create a new session for a user.
 * Issues a new access + refresh token pair and stores the session in DB.
 */
export async function createSession(opts: CreateSessionOptions): Promise<SessionTokens> {
  const { token: refreshToken, hash: refreshHash } = generateRefreshToken();
  const refreshExpiry = refreshTokenExpiresAt();
  const { token: accessToken, jti, expiresAt: accessExpiry } = await signAccessToken(
    opts.userId,
    opts.email,
  );

  // Hash IP for privacy-preserving storage
  const ipHash = opts.ip
    ? require('crypto').createHash('sha256').update(opts.ip).digest('hex')
    : null;

  await db.session.create({
    data: {
      userId:           opts.userId,
      refreshTokenHash: refreshHash,
      accessTokenJti:   jti,
      userAgent:        opts.userAgent?.slice(0, 500) ?? null,
      ipHash,
      expiresAt:        refreshExpiry,
      lastUsedAt:       new Date(),
    },
  });

  return {
    accessToken,
    refreshToken,
    accessTokenJti:       jti,
    accessTokenExpiresAt: accessExpiry,
    refreshTokenExpiresAt: refreshExpiry,
  };
}

/**
 * Refresh an existing session.
 * Implements refresh token rotation: invalidates the old token, issues a new pair.
 * Returns null if the refresh token is invalid, expired, or revoked.
 */
export async function refreshSession(
  rawRefreshToken: string,
  userEmail: string,
): Promise<SessionTokens | null> {
  const tokenHash = hashToken(rawRefreshToken);
  const now = new Date();

  const session = await db.session.findUnique({
    where: { refreshTokenHash: tokenHash },
    include: { user: { select: { id: true, email: true } } },
  });

  if (!session || session.isRevoked || session.expiresAt < now) {
    return null;
  }

  // Issue new token pair
  const { token: newRefreshToken, hash: newRefreshHash } = generateRefreshToken();
  const newRefreshExpiry = refreshTokenExpiresAt();
  const { token: accessToken, jti, expiresAt: accessExpiry } = await signAccessToken(
    session.userId,
    userEmail,
  );

  // Atomic update: invalidate old token, create new record
  await db.$transaction([
    db.session.update({
      where: { id: session.id },
      data:  { isRevoked: true },
    }),
    db.session.create({
      data: {
        userId:           session.userId,
        refreshTokenHash: newRefreshHash,
        accessTokenJti:   jti,
        userAgent:        session.userAgent,
        ipHash:           session.ipHash,
        expiresAt:        newRefreshExpiry,
        lastUsedAt:       now,
      },
    }),
  ]);

  return {
    accessToken,
    refreshToken:            newRefreshToken,
    accessTokenJti:          jti,
    accessTokenExpiresAt:    accessExpiry,
    refreshTokenExpiresAt:   newRefreshExpiry,
  };
}

/**
 * Revoke a specific session by ID.
 * Validates that the session belongs to the given user.
 */
export async function revokeSession(sessionId: string, userId: string): Promise<boolean> {
  const result = await db.session.updateMany({
    where: { id: sessionId, userId, isRevoked: false },
    data:  { isRevoked: true },
  });
  return result.count > 0;
}

/**
 * Revoke ALL sessions for a user.
 * Used for "logout everywhere" and security incidents.
 */
export async function revokeAllSessions(userId: string): Promise<number> {
  const result = await db.session.updateMany({
    where: { userId, isRevoked: false },
    data:  { isRevoked: true },
  });
  return result.count;
}

/**
 * Get all active sessions for a user (for the sessions management page).
 * Returns anonymized data — no raw tokens, no raw IPs.
 */
export async function getUserSessions(userId: string): Promise<Array<{
  id:         string;
  userAgent:  string | null;
  lastUsedAt: Date;
  createdAt:  Date;
  expiresAt:  Date;
  isCurrent:  boolean;
}>> {
  const sessions = await db.session.findMany({
    where:   { userId, isRevoked: false, expiresAt: { gt: new Date() } },
    orderBy: { lastUsedAt: 'desc' },
    select: {
      id:        true,
      userAgent: true,
      lastUsedAt: true,
      createdAt:  true,
      expiresAt:  true,
    },
  });

  // The "current" session is the most recently used one
  const mostRecentId = sessions[0]?.id;

  return sessions.map((s) => ({
    ...s,
    isCurrent: s.id === mostRecentId,
  }));
}

/**
 * Clean up expired and revoked sessions older than 30 days.
 * Call this periodically (e.g., via a cron job).
 */
export async function cleanupSessions(): Promise<number> {
  const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const result = await db.session.deleteMany({
    where: {
      OR: [
        { expiresAt: { lt: new Date() } },
        { isRevoked: true, lastUsedAt: { lt: cutoff } },
      ],
    },
  });
  return result.count;
}

/**
 * Create a session and set the auth cookies in a single step.
 * Convenience wrapper for login handlers.
 */
export async function createSessionAndSetCookies(opts: CreateSessionOptions): Promise<void> {
  const tokens = await createSession(opts);
  await setAuthCookies(
    tokens.accessToken,
    tokens.refreshToken,
    tokens.accessTokenExpiresAt,
    tokens.refreshTokenExpiresAt,
  );
}
