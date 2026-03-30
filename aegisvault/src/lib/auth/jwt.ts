/**
 * AegisVault — JWT Utilities (Server-Side Only)
 *
 * Access tokens: short-lived (15 min), HS256, stored in httpOnly cookie
 * Refresh tokens: opaque random bytes, stored hashed in DB, set in httpOnly cookie
 *
 * SECURITY:
 *   - Both tokens are set as httpOnly, Secure, SameSite=Strict cookies
 *   - Refresh tokens are stored as SHA-256 hashes in the DB (never raw)
 *   - Access token JTI is tracked for revocation
 *   - On refresh: old token is invalidated, new pair issued (rotation)
 */

import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import { createHash, randomBytes } from 'crypto';
import { cookies } from 'next/headers';
import { db } from '../server/db';

// ── Config ────────────────────────────────────────────────────────────────────

function loadJwtSecret(): Uint8Array {
  const secret = process.env.JWT_ACCESS_SECRET;
  if (!secret) {
    throw new Error('JWT_ACCESS_SECRET environment variable is not set. Refusing to start.');
  }
  return new TextEncoder().encode(secret);
}

const ACCESS_SECRET = loadJwtSecret();

const ACCESS_TTL     = parseInt(process.env.ACCESS_TOKEN_TTL  ?? '900',     10); // 15 min
const REFRESH_TTL    = parseInt(process.env.REFRESH_TOKEN_TTL ?? '2592000', 10); // 30 days

export const COOKIE_ACCESS  = 'aegis_access';
export const COOKIE_REFRESH = 'aegis_refresh';

// ── Access Token ──────────────────────────────────────────────────────────────

export interface AccessTokenPayload extends JWTPayload {
  sub: string;   // userId
  jti: string;   // unique token ID (for revocation)
  email: string;
}

/**
 * Sign a new access token.
 */
export async function signAccessToken(userId: string, email: string): Promise<{
  token: string;
  jti: string;
  expiresAt: Date;
}> {
  const jti = randomBytes(16).toString('hex');
  const expiresAt = new Date(Date.now() + ACCESS_TTL * 1000);

  const token = await new SignJWT({ email } satisfies Partial<AccessTokenPayload>)
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(userId)
    .setJti(jti)
    .setIssuedAt()
    .setExpirationTime(Math.floor(expiresAt.getTime() / 1000))
    .sign(ACCESS_SECRET);

  return { token, jti, expiresAt };
}

/**
 * Verify and decode an access token.
 * Returns null on any failure (expired, invalid signature, etc.)
 */
export async function verifyAccessToken(token: string): Promise<AccessTokenPayload | null> {
  try {
    const { payload } = await jwtVerify(token, ACCESS_SECRET);
    return payload as AccessTokenPayload;
  } catch {
    return null;
  }
}

// ── Refresh Token ─────────────────────────────────────────────────────────────

/**
 * Generate a cryptographically random refresh token.
 * Returns both the raw token (to send to client) and its hash (to store in DB).
 */
export function generateRefreshToken(): { token: string; hash: string } {
  const token = randomBytes(48).toString('base64url');
  const hash  = hashToken(token);
  return { token, hash };
}

/**
 * Hash a refresh token for safe DB storage.
 * Uses SHA-256 — sufficient since the tokens are already high-entropy random values.
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * Compute the refresh token expiry date.
 */
export function refreshTokenExpiresAt(): Date {
  return new Date(Date.now() + REFRESH_TTL * 1000);
}

// ── Cookie Helpers ────────────────────────────────────────────────────────────

const isProduction = process.env.NODE_ENV === 'production';

/**
 * Set both auth cookies (access + refresh tokens).
 * Called after successful login or token refresh.
 */
export async function setAuthCookies(
  accessToken: string,
  refreshToken: string,
  accessExpiresAt: Date,
  refreshExpiresAt: Date,
): Promise<void> {
  const cookieStore = await cookies();

  cookieStore.set(COOKIE_ACCESS, accessToken, {
    httpOnly: true,
    secure:   isProduction,
    sameSite: 'strict',
    expires:  accessExpiresAt,
    path:     '/',
  });

  cookieStore.set(COOKIE_REFRESH, refreshToken, {
    httpOnly: true,
    secure:   isProduction,
    sameSite: 'strict',
    expires:  refreshExpiresAt,
    path:     '/api/auth/refresh',  // limit refresh token to the refresh endpoint only
  });
}

/**
 * Clear auth cookies (logout).
 */
export async function clearAuthCookies(): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.delete(COOKIE_ACCESS);
  cookieStore.delete(COOKIE_REFRESH);
}

/**
 * Get the current access token from cookies.
 */
export async function getAccessTokenFromCookies(): Promise<string | null> {
  const cookieStore = await cookies();
  return cookieStore.get(COOKIE_ACCESS)?.value ?? null;
}

/**
 * Get the refresh token from cookies.
 */
export async function getRefreshTokenFromCookies(): Promise<string | null> {
  const cookieStore = await cookies();
  return cookieStore.get(COOKIE_REFRESH)?.value ?? null;
}

// ── Request Auth ──────────────────────────────────────────────────────────────

/**
 * Authenticate an incoming API request.
 * Reads the access token from cookies, verifies its signature and expiry,
 * then confirms the session has not been revoked in the database (JTI check).
 * Returns null if the request is unauthenticated or the session is revoked.
 */
export async function getAuthFromRequest(): Promise<AccessTokenPayload | null> {
  const token = await getAccessTokenFromCookies();
  if (!token) return null;

  const payload = await verifyAccessToken(token);
  if (!payload || !payload.jti) return null;

  const session = await db.session.findFirst({
    where: { accessTokenJti: payload.jti },
    select: { isRevoked: true },
  });

  if (!session || session.isRevoked) return null;

  return payload;
}
