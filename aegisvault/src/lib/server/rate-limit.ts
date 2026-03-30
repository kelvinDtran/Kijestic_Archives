/**
 * AegisVault — Rate Limiting (DB-backed)
 *
 * Implements a sliding window rate limiter backed by PostgreSQL.
 * For production with high traffic, replace with Redis (e.g., @upstash/ratelimit).
 *
 * Rate limit keys are hashed to avoid storing raw IPs in the database.
 * This provides a balance between abuse prevention and user privacy.
 */

import { createHash } from 'crypto';
import { db } from './db';
import { headers } from 'next/headers';

// ── Configuration ─────────────────────────────────────────────────────────────

export const RATE_LIMITS = {
  // Authentication endpoints
  login:    { max: parseInt(process.env.RATE_LIMIT_LOGIN_MAX    ?? '10', 10), windowMs: 15 * 60 * 1000 },
  register: { max: parseInt(process.env.RATE_LIMIT_REGISTER_MAX ?? '5',  10), windowMs: 60 * 60 * 1000 },
  // MFA
  mfa:      { max: 5,  windowMs: 15 * 60 * 1000 },
  // General API
  api:      { max: 100, windowMs: 60 * 1000 },
} as const;

export type RateLimitAction = keyof typeof RATE_LIMITS;

/**
 * Actions that must fail closed (deny) when the DB is unavailable.
 * Failing open on auth endpoints would allow unlimited login/MFA attempts
 * if the rate-limit store becomes unreachable — a brute-force risk.
 */
const FAIL_CLOSED_ACTIONS = new Set<RateLimitAction>(['login', 'mfa']);

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Get the client IP from the request.
 * Handles Vercel, Cloudflare, and direct connections.
 *
 * WARNING: X-Forwarded-For and X-Real-IP headers are only trustworthy when
 * the application sits behind a correctly configured reverse proxy (e.g.,
 * Nginx, Cloudflare, Vercel edge). If the server is exposed directly these
 * headers can be spoofed by clients, allowing them to bypass rate limits.
 */
export async function getClientIp(): Promise<string> {
  const headerList = await headers();
  return (
    headerList.get('cf-connecting-ip') ??
    headerList.get('x-real-ip') ??
    headerList.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    'unknown'
  );
}

/**
 * Hash an identifier for use as a rate limit key.
 * Hashing prevents storing raw IPs/emails in the database.
 * Full 256-bit (64 hex chars) digest is used to prevent hash-collision
 * attacks that could allow an attacker to share another user's rate-limit
 * bucket.
 */
export function hashIdentifier(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

// ── Rate Limiter ──────────────────────────────────────────────────────────────

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
  retryAfterMs: number;
}

/**
 * Check and increment a rate limit counter atomically.
 * Uses a single PostgreSQL INSERT … ON CONFLICT DO UPDATE so that the
 * read-then-write is never split across two round-trips, eliminating the
 * TOCTOU race present in a non-atomic upsert + separate reset.
 *
 * If the limit is exceeded, returns { allowed: false }.
 *
 * @param action     - The action being rate-limited
 * @param identifier - Raw identifier (IP, email) — will be hashed internally
 */
export async function checkRateLimit(
  action: RateLimitAction,
  identifier: string,
): Promise<RateLimitResult> {
  const config = RATE_LIMITS[action];
  const key    = `${action}:${hashIdentifier(identifier)}`;
  const now    = new Date();

  // Cleanup expired entries periodically (10% chance to avoid overhead)
  if (Math.random() < 0.1) {
    db.rateLimitEntry
      .deleteMany({ where: { resetAt: { lt: now } } })
      .catch(() => {/* non-critical cleanup */});
  }

  try {
    // Atomic upsert: insert a fresh row OR increment/reset within a single
    // statement to avoid a TOCTOU race between reading the current count and
    // writing the new one.
    type RawRow = { count: number; resetAt: Date };
    const rows = await db.$queryRaw<RawRow[]>`
      INSERT INTO "RateLimitEntry" (id, key, count, "resetAt", "updatedAt")
      VALUES (
        gen_random_uuid()::text,
        ${key},
        1,
        NOW() + ${config.windowMs} * interval '1 millisecond',
        NOW()
      )
      ON CONFLICT (key) DO UPDATE SET
        count    = CASE
                     WHEN "RateLimitEntry"."resetAt" > NOW()
                     THEN "RateLimitEntry".count + 1
                     ELSE 1
                   END,
        "resetAt" = CASE
                     WHEN "RateLimitEntry"."resetAt" > NOW()
                     THEN "RateLimitEntry"."resetAt"
                     ELSE NOW() + ${config.windowMs} * interval '1 millisecond'
                   END,
        "updatedAt" = NOW()
      RETURNING count, "resetAt"
    `;

    const entry    = rows[0];
    const resetAt  = new Date(entry.resetAt);
    const count    = Number(entry.count);
    const allowed  = count <= config.max;
    const remaining = Math.max(0, config.max - count);

    return {
      allowed,
      remaining,
      resetAt,
      retryAfterMs: allowed ? 0 : resetAt.getTime() - now.getTime(),
    };
  } catch (err) {
    if (FAIL_CLOSED_ACTIONS.has(action)) {
      // Deliberately fail closed for authentication actions.
      // If the rate-limit store is unavailable we must not allow unlimited
      // login or MFA attempts — the safer default is to deny and surface a
      // 503-style response rather than risk brute-force exposure.
      console.error('[RateLimit] DB unavailable for auth action — failing closed:', action, err);
      return {
        allowed:      false,
        remaining:    0,
        resetAt:      new Date(),
        retryAfterMs: 0,
      };
    }

    // For non-auth actions (register, api) failing open is acceptable, but
    // the error should still be logged for observability.
    console.error('[RateLimit] Failed to check rate limit for key:', key, err);
    return {
      allowed:      true,
      remaining:    config.max,
      resetAt:      new Date(now.getTime() + config.windowMs),
      retryAfterMs: 0,
    };
  }
}

/**
 * Convenience: check rate limit and return a 429 Response if exceeded.
 * Returns null if the request is allowed.
 */
export async function enforceRateLimit(
  action: RateLimitAction,
  identifier: string,
): Promise<Response | null> {
  const result = await checkRateLimit(action, identifier);

  if (!result.allowed) {
    return new Response(
      JSON.stringify({
        success: false,
        error: 'Too many requests. Please try again later.',
        code: 'RATE_LIMITED',
        retryAfterMs: result.retryAfterMs,
      }),
      {
        status: 429,
        headers: {
          'Content-Type':  'application/json',
          'Retry-After':   String(Math.ceil(result.retryAfterMs / 1000)),
          'X-RateLimit-Limit':     String(RATE_LIMITS[action].max),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset':     String(Math.floor(result.resetAt.getTime() / 1000)),
        },
      },
    );
  }

  return null;
}
