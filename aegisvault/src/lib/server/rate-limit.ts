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

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Get the client IP from the request.
 * Handles Vercel, Cloudflare, and direct connections.
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
 */
export function hashIdentifier(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 16);
}

// ── Rate Limiter ──────────────────────────────────────────────────────────────

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
  retryAfterMs: number;
}

/**
 * Check and increment a rate limit counter.
 * If the limit is exceeded, returns { allowed: false }.
 *
 * @param action  - The action being rate-limited
 * @param identifier - Raw identifier (IP, email) — will be hashed internally
 */
export async function checkRateLimit(
  action: RateLimitAction,
  identifier: string,
): Promise<RateLimitResult> {
  const config = RATE_LIMITS[action];
  const key    = `${action}:${hashIdentifier(identifier)}`;
  const now    = new Date();
  const resetAt = new Date(now.getTime() + config.windowMs);

  // Cleanup expired entries periodically (10% chance to avoid overhead)
  if (Math.random() < 0.1) {
    db.rateLimitEntry
      .deleteMany({ where: { resetAt: { lt: now } } })
      .catch(() => {/* non-critical cleanup */});
  }

  try {
    const entry = await db.rateLimitEntry.upsert({
      where: { key },
      create: { key, count: 1, resetAt },
      update: {
        count: { increment: 1 },
        // Reset window if expired
        resetAt: {
          // Only update resetAt if the current entry has expired
          // Note: Prisma doesn't support conditional updates directly;
          // we handle this with a raw check
        },
      },
    });

    // If the entry's reset window has passed, reset it
    if (entry.resetAt < now) {
      const reset = await db.rateLimitEntry.update({
        where: { key },
        data: { count: 1, resetAt },
      });
      return {
        allowed:      true,
        remaining:    config.max - 1,
        resetAt:      reset.resetAt,
        retryAfterMs: 0,
      };
    }

    const remaining = Math.max(0, config.max - entry.count);
    const allowed   = entry.count <= config.max;

    return {
      allowed,
      remaining,
      resetAt:      entry.resetAt,
      retryAfterMs: allowed ? 0 : entry.resetAt.getTime() - now.getTime(),
    };
  } catch {
    // If rate limiting fails (DB issue), allow the request but log
    console.error('[RateLimit] Failed to check rate limit for key:', key);
    return {
      allowed:      true,
      remaining:    config.max,
      resetAt,
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
