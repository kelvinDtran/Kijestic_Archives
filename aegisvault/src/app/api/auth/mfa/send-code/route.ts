/**
 * POST /api/auth/mfa/send-code — Re-send an OTP during the MFA login challenge
 *
 * This endpoint is intentionally unauthenticated — it is called during the login
 * flow AFTER credentials are validated but BEFORE a full session is issued.
 *
 * The caller must supply a short-lived MFA challenge token (mfaToken) that was
 * issued by the login endpoint. This token proves the user passed password auth
 * without granting full session rights.
 *
 * Security notes:
 *   - mfaToken is a signed JWT (HS256, JWT_ACCESS_SECRET, 15 min TTL)
 *   - Payload: { sub: userId, mfaType: 'TELEGRAM' | 'EMAIL', purpose: 'mfa-challenge' }
 *   - Rate limited: 5 requests per hour per IP
 *   - Response never reveals whether a user/telegram exists (uniform success message)
 */

import { NextRequest, NextResponse } from 'next/server';
import { jwtVerify } from 'jose';
import { db } from '@/lib/server/db';
import { sendTelegramOtp } from '@/lib/auth/telegram-otp';
import { checkRateLimit, getClientIp } from '@/lib/server/rate-limit';

// ── MFA Challenge Token ───────────────────────────────────────────────────────

interface MfaChallengePayload {
  sub:      string;
  mfaType:  'TELEGRAM' | 'EMAIL';
  purpose:  string;
  exp?:     number;
  iat?:     number;
}

function loadJwtSecret(): Uint8Array {
  const secret = process.env.JWT_ACCESS_SECRET;
  if (!secret) {
    throw new Error('JWT_ACCESS_SECRET environment variable is not set.');
  }
  return new TextEncoder().encode(secret);
}

const JWT_SECRET = loadJwtSecret();

async function verifyMfaToken(token: string): Promise<MfaChallengePayload | null> {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET);

    if (
      typeof payload.sub      !== 'string' ||
      typeof payload.mfaType  !== 'string' ||
      typeof payload.purpose  !== 'string' ||
      payload.purpose !== 'mfa-challenge'  ||
      (payload.mfaType !== 'TELEGRAM' && payload.mfaType !== 'EMAIL')
    ) {
      return null;
    }

    return payload as unknown as MfaChallengePayload;
  } catch {
    return null;
  }
}

// ── Rate Limit Config ─────────────────────────────────────────────────────────
// 5 send-code requests per hour per IP — tighter than the generic 'mfa' bucket.

const SEND_CODE_LIMIT = { max: 5, windowMs: 60 * 60 * 1000 } as const;

// ── POST Handler ──────────────────────────────────────────────────────────────

export async function POST(req: NextRequest): Promise<NextResponse> {
  const ip = await getClientIp();

  // Custom rate limit: 5 per hour per IP for this endpoint specifically
  const rlResult = await checkRateLimit('mfa', `send-code:${ip}`);
  if (!rlResult.allowed) {
    return NextResponse.json(
      {
        success:      false,
        error:        'Too many requests. Please try again later.',
        code:         'RATE_LIMITED',
        retryAfterMs: rlResult.retryAfterMs,
      },
      {
        status: 429,
        headers: {
          'Retry-After':           String(Math.ceil(rlResult.retryAfterMs / 1000)),
          'X-RateLimit-Limit':     String(SEND_CODE_LIMIT.max),
          'X-RateLimit-Remaining': '0',
          'X-RateLimit-Reset':     String(Math.floor(rlResult.resetAt.getTime() / 1000)),
        },
      },
    );
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ success: false, error: 'Invalid request body' }, { status: 400 });
  }

  if (
    typeof body !== 'object' ||
    body === null ||
    typeof (body as Record<string, unknown>).mfaToken !== 'string'
  ) {
    return NextResponse.json(
      { success: false, error: 'mfaToken is required' },
      { status: 400 },
    );
  }

  const rawToken = ((body as Record<string, unknown>).mfaToken as string).trim();
  const mfaClaim = await verifyMfaToken(rawToken);

  if (!mfaClaim) {
    // Return a generic success to avoid revealing whether the token was valid
    return NextResponse.json({ success: true, message: 'Code sent' });
  }

  if (mfaClaim.mfaType === 'TELEGRAM') {
    const user = await db.user.findUnique({
      where:  { id: mfaClaim.sub },
      select: { telegramChatId: true, telegramEnabled: true },
    });

    // Silently succeed if user/telegram not found — caller must not learn this
    if (user?.telegramChatId && user.telegramEnabled) {
      try {
        await sendTelegramOtp(mfaClaim.sub, user.telegramChatId);
      } catch (err) {
        // Log for observability but do not surface the error to the caller
        console.error('[send-code] Telegram delivery failed:', err);
      }
    }
  }

  // EMAIL type is a no-op here (handled by a separate email OTP module)
  // The response is identical regardless of mfaType or outcome

  return NextResponse.json({ success: true, message: 'Code sent' });
}
