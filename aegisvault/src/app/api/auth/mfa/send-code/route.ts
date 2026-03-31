/**
 * POST /api/auth/mfa/send-code — Send a recovery OTP during the passkey login challenge
 *
 * This endpoint is intentionally unauthenticated — it is called during the login
 * flow AFTER credentials are validated but BEFORE a full session is issued.
 *
 * The caller must supply a short-lived preAuthToken that was issued by the login
 * endpoint. This token proves the user passed password auth without granting
 * full session rights.
 *
 * Security notes:
 *   - preAuthToken is a signed JWT (HS256, JWT_ACCESS_SECRET, 5 min TTL)
 *   - Payload: { sub: userId, purpose: 'pre-auth', email }
 *   - Rate limited: 5 requests per hour per IP
 *   - Returns 503 if the requested channel is not configured for this user
 */

import { NextRequest, NextResponse } from 'next/server';
import { jwtVerify } from 'jose';
import { z } from 'zod';
import { db } from '@/lib/server/db';
import { sendTelegramOtp } from '@/lib/auth/telegram-otp';
import { checkRateLimit, getClientIp } from '@/lib/server/rate-limit';

// ── JWT secret ────────────────────────────────────────────────────────────────

function loadJwtSecret(): Uint8Array {
  const secret = process.env.JWT_ACCESS_SECRET;
  if (!secret) {
    throw new Error('JWT_ACCESS_SECRET environment variable is not set.');
  }
  return new TextEncoder().encode(secret);
}

const JWT_SECRET = loadJwtSecret();

// ── Request schema ────────────────────────────────────────────────────────────

const SendCodeSchema = z.object({
  preAuthToken: z.string().min(1),
  type:         z.enum(['telegram', 'whatsapp']),
});

// ── Rate Limit Config ─────────────────────────────────────────────────────────
// 5 send-code requests per hour per IP

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

  // ── Parse body ─────────────────────────────────────────────────────────────
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ success: false, error: 'Invalid request body' }, { status: 400 });
  }

  const parsed = SendCodeSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ success: false, error: 'Validation failed' }, { status: 400 });
  }

  const { preAuthToken, type } = parsed.data;

  // ── Verify preAuthToken ────────────────────────────────────────────────────
  let userId: string;

  try {
    const { payload } = await jwtVerify(preAuthToken, JWT_SECRET);

    if (
      typeof payload.sub     !== 'string' ||
      !payload.sub           ||
      payload['purpose']     !== 'pre-auth'
    ) {
      return NextResponse.json(
        { success: false, error: 'Invalid pre-auth token' },
        { status: 401 },
      );
    }

    userId = payload.sub;
  } catch {
    return NextResponse.json(
      { success: false, error: 'Pre-auth token is invalid or has expired' },
      { status: 401 },
    );
  }

  // ── Send code by type ──────────────────────────────────────────────────────
  if (type === 'telegram') {
    const user = await db.user.findUnique({
      where:  { id: userId },
      select: { telegramEnabled: true, telegramChatId: true },
    });

    if (!user?.telegramEnabled || !user.telegramChatId) {
      return NextResponse.json(
        { success: false, error: 'This recovery method is not available' },
        { status: 503 },
      );
    }

    await sendTelegramOtp(userId, user.telegramChatId);
  } else {
    // type === 'whatsapp'
    try {
      const { sendWhatsAppOtp } = await import('@/lib/auth/whatsapp-otp');

      const user = await db.user.findUnique({
        where:  { id: userId },
        select: { whatsappEnabled: true, whatsappNumber: true } as never,
      }) as { whatsappEnabled?: boolean; whatsappNumber?: string | null } | null;

      if (!user?.whatsappEnabled || !user.whatsappNumber) {
        return NextResponse.json(
          { success: false, error: 'This recovery method is not available' },
          { status: 503 },
        );
      }

      await sendWhatsAppOtp(userId, user.whatsappNumber);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : '';
      if (message.includes('not configured') || message.includes('Cannot find module')) {
        return NextResponse.json(
          { success: false, error: 'This recovery method is not available' },
          { status: 503 },
        );
      }
      throw err;
    }
  }

  return NextResponse.json({ success: true, message: 'Code sent' });
}
