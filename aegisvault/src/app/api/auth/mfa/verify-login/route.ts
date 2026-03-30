/**
 * POST /api/auth/mfa/verify-login
 *
 * Completes login for users whose MFA method is SMS or Email OTP.
 *
 * Flow:
 *   1. Verify the short-lived mfaToken issued by POST /api/auth/login
 *   2. Verify the OTP code the user submitted (SMS or Email)
 *   3. Create a full session → set httpOnly cookies
 *   4. Return the authenticated user info
 *
 * The mfaToken is a 15-minute HS256 JWT with:
 *   { sub: userId, mfaType: 'sms' | 'email', purpose: 'mfa-challenge' }
 *
 * No authentication cookie is required — the user is not yet logged in.
 */

import { NextRequest, NextResponse } from 'next/server';
import { jwtVerify } from 'jose';
import { z } from 'zod';
import { db } from '@/lib/server/db';
import { verifySmsOtp } from '@/lib/auth/sms-otp';
import { verifyEmailOtp } from '@/lib/auth/email-otp';
import { logAuditEvent } from '@/lib/server/audit';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';
import { createSessionAndSetCookies } from '@/lib/server/session';

// ── JWT secret (same key used to sign mfaTokens in the login route) ───────────

function loadJwtSecret(): Uint8Array {
  const secret = process.env.JWT_ACCESS_SECRET;
  if (!secret) {
    throw new Error('JWT_ACCESS_SECRET environment variable is not set. Refusing to start.');
  }
  return new TextEncoder().encode(secret);
}

const ACCESS_SECRET = loadJwtSecret();

// ── Request schema ────────────────────────────────────────────────────────────

const VerifyLoginSchema = z.object({
  mfaToken: z.string().min(1),
  code:     z.string().length(6),
});

// ── Handler ───────────────────────────────────────────────────────────────────

export async function POST(req: NextRequest) {
  // ── Rate limiting ──────────────────────────────────────────────────────────
  const ip = await getClientIp();
  const limited = await enforceRateLimit('mfa', ip);
  if (limited) return limited;

  const userAgent = req.headers.get('user-agent') ?? undefined;
  const auditCtx  = { ip, userAgent };

  // ── Parse and validate ─────────────────────────────────────────────────────
  let body: unknown;
  try { body = await req.json(); }
  catch { return NextResponse.json({ success: false, error: 'Invalid request body' }, { status: 400 }); }

  const parsed = VerifyLoginSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ success: false, error: 'Validation failed' }, { status: 400 });
  }

  const { mfaToken, code } = parsed.data;

  // ── Verify mfaToken ────────────────────────────────────────────────────────
  let userId: string;
  let mfaType: string;

  try {
    const { payload } = await jwtVerify(mfaToken, ACCESS_SECRET);

    if (payload['purpose'] !== 'mfa-challenge') {
      return NextResponse.json(
        { success: false, error: 'Invalid MFA token' },
        { status: 401 },
      );
    }

    if (typeof payload.sub !== 'string' || !payload.sub) {
      return NextResponse.json(
        { success: false, error: 'Invalid MFA token' },
        { status: 401 },
      );
    }

    if (payload['mfaType'] !== 'sms' && payload['mfaType'] !== 'email') {
      return NextResponse.json(
        { success: false, error: 'Invalid MFA token' },
        { status: 401 },
      );
    }

    userId  = payload.sub;
    mfaType = payload['mfaType'] as string;
  } catch {
    // Expired, tampered, or otherwise invalid token
    return NextResponse.json(
      { success: false, error: 'MFA token is invalid or has expired' },
      { status: 401 },
    );
  }

  // ── Verify OTP code ────────────────────────────────────────────────────────
  const isValid =
    mfaType === 'sms'
      ? await verifySmsOtp(userId, code)
      : await verifyEmailOtp(userId, code);

  if (!isValid) {
    await logAuditEvent('AUTH_MFA_CHALLENGE_FAILED', {
      ...auditCtx,
      userId,
      metadata: { type: mfaType },
    });
    // Re-apply MFA rate limit on failure to slow brute-force attempts
    const mfaLimitResponse = await enforceRateLimit('mfa', ip);
    if (mfaLimitResponse) return mfaLimitResponse;
    return NextResponse.json(
      { success: false, error: 'Invalid or expired verification code', code: 'MFA_INVALID' },
      { status: 401 },
    );
  }

  await logAuditEvent('AUTH_MFA_CHALLENGE_SUCCESS', {
    userId,
    ...auditCtx,
    metadata: { type: mfaType },
  });

  // ── Look up user and create session ────────────────────────────────────────
  const user = await db.user.findUnique({
    where:  { id: userId },
    select: { id: true, email: true, lockTimeout: true },
  });

  if (!user) {
    // Extremely unlikely (account deleted between login and OTP verify)
    return NextResponse.json(
      { success: false, error: 'User not found' },
      { status: 401 },
    );
  }

  await createSessionAndSetCookies({ userId: user.id, email: user.email, userAgent, ip });

  // Update last login timestamp
  await db.user.update({
    where: { id: user.id },
    data:  { lastLoginAt: new Date() },
  });

  await logAuditEvent('AUTH_LOGIN_SUCCESS', {
    userId: user.id,
    ...auditCtx,
    metadata: { mfa: true, mfaType },
  });

  return NextResponse.json({
    success: true,
    data: {
      user: {
        id:    user.id,
        email: user.email,
      },
    },
  });
}
