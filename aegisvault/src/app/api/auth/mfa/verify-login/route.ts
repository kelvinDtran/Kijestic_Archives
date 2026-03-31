/**
 * POST /api/auth/mfa/verify-login
 *
 * Recovery login path for users who cannot use their passkey.
 * Accepts a preAuthToken (issued by POST /api/auth/login) and a recovery code.
 *
 * Supported recovery types:
 *   - 'telegram': verify a Telegram OTP sent via /api/auth/mfa/send-code
 *   - 'whatsapp': verify a WhatsApp OTP sent via /api/auth/mfa/send-code
 *   - 'backup':   verify a one-time backup code
 *
 * Flow:
 *   1. Verify the short-lived preAuthToken
 *   2. Verify the submitted code for the given type
 *   3. Create a full session → set httpOnly cookies
 *   4. Return the authenticated user info
 *
 * No authentication cookie is required — the user is not yet logged in.
 */

import { NextRequest, NextResponse } from 'next/server';
import { jwtVerify } from 'jose';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { db } from '@/lib/server/db';
import { verifyTelegramOtp } from '@/lib/auth/telegram-otp';
import { logAuditEvent } from '@/lib/server/audit';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';
import { createSessionAndSetCookies } from '@/lib/server/session';

// ── JWT secret (same key used to sign preAuthTokens in the login route) ───────

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
  preAuthToken: z.string().min(1),
  code:         z.string().min(1).max(100),
  type:         z.enum(['telegram', 'whatsapp', 'backup']),
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

  const { preAuthToken, code, type } = parsed.data;

  // ── Verify preAuthToken ────────────────────────────────────────────────────
  let userId: string;

  try {
    const { payload } = await jwtVerify(preAuthToken, ACCESS_SECRET);

    if (payload['purpose'] !== 'pre-auth') {
      return NextResponse.json(
        { success: false, error: 'Invalid pre-auth token' },
        { status: 401 },
      );
    }

    if (typeof payload.sub !== 'string' || !payload.sub) {
      return NextResponse.json(
        { success: false, error: 'Invalid pre-auth token' },
        { status: 401 },
      );
    }

    userId = payload.sub;
  } catch {
    // Expired, tampered, or otherwise invalid token
    return NextResponse.json(
      { success: false, error: 'Pre-auth token is invalid or has expired' },
      { status: 401 },
    );
  }

  // ── Verify code by type ────────────────────────────────────────────────────
  let isValid = false;

  if (type === 'telegram') {
    isValid = await verifyTelegramOtp(userId, code);
  } else if (type === 'whatsapp') {
    try {
      const { verifyWhatsAppOtp } = await import('@/lib/auth/whatsapp-otp');
      isValid = await verifyWhatsAppOtp(userId, code);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : '';
      if (message.includes('not configured')) {
        return NextResponse.json(
          { success: false, error: 'This recovery method is not available' },
          { status: 503 },
        );
      }
      throw err;
    }
  } else {
    // type === 'backup'
    const backupCodes = await db.backupCode.findMany({
      where: { userId, usedAt: null },
    });

    let matchedCode: { id: string } | null = null;

    for (const bc of backupCodes) {
      const codeWithoutDashes = code.replace(/-/g, '');
      if (
        await bcrypt.compare(codeWithoutDashes, bc.codeHash) ||
        await bcrypt.compare(code, bc.codeHash)
      ) {
        matchedCode = bc;
        break;
      }
    }

    if (!matchedCode) {
      await logAuditEvent('AUTH_MFA_CHALLENGE_FAILED', {
        ...auditCtx,
        userId,
        metadata: { type: 'backup' },
      });
      const mfaLimitResponse = await enforceRateLimit('mfa', ip);
      if (mfaLimitResponse) return mfaLimitResponse;
      return NextResponse.json(
        { success: false, error: 'Invalid or expired verification code', code: 'MFA_INVALID' },
        { status: 401 },
      );
    }

    await db.backupCode.update({
      where: { id: matchedCode.id },
      data:  { usedAt: new Date() },
    });

    isValid = true;
  }

  if (!isValid) {
    await logAuditEvent('AUTH_MFA_CHALLENGE_FAILED', {
      ...auditCtx,
      userId,
      metadata: { type },
    });
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
    metadata: { type },
  });

  // ── Look up user and create session ────────────────────────────────────────
  const user = await db.user.findUnique({
    where:  { id: userId },
    select: { id: true, email: true, lockTimeout: true },
  });

  if (!user) {
    // Extremely unlikely (account deleted between login and code verify)
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
    metadata: { mfa: true, mfaType: type },
  });

  return NextResponse.json({
    success: true,
    data: {
      user: {
        id:          user.id,
        email:       user.email,
        lockTimeout: user.lockTimeout,
      },
    },
  });
}
