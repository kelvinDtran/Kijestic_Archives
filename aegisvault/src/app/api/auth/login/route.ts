/**
 * POST /api/auth/login
 *
 * Authenticate a user with email + account password.
 * Optionally verifies a TOTP code if MFA is enabled.
 *
 * Flow:
 *   1. Validate credentials
 *   2. If MFA is enabled, either verify inline (TOTP) or issue a short-lived
 *      mfaToken and return a challenge (Telegram / Email OTP)
 *   3. Create session → set httpOnly cookies
 *   4. Return user info (no tokens in body — they're in cookies)
 *
 * Priority order when multiple MFA methods are enabled: TOTP > Telegram > Email
 *
 * The vault is still "locked" after login. The client must prompt for
 * the master password separately to unlock vault decryption.
 */

import { NextRequest, NextResponse } from 'next/server';
import { SignJWT } from 'jose';
import { z } from 'zod';
import { db } from '@/lib/server/db';
import { verifyAccountPassword } from '@/lib/auth/password';
import { verifyTotpCode } from '@/lib/auth/totp';
import { sendTelegramOtp } from '@/lib/auth/telegram-otp';
import { sendEmailOtp } from '@/lib/auth/email-otp';
import { logAuditEvent } from '@/lib/server/audit';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';
import { createSessionAndSetCookies } from '@/lib/server/session';

// Shared secret used to sign short-lived MFA challenge tokens
function loadJwtSecret(): Uint8Array {
  const secret = process.env.JWT_ACCESS_SECRET;
  if (!secret) {
    throw new Error('JWT_ACCESS_SECRET environment variable is not set. Refusing to start.');
  }
  return new TextEncoder().encode(secret);
}

const ACCESS_SECRET = loadJwtSecret();

const LoginSchema = z.object({
  email:    z.string().email().max(254).toLowerCase().trim(),
  password: z.string().min(1).max(128),
  totpCode: z.string().length(6).optional(),
});

// Generic error message — never reveal whether the email exists
const INVALID_CREDENTIALS_MSG = 'Invalid email or password';

export async function POST(req: NextRequest) {
  // ── Rate limiting ──────────────────────────────────────────────────────────
  const ip = await getClientIp();
  const limited = await enforceRateLimit('login', ip);
  if (limited) return limited;

  // ── Parse and validate ─────────────────────────────────────────────────────
  let body: unknown;
  try { body = await req.json(); }
  catch { return NextResponse.json({ success: false, error: 'Invalid request body' }, { status: 400 }); }

  const parsed = LoginSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ success: false, error: 'Validation failed' }, { status: 400 });
  }

  const { email, password, totpCode } = parsed.data;
  const userAgent = req.headers.get('user-agent') ?? undefined;
  const auditCtx  = { ip, userAgent };

  // ── Find user ──────────────────────────────────────────────────────────────
  const user = await db.user.findUnique({
    where:  { email },
    select: {
      id:               true,
      email:            true,
      passwordHash:     true,
      totpEnabled:      true,
      totpSecret:       true,
      telegramEnabled:  true,
      telegramChatId:   true,
      emailMfaEnabled:  true,
      lockTimeout:      true,
    },
  });

  // Always run bcrypt verify even if user doesn't exist
  // This prevents timing attacks that would reveal email enumeration
  const DUMMY_HASH = '$2a$12$dummyhashfortimingprotectiononly.padding';
  const passwordMatch = await verifyAccountPassword(
    password,
    user?.passwordHash ?? DUMMY_HASH,
  );

  if (!user || !passwordMatch) {
    await logAuditEvent('AUTH_LOGIN_FAILED', {
      ...auditCtx,
      metadata: { reason: 'invalid_credentials' },
    });
    // Consistent response time — don't return faster for non-existent users
    return NextResponse.json(
      { success: false, error: INVALID_CREDENTIALS_MSG },
      { status: 401 },
    );
  }

  // ── MFA dispatch — priority order: TOTP > Telegram > Email ───────────────

  // TOTP: verify inline (code supplied) or signal challenge to client
  if (user.totpEnabled) {
    if (!totpCode) {
      // Signal to the client that TOTP MFA is required
      return NextResponse.json(
        { success: false, mfaRequired: true, mfaType: 'totp', error: 'MFA required', code: 'MFA_REQUIRED' },
        { status: 401 },
      );
    }

    if (!user.totpSecret || !verifyTotpCode(user.totpSecret, totpCode)) {
      await logAuditEvent('AUTH_MFA_CHALLENGE_FAILED', {
        ...auditCtx,
        userId: user.id,
        metadata: { type: 'totp' },
      });
      // Rate limit MFA failures separately
      const mfaLimitResponse = await enforceRateLimit('mfa', ip);
      if (mfaLimitResponse) return mfaLimitResponse;
      return NextResponse.json(
        { success: false, error: 'Invalid MFA code', code: 'MFA_INVALID' },
        { status: 401 },
      );
    }

    await logAuditEvent('AUTH_MFA_CHALLENGE_SUCCESS', {
      userId: user.id,
      ...auditCtx,
      metadata: { type: 'totp' },
    });
  } else if (user.telegramEnabled) {
    // Telegram OTP: send code then return a short-lived mfaToken for the verify step
    if (!user.telegramChatId) {
      return NextResponse.json(
        { success: false, error: 'Telegram MFA is enabled but no chat ID is configured' },
        { status: 500 },
      );
    }

    await sendTelegramOtp(user.id, user.telegramChatId);

    const mfaToken = await new SignJWT({ mfaType: 'telegram', purpose: 'mfa-challenge' })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject(user.id)
      .setIssuedAt()
      .setExpirationTime('15m')
      .sign(ACCESS_SECRET);

    return NextResponse.json(
      { success: false, mfaRequired: true, mfaType: 'telegram', mfaToken },
      { status: 401 },
    );
  } else if (user.emailMfaEnabled) {
    // Email OTP: send code then return a short-lived mfaToken for the verify step
    await sendEmailOtp(user.id, user.email);

    const mfaToken = await new SignJWT({ mfaType: 'email', purpose: 'mfa-challenge' })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject(user.id)
      .setIssuedAt()
      .setExpirationTime('15m')
      .sign(ACCESS_SECRET);

    return NextResponse.json(
      { success: false, mfaRequired: true, mfaType: 'email', mfaToken },
      { status: 401 },
    );
  }

  // ── Create session ─────────────────────────────────────────────────────────
  await createSessionAndSetCookies({ userId: user.id, email: user.email, userAgent, ip });

  // Update last login timestamp
  await db.user.update({
    where: { id: user.id },
    data:  { lastLoginAt: new Date() },
  });

  const mfaUsed = user.totpEnabled || user.telegramEnabled || user.emailMfaEnabled;
  await logAuditEvent('AUTH_LOGIN_SUCCESS', {
    userId: user.id,
    ...auditCtx,
    metadata: { mfa: mfaUsed },
  });

  return NextResponse.json({
    success: true,
    data: {
      user: {
        id:               user.id,
        email:            user.email,
        totpEnabled:      user.totpEnabled,
        telegramEnabled:  user.telegramEnabled,
        emailMfaEnabled:  user.emailMfaEnabled,
        lockTimeout:      user.lockTimeout,
      },
    },
  });
}
