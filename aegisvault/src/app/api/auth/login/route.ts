/**
 * POST /api/auth/login
 *
 * Authenticate a user with email + account password.
 *
 * Flow:
 *   1. Validate credentials
 *   2. If the user has passkeys enrolled, issue a short-lived preAuthToken
 *      and return PASSKEY_REQUIRED (status 200 — password was correct)
 *   3. If no passkeys, create full session → set httpOnly cookies
 *   4. Return user info (no tokens in body — they're in cookies)
 *
 * The vault is still "locked" after login. The client must prompt for
 * the master password separately to unlock vault decryption.
 */

import { NextRequest, NextResponse } from 'next/server';
import { SignJWT } from 'jose';
import { z } from 'zod';
import { db } from '@/lib/server/db';
import { verifyAccountPassword } from '@/lib/auth/password';
import { logAuditEvent } from '@/lib/server/audit';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';
import { createSessionAndSetCookies } from '@/lib/server/session';

// Shared secret used to sign short-lived pre-auth tokens
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

  const { email, password } = parsed.data;
  const userAgent = req.headers.get('user-agent') ?? undefined;
  const auditCtx  = { ip, userAgent };

  // ── Find user ──────────────────────────────────────────────────────────────
  const user = await db.user.findUnique({
    where:  { email },
    select: {
      id:               true,
      email:            true,
      passwordHash:     true,
      telegramEnabled:  true,
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

  // ── Check for enrolled passkeys ────────────────────────────────────────────
  const passkeyCount = await db.webAuthnCredential.count({
    where: { userId: user.id },
  });

  if (passkeyCount > 0) {
    // Issue a short-lived preAuthToken — password was correct, passkey is next step
    const preAuthToken = await new SignJWT({ purpose: 'pre-auth', email: user.email })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject(user.id)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(ACCESS_SECRET);

    return NextResponse.json(
      {
        success:       false,
        code:          'PASSKEY_REQUIRED',
        preAuthToken,
        data: {
          telegramEnabled: user.telegramEnabled,
          whatsappEnabled: false,
        },
      },
      { status: 200 },
    );
  }

  // ── No passkeys — create full session ─────────────────────────────────────
  await createSessionAndSetCookies({ userId: user.id, email: user.email, userAgent, ip });

  // Update last login timestamp
  await db.user.update({
    where: { id: user.id },
    data:  { lastLoginAt: new Date() },
  });

  await logAuditEvent('AUTH_LOGIN_SUCCESS', {
    userId: user.id,
    ...auditCtx,
    metadata: { mfa: false },
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
