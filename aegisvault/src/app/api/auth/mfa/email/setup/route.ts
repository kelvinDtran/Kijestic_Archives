/**
 * POST   /api/auth/mfa/email/setup  — Send a verification OTP to enable email MFA
 * DELETE /api/auth/mfa/email/setup  — Disable email MFA (requires OTP or password)
 */

import { NextRequest, NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { sendEmailOtp, verifyEmailOtp } from '@/lib/auth/email-otp';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

// ── POST: Initiate email MFA setup ────────────────────────────────────────────
// Sends a 6-digit verification OTP to the user's account email.
// The user must then POST to /api/auth/mfa/email/verify with the code to enable.

export async function POST(_req: NextRequest) {
  const ip = await getClientIp();
  const rateLimitResponse = await enforceRateLimit('mfa', ip);
  if (rateLimitResponse) return rateLimitResponse;

  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  const user = await db.user.findUnique({
    where:  { id: auth.sub },
    select: { email: true, emailMfaEnabled: true },
  });

  if (!user) {
    return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
  }

  if (user.emailMfaEnabled) {
    return NextResponse.json(
      { success: false, error: 'Email MFA is already enabled. Disable it first.' },
      { status: 409 },
    );
  }

  try {
    await sendEmailOtp(auth.sub, user.email);
  } catch (err) {
    console.error('[EmailMFA] Failed to send OTP during setup:', err);
    return NextResponse.json(
      { success: false, error: 'Failed to send verification email. Please try again.' },
      { status: 502 },
    );
  }

  return NextResponse.json({
    success: true,
    message: 'Verification code sent to your email',
  });
}

// ── DELETE: Disable email MFA ─────────────────────────────────────────────────
// Requires either a valid email OTP ({ code }) or account password ({ password }).

interface DisableEmailMfaBody {
  code?: string;
  password?: string;
}

export async function DELETE(req: NextRequest) {
  const ip = await getClientIp();
  const rateLimitResponse = await enforceRateLimit('mfa', ip);
  if (rateLimitResponse) return rateLimitResponse;

  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  let body: DisableEmailMfaBody;
  try {
    body = (await req.json()) as DisableEmailMfaBody;
  } catch {
    return NextResponse.json({ success: false, error: 'Invalid request body' }, { status: 400 });
  }

  const { code, password } = body;

  if (!code && !password) {
    return NextResponse.json(
      { success: false, error: 'Provide either a verification code or your account password.' },
      { status: 400 },
    );
  }

  const user = await db.user.findUnique({
    where:  { id: auth.sub },
    select: { emailMfaEnabled: true, passwordHash: true },
  });

  if (!user) {
    return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
  }

  if (!user.emailMfaEnabled) {
    return NextResponse.json(
      { success: false, error: 'Email MFA is not enabled.' },
      { status: 409 },
    );
  }

  // Verify identity via OTP or password
  let verified = false;

  if (code) {
    verified = await verifyEmailOtp(auth.sub, code);
  } else if (password) {
    verified = await bcrypt.compare(password, user.passwordHash);
  }

  if (!verified) {
    const ctx = await buildAuditContext(auth.sub);
    await logAuditEvent('AUTH_MFA_CHALLENGE_FAILED', {
      ...ctx,
      metadata: { method: 'email' },
    });
    return NextResponse.json(
      { success: false, error: 'Invalid verification code or password.' },
      { status: 401 },
    );
  }

  await db.user.update({
    where: { id: auth.sub },
    data:  { emailMfaEnabled: false },
  });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('AUTH_MFA_DISABLED', {
    ...ctx,
    metadata: { method: 'email' },
  });

  return NextResponse.json({
    success: true,
    message: 'Email MFA disabled',
  });
}
