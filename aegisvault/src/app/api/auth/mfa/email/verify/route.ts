/**
 * POST /api/auth/mfa/email/verify — Complete email MFA setup
 *
 * Verifies the OTP sent during setup (/api/auth/mfa/email/setup POST)
 * and, on success, activates emailMfaEnabled on the user record.
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { verifyEmailOtp } from '@/lib/auth/email-otp';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

interface VerifyEmailMfaBody {
  code: string;
}

export async function POST(req: NextRequest) {
  const ip = await getClientIp();
  const rateLimitResponse = await enforceRateLimit('mfa', ip);
  if (rateLimitResponse) return rateLimitResponse;

  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  let body: VerifyEmailMfaBody;
  try {
    body = (await req.json()) as VerifyEmailMfaBody;
  } catch {
    return NextResponse.json({ success: false, error: 'Invalid request body' }, { status: 400 });
  }

  const { code } = body;

  if (!code || typeof code !== 'string') {
    return NextResponse.json(
      { success: false, error: 'Verification code is required.' },
      { status: 400 },
    );
  }

  const user = await db.user.findUnique({
    where:  { id: auth.sub },
    select: { emailMfaEnabled: true },
  });

  if (!user) {
    return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
  }

  if (user.emailMfaEnabled) {
    return NextResponse.json(
      { success: false, error: 'Email MFA is already enabled.' },
      { status: 409 },
    );
  }

  const isValid = await verifyEmailOtp(auth.sub, code);

  if (!isValid) {
    const ctx = await buildAuditContext(auth.sub);
    await logAuditEvent('AUTH_MFA_CHALLENGE_FAILED', {
      ...ctx,
      metadata: { method: 'email' },
    });
    return NextResponse.json(
      { success: false, error: 'Invalid or expired verification code.' },
      { status: 401 },
    );
  }

  await db.user.update({
    where: { id: auth.sub },
    data:  { emailMfaEnabled: true },
  });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('AUTH_MFA_ENABLED', {
    ...ctx,
    metadata: { method: 'email' },
  });

  return NextResponse.json({
    success: true,
    message: 'Email MFA enabled',
  });
}
