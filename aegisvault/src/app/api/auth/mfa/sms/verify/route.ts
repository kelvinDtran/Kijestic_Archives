/**
 * POST /api/auth/mfa/sms/verify — Complete SMS MFA setup by verifying the OTP
 *
 * The user must have gone through POST /api/auth/mfa/sms/setup first (which
 * saves their phone number and sends the first OTP). This endpoint validates
 * that code and, on success, activates SMS MFA (smsEnabled = true).
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { verifySmsOtp } from '@/lib/auth/sms-otp';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

export async function POST(req: NextRequest): Promise<NextResponse> {
  const ip = await getClientIp();
  const limited = await enforceRateLimit('mfa', ip);
  if (limited) return limited as NextResponse;

  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
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
    typeof (body as Record<string, unknown>).code !== 'string'
  ) {
    return NextResponse.json(
      { success: false, error: 'code is required' },
      { status: 400 },
    );
  }

  const code = ((body as Record<string, unknown>).code as string).trim();

  const user = await db.user.findUnique({
    where:  { id: auth.sub },
    select: { phoneNumber: true, smsEnabled: true },
  });

  if (!user) {
    return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
  }

  if (!user.phoneNumber) {
    return NextResponse.json(
      { success: false, error: 'No phone number on file. Start SMS setup first.' },
      { status: 409 },
    );
  }

  if (user.smsEnabled) {
    return NextResponse.json(
      { success: false, error: 'SMS MFA is already enabled' },
      { status: 409 },
    );
  }

  const isValid = await verifySmsOtp(auth.sub, code);

  if (!isValid) {
    const ctx = await buildAuditContext(auth.sub);
    await logAuditEvent('AUTH_MFA_CHALLENGE_FAILED', {
      ...ctx,
      metadata: { mfaType: 'SMS', action: 'setup_verify' },
    });
    return NextResponse.json(
      { success: false, error: 'Invalid or expired verification code' },
      { status: 401 },
    );
  }

  await db.user.update({
    where: { id: auth.sub },
    data:  { smsEnabled: true },
  });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('AUTH_MFA_ENABLED', { ...ctx, metadata: { mfaType: 'SMS' } });

  return NextResponse.json({ success: true, message: 'SMS MFA enabled' });
}
