/**
 * POST /api/auth/mfa/whatsapp/verify — Complete WhatsApp MFA enrollment
 *
 * Verifies the OTP sent during setup (/api/auth/mfa/whatsapp/setup POST)
 * and, on success, activates whatsappEnabled on the user record.
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { verifyWhatsAppOtp } from '@/lib/auth/whatsapp-otp';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

interface VerifyWhatsAppBody {
  code: string;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const ip = await getClientIp();
  const limited = await enforceRateLimit('mfa', ip);
  if (limited) return limited as NextResponse;

  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  let body: VerifyWhatsAppBody;
  try {
    body = (await req.json()) as VerifyWhatsAppBody;
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
    select: { whatsappEnabled: true, whatsappNumber: true },
  });

  if (!user) {
    return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
  }

  if (user.whatsappEnabled) {
    return NextResponse.json(
      { success: false, error: 'WhatsApp MFA is already enabled.' },
      { status: 409 },
    );
  }

  const isValid = await verifyWhatsAppOtp(auth.sub, code);

  if (!isValid) {
    const ctx = await buildAuditContext(auth.sub);
    await logAuditEvent('AUTH_MFA_CHALLENGE_FAILED', {
      ...ctx,
      metadata: { mfaType: 'WHATSAPP', action: 'verify_setup' },
    });
    return NextResponse.json(
      { success: false, error: 'Invalid or expired verification code.' },
      { status: 401 },
    );
  }

  await db.user.update({
    where: { id: auth.sub },
    data:  { whatsappEnabled: true },
  });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('AUTH_MFA_ENABLED', { ...ctx, metadata: { mfaType: 'WHATSAPP' } });

  return NextResponse.json({ success: true, message: 'WhatsApp MFA enabled' });
}
