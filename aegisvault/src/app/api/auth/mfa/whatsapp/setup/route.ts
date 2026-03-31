/**
 * POST   /api/auth/mfa/whatsapp/setup — Save phone number and send verification OTP
 * DELETE /api/auth/mfa/whatsapp/setup — Disable WhatsApp MFA
 */

import { NextRequest, NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { sendWhatsAppOtp, verifyWhatsAppOtp } from '@/lib/auth/whatsapp-otp';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

// E.164 phone number format: + followed by 1–15 digits, first digit 1–9
const E164_REGEX = /^\+[1-9]\d{1,14}$/;

// ── POST: Initiate WhatsApp MFA setup ─────────────────────────────────────────

interface SetupWhatsAppBody {
  phoneNumber: string;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const ip = await getClientIp();
  const limited = await enforceRateLimit('mfa', ip);
  if (limited) return limited as NextResponse;

  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  // Guard: WhatsApp must be configured server-side
  if (
    !process.env.WHATSAPP_API_TOKEN ||
    !process.env.WHATSAPP_PHONE_NUMBER_ID
  ) {
    return NextResponse.json(
      { success: false, error: 'WhatsApp MFA is not configured on this server' },
      { status: 503 },
    );
  }

  let body: SetupWhatsAppBody;
  try {
    body = (await req.json()) as SetupWhatsAppBody;
  } catch {
    return NextResponse.json({ success: false, error: 'Invalid request body' }, { status: 400 });
  }

  const { phoneNumber } = body;

  if (!phoneNumber || typeof phoneNumber !== 'string' || !E164_REGEX.test(phoneNumber)) {
    return NextResponse.json(
      {
        success: false,
        error: 'phoneNumber must be in E.164 format (e.g. +16025551234)',
      },
      { status: 400 },
    );
  }

  // Save phone number to user (even before verification)
  await db.user.update({
    where: { id: auth.sub },
    data:  { whatsappNumber: phoneNumber },
  });

  try {
    await sendWhatsAppOtp(auth.sub, phoneNumber);
  } catch (err) {
    return NextResponse.json(
      {
        success: false,
        error:   err instanceof Error ? err.message : 'Failed to send WhatsApp verification code.',
      },
      { status: 502 },
    );
  }

  return NextResponse.json({
    success: true,
    message: 'Verification code sent to your WhatsApp',
  });
}

// ── DELETE: Disable WhatsApp MFA ──────────────────────────────────────────────

interface DisableWhatsAppBody {
  code?: string;
  password?: string;
}

export async function DELETE(req: NextRequest): Promise<NextResponse> {
  const ip = await getClientIp();
  const limited = await enforceRateLimit('mfa', ip);
  if (limited) return limited as NextResponse;

  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  let body: DisableWhatsAppBody;
  try {
    body = (await req.json()) as DisableWhatsAppBody;
  } catch {
    return NextResponse.json({ success: false, error: 'Invalid request body' }, { status: 400 });
  }

  const { code, password } = body;

  if (!code && !password) {
    return NextResponse.json(
      {
        success: false,
        error: 'Either a verification code or your account password is required to disable WhatsApp MFA',
      },
      { status: 400 },
    );
  }

  const user = await db.user.findUnique({
    where:  { id: auth.sub },
    select: { whatsappEnabled: true, passwordHash: true },
  });

  if (!user) {
    return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
  }

  if (!user.whatsappEnabled) {
    return NextResponse.json(
      { success: false, error: 'WhatsApp MFA is not enabled' },
      { status: 409 },
    );
  }

  // Verify identity: accept either the current WhatsApp OTP or the account password
  let verified = false;

  if (code) {
    verified = await verifyWhatsAppOtp(auth.sub, code);
  } else if (password) {
    verified = await bcrypt.compare(password, user.passwordHash);
  }

  if (!verified) {
    const ctx = await buildAuditContext(auth.sub);
    await logAuditEvent('AUTH_MFA_CHALLENGE_FAILED', {
      ...ctx,
      metadata: { mfaType: 'WHATSAPP', action: 'disable' },
    });
    return NextResponse.json(
      { success: false, error: 'Invalid code or password' },
      { status: 401 },
    );
  }

  await db.user.update({
    where: { id: auth.sub },
    data:  { whatsappEnabled: false, whatsappNumber: null },
  });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('AUTH_MFA_DISABLED', { ...ctx, metadata: { mfaType: 'WHATSAPP' } });

  return NextResponse.json({ success: true, message: 'WhatsApp MFA disabled' });
}
