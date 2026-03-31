/**
 * DELETE /api/auth/mfa/telegram/setup — Disable Telegram MFA
 *
 * Requires either a current Telegram OTP code or the account password.
 * Auth: required.
 * Rate limited.
 */

import { NextRequest, NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { verifyTelegramOtp } from '@/lib/auth/telegram-otp';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

export async function DELETE(req: NextRequest): Promise<NextResponse> {
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

  if (typeof body !== 'object' || body === null) {
    return NextResponse.json(
      { success: false, error: 'Request body must be an object with code or password' },
      { status: 400 },
    );
  }

  const payload          = body as Record<string, unknown>;
  const providedCode     = typeof payload.code     === 'string' ? payload.code     : null;
  const providedPassword = typeof payload.password === 'string' ? payload.password : null;

  if (!providedCode && !providedPassword) {
    return NextResponse.json(
      { success: false, error: 'Either code or password is required to disable Telegram MFA' },
      { status: 400 },
    );
  }

  const user = await db.user.findUnique({
    where:  { id: auth.sub },
    select: { telegramEnabled: true, passwordHash: true },
  });

  if (!user) {
    return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
  }

  if (!user.telegramEnabled) {
    return NextResponse.json(
      { success: false, error: 'Telegram MFA is not enabled' },
      { status: 409 },
    );
  }

  // Verify identity: accept either the current Telegram OTP or the account password
  let verified = false;

  if (providedCode) {
    verified = await verifyTelegramOtp(auth.sub, providedCode);
  } else if (providedPassword) {
    verified = await bcrypt.compare(providedPassword, user.passwordHash);
  }

  if (!verified) {
    const ctx = await buildAuditContext(auth.sub);
    await logAuditEvent('AUTH_MFA_CHALLENGE_FAILED', {
      ...ctx,
      metadata: { mfaType: 'TELEGRAM', action: 'disable' },
    });
    return NextResponse.json(
      { success: false, error: 'Invalid code or password' },
      { status: 401 },
    );
  }

  await db.user.update({
    where: { id: auth.sub },
    data:  { telegramEnabled: false, telegramChatId: null },
  });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('AUTH_MFA_DISABLED', { ...ctx, metadata: { mfaType: 'TELEGRAM' } });

  return NextResponse.json({ success: true, message: 'Telegram MFA disabled' });
}
