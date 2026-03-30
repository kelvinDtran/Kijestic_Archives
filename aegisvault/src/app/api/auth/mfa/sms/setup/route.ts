/**
 * POST   /api/auth/mfa/sms/setup  — Start SMS MFA setup (saves phone, sends OTP)
 * DELETE /api/auth/mfa/sms/setup  — Disable SMS MFA (verify current OTP or password)
 */

import { NextRequest, NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { sendSmsOtp, verifySmsOtp } from '@/lib/auth/sms-otp';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

// E.164 phone number regex
const E164_REGEX = /^\+[1-9]\d{1,14}$/;

// ── POST: Start SMS MFA setup ─────────────────────────────────────────────────

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
    typeof (body as Record<string, unknown>).phoneNumber !== 'string'
  ) {
    return NextResponse.json(
      { success: false, error: 'phoneNumber is required' },
      { status: 400 },
    );
  }

  const phoneNumber = ((body as Record<string, unknown>).phoneNumber as string).trim();

  if (!E164_REGEX.test(phoneNumber)) {
    return NextResponse.json(
      { success: false, error: 'phoneNumber must be in E.164 format (e.g. +16025551234)' },
      { status: 400 },
    );
  }

  const user = await db.user.findUnique({
    where:  { id: auth.sub },
    select: { smsEnabled: true },
  });

  if (!user) {
    return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
  }

  if (user.smsEnabled) {
    return NextResponse.json(
      { success: false, error: 'SMS MFA is already enabled. Disable it first.' },
      { status: 409 },
    );
  }

  // Persist the phone number (not yet activated — smsEnabled stays false until verified)
  await db.user.update({
    where: { id: auth.sub },
    data:  { phoneNumber },
  });

  try {
    await sendSmsOtp(auth.sub, phoneNumber);
  } catch (err) {
    console.error('[SMS MFA Setup] Failed to send OTP:', err);
    return NextResponse.json(
      { success: false, error: 'Failed to send verification code. Please try again.' },
      { status: 502 },
    );
  }

  return NextResponse.json({
    success: true,
    message: 'Verification code sent',
  });
}

// ── DELETE: Disable SMS MFA ───────────────────────────────────────────────────

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

  const payload = body as Record<string, unknown>;
  const providedCode     = typeof payload.code     === 'string' ? payload.code     : null;
  const providedPassword = typeof payload.password === 'string' ? payload.password : null;

  if (!providedCode && !providedPassword) {
    return NextResponse.json(
      { success: false, error: 'Either code or password is required to disable SMS MFA' },
      { status: 400 },
    );
  }

  const user = await db.user.findUnique({
    where:  { id: auth.sub },
    select: { smsEnabled: true, passwordHash: true },
  });

  if (!user) {
    return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
  }

  if (!user.smsEnabled) {
    return NextResponse.json(
      { success: false, error: 'SMS MFA is not enabled' },
      { status: 409 },
    );
  }

  // Verify identity: accept either the current SMS OTP or the account password
  let verified = false;

  if (providedCode) {
    verified = await verifySmsOtp(auth.sub, providedCode);
  } else if (providedPassword) {
    verified = await bcrypt.compare(providedPassword, user.passwordHash);
  }

  if (!verified) {
    const ctx = await buildAuditContext(auth.sub);
    await logAuditEvent('AUTH_MFA_CHALLENGE_FAILED', {
      ...ctx,
      metadata: { mfaType: 'SMS', action: 'disable' },
    });
    return NextResponse.json(
      { success: false, error: 'Invalid code or password' },
      { status: 401 },
    );
  }

  await db.user.update({
    where: { id: auth.sub },
    data:  { smsEnabled: false, phoneNumber: null },
  });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('AUTH_MFA_DISABLED', { ...ctx, metadata: { mfaType: 'SMS' } });

  return NextResponse.json({ success: true, message: 'SMS MFA disabled' });
}
