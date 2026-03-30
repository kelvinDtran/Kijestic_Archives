/**
 * POST /api/auth/mfa/setup  — Initialize TOTP setup
 * DELETE /api/auth/mfa/setup — Disable TOTP
 */

import { NextRequest, NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { generateTotpSecret, generateBackupCodes, verifyTotpCode } from '@/lib/auth/totp';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';

// Initiate TOTP setup — returns QR code and secret for user to scan
export async function POST(_req: NextRequest) {
  const ip = await getClientIp();
  const limitResponse = await enforceRateLimit('mfa', ip);
  if (limitResponse) return limitResponse;

  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  const user = await db.user.findUnique({
    where: { id: auth.sub },
    select: { email: true, totpEnabled: true },
  });

  if (!user) return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
  if (user.totpEnabled) {
    return NextResponse.json(
      { success: false, error: 'MFA is already enabled. Disable it first.' },
      { status: 409 },
    );
  }

  const { secret, encryptedSecret, qrCodeUrl } = await generateTotpSecret(user.email);
  const { plainCodes } = await generateBackupCodes();

  // Temporarily store the pending TOTP secret
  // It won't be "active" until the user verifies it at /api/auth/mfa/verify
  await db.user.update({
    where: { id: auth.sub },
    data:  { totpSecret: encryptedSecret }, // stored but totpEnabled still false
  });

  // Migrate backup codes to the BackupCode table
  await db.backupCode.deleteMany({ where: { userId: auth.sub } });
  const hashedEntries = await Promise.all(
    plainCodes.map(async (code) => ({
      userId:   auth.sub,
      codeHash: await bcrypt.hash(code, 10),
    })),
  );
  await db.backupCode.createMany({ data: hashedEntries });

  return NextResponse.json({
    success: true,
    data: {
      // The QR code URL is a data: URL (no external request) — safe to send
      qrCodeUrl,
      // Also return the raw secret for users who can't scan QR codes
      secret,
      // Backup codes shown ONCE — user must save these now
      backupCodes: plainCodes,
    },
  });
}

// Disable TOTP — requires TOTP code or account password for verification
export async function DELETE(req: NextRequest) {
  const ip = await getClientIp();
  const limitResponse = await enforceRateLimit('mfa', ip);
  if (limitResponse) return limitResponse;

  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  let body: unknown;
  try { body = await req.json(); }
  catch { body = {}; }

  const { totpCode, password } = (body ?? {}) as { totpCode?: string; password?: string };

  const user = await db.user.findUnique({
    where:  { id: auth.sub },
    select: { passwordHash: true, totpSecret: true, totpEnabled: true },
  });

  if (!user) return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });

  // Verify identity before disabling MFA
  let verified = false;

  if (totpCode && user.totpSecret) {
    verified = verifyTotpCode(user.totpSecret, totpCode);
  } else if (password && user.passwordHash) {
    verified = await bcrypt.compare(password, user.passwordHash);
  }

  if (!verified) {
    return NextResponse.json(
      { success: false, error: 'Verification required to disable MFA' },
      { status: 403 },
    );
  }

  await db.user.update({
    where: { id: auth.sub },
    data:  { totpEnabled: false, totpSecret: null },
  });

  await db.backupCode.deleteMany({ where: { userId: auth.sub } });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('AUTH_MFA_DISABLED', ctx);

  return NextResponse.json({ success: true, data: { message: 'MFA disabled' } });
}
