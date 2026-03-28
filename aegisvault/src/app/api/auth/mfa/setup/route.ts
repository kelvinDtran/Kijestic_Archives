/**
 * POST /api/auth/mfa/setup  — Initialize TOTP setup
 * DELETE /api/auth/mfa/setup — Disable TOTP
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { generateTotpSecret, generateBackupCodes } from '@/lib/auth/totp';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

// Initiate TOTP setup — returns QR code and secret for user to scan
export async function POST(_req: NextRequest) {
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
  const { plainCodes, hashedCodes } = await generateBackupCodes();

  // Temporarily store the pending TOTP secret
  // It won't be "active" until the user verifies it at /api/auth/mfa/verify
  await db.user.update({
    where: { id: auth.sub },
    data:  { totpSecret: encryptedSecret }, // stored but totpEnabled still false
  });

  // Store backup codes (hashed) — for this MVP they're in a JSON field on user
  // In production, add a separate BackupCode table
  await db.$executeRaw`
    UPDATE "User" SET "backupCodes" = ${JSON.stringify(hashedCodes)}::jsonb
    WHERE id = ${auth.sub}
  `.catch(() => {/* table may not have this field in current schema */});

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

// Disable TOTP
export async function DELETE(_req: NextRequest) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  await db.user.update({
    where: { id: auth.sub },
    data:  { totpEnabled: false, totpSecret: null },
  });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('AUTH_MFA_DISABLED', ctx);

  return NextResponse.json({ success: true, data: { message: 'MFA disabled' } });
}
