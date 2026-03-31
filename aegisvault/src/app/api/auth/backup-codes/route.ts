/**
 * GET  /api/auth/backup-codes  — Count how many valid (unused) backup codes remain
 * POST /api/auth/backup-codes  — Generate 8 new backup codes (replaces all existing ones)
 */

import { NextRequest, NextResponse } from 'next/server';
import { randomBytes } from 'crypto';
import bcrypt from 'bcryptjs';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

const BACKUP_CODE_COUNT = 8;
const BCRYPT_COST       = 10;

// ── Helpers ───────────────────────────────────────────────────────────────────

function generateBackupCodes(count = BACKUP_CODE_COUNT): string[] {
  return Array.from({ length: count }, () => {
    const raw = randomBytes(16).toString('base64url').slice(0, 20).toUpperCase();
    return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}-${raw.slice(16, 20)}`;
  });
}

// ── GET: Count remaining valid backup codes ───────────────────────────────────

export async function GET(_req: NextRequest): Promise<NextResponse> {
  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  const remaining = await db.backupCode.count({
    where: { userId: auth.sub, usedAt: null },
  });

  return NextResponse.json({
    success: true,
    data: { remaining, total: BACKUP_CODE_COUNT },
  });
}

// ── POST: Regenerate backup codes ─────────────────────────────────────────────

export async function POST(_req: NextRequest): Promise<NextResponse> {
  const ip = await getClientIp();
  const limited = await enforceRateLimit('api', ip);
  if (limited) return limited as NextResponse;

  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  const plainCodes = generateBackupCodes();

  // Hash all codes concurrently
  const hashedCodes = await Promise.all(
    plainCodes.map((code) => bcrypt.hash(code, BCRYPT_COST)),
  );

  // Delete all existing backup codes for this user, then insert new ones
  await db.backupCode.deleteMany({ where: { userId: auth.sub } });

  await db.backupCode.createMany({
    data: hashedCodes.map((codeHash) => ({
      userId:   auth.sub,
      codeHash,
    })),
  });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('ACCOUNT_SETTINGS_UPDATED', {
    ...ctx,
    metadata: { action: 'backup_codes_regenerated' },
  });

  return NextResponse.json({
    success: true,
    data: { codes: plainCodes },
  });
}
