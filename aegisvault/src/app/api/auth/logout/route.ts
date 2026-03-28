/**
 * POST /api/auth/logout
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuthFromRequest, clearAuthCookies, hashToken } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

export async function POST(req: NextRequest) {
  const auth = await getAuthFromRequest();

  if (auth) {
    // Revoke the current session by JTI
    await db.session.updateMany({
      where: { accessTokenJti: auth.jti, userId: auth.sub },
      data:  { isRevoked: true },
    });
    const ctx = await buildAuditContext(auth.sub);
    await logAuditEvent('AUTH_LOGOUT', ctx);
  }

  await clearAuthCookies();

  return NextResponse.json({ success: true, data: { message: 'Logged out successfully' } });
}
