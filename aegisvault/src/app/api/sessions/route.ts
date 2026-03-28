/**
 * GET    /api/sessions  — List active sessions
 * DELETE /api/sessions  — Revoke all sessions (logout everywhere)
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { getUserSessions, revokeAllSessions } from '@/lib/server/session';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

export async function GET(_req: NextRequest) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  const sessions = await getUserSessions(auth.sub);
  return NextResponse.json({ success: true, data: { sessions } });
}

export async function DELETE(_req: NextRequest) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  const count = await revokeAllSessions(auth.sub);
  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('AUTH_ALL_SESSIONS_REVOKED', { ...ctx, metadata: { count } });

  return NextResponse.json({
    success: true,
    data: { message: `Revoked ${count} sessions`, count },
  });
}
