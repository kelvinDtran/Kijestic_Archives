/**
 * DELETE /api/sessions/[id]  — Revoke a specific session
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { revokeSession } from '@/lib/server/session';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

type Params = { params: Promise<{ id: string }> };

export async function DELETE(_req: NextRequest, { params }: Params) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const success = await revokeSession(id, auth.sub);

  if (!success) {
    return NextResponse.json({ success: false, error: 'Session not found' }, { status: 404 });
  }

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('AUTH_SESSION_REVOKED', { ...ctx, metadata: { sessionId: id } });

  return NextResponse.json({ success: true, data: { message: 'Session revoked' } });
}
