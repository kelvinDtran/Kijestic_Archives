/**
 * GET /api/audit
 *
 * Returns the authenticated user's security event log.
 * Results are paginated and ordered by most recent first.
 *
 * Query params:
 *   - limit: number of results per page (default 50, max 200)
 *   - cursor: ID of the last result from the previous page (for cursor pagination)
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { getUserAuditLogs } from '@/lib/server/audit';

export async function GET(req: NextRequest) {
  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  const url   = new URL(req.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') ?? '50', 10), 200);

  const logs = await getUserAuditLogs(auth.sub, limit);

  return NextResponse.json({ success: true, data: { logs } });
}
