/**
 * GET /api/auth/mfa/telegram/status — Check if Telegram MFA is linked
 *
 * Used by the settings page to poll for link completion.
 * Auth: required.
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';

export async function GET(_req: NextRequest): Promise<NextResponse> {
  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  const user = await db.user.findUnique({
    where:  { id: auth.sub },
    select: { telegramEnabled: true, telegramChatId: true },
  });

  if (!user) {
    return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
  }

  return NextResponse.json({
    success: true,
    data: {
      linked:  user.telegramEnabled,
      chatId:  user.telegramChatId?.toString() ?? null,
    },
  });
}
