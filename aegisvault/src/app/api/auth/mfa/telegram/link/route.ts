/**
 * POST /api/auth/mfa/telegram/link — Generate a Telegram link code for MFA setup
 *
 * Returns a deep link that the user opens in Telegram to link their account.
 * Auth: required (must be logged in).
 * Rate limited.
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { generateTelegramLinkCode } from '@/lib/auth/telegram-otp';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';

export async function POST(_req: NextRequest): Promise<NextResponse> {
  const ip = await getClientIp();
  const limited = await enforceRateLimit('mfa', ip);
  if (limited) return limited as NextResponse;

  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const { linkCode, deepLink } = await generateTelegramLinkCode(auth.sub);

    return NextResponse.json({
      success: true,
      data: {
        deepLink,
        linkCode,
        expiresInMinutes: 30,
      },
    });
  } catch (err) {
    console.error('[Telegram MFA Link] Failed to generate link code:', err);
    return NextResponse.json(
      { success: false, error: 'Failed to generate link code. Please try again.' },
      { status: 500 },
    );
  }
}
