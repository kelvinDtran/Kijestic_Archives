/**
 * POST /api/auth/mfa/verify
 *
 * Verify a TOTP code during the setup flow to confirm the user has
 * successfully configured their authenticator app.
 * Activates TOTP on the account.
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { verifyTotpCode } from '@/lib/auth/totp';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';

const VerifySchema = z.object({
  code: z.string().length(6).regex(/^\d{6}$/, 'TOTP code must be 6 digits'),
});

export async function POST(req: NextRequest) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  // Rate limit MFA verification attempts
  const ip = await getClientIp();
  const limited = await enforceRateLimit('mfa', ip);
  if (limited) return limited;

  let body: unknown;
  try { body = await req.json(); }
  catch { return NextResponse.json({ success: false, error: 'Invalid request' }, { status: 400 }); }

  const parsed = VerifySchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ success: false, error: 'Invalid code format' }, { status: 400 });
  }

  const user = await db.user.findUnique({
    where:  { id: auth.sub },
    select: { totpSecret: true, totpEnabled: true },
  });

  if (!user?.totpSecret) {
    return NextResponse.json(
      { success: false, error: 'No pending MFA setup found. Start setup first.' },
      { status: 400 },
    );
  }

  const isValid = verifyTotpCode(user.totpSecret, parsed.data.code);
  const ctx = await buildAuditContext(auth.sub);

  if (!isValid) {
    await logAuditEvent('AUTH_MFA_CHALLENGE_FAILED', { ...ctx, metadata: { step: 'setup_verify' } });
    return NextResponse.json(
      { success: false, error: 'Invalid code. Make sure your authenticator app is synced.' },
      { status: 401 },
    );
  }

  // Activate TOTP
  await db.user.update({
    where: { id: auth.sub },
    data:  { totpEnabled: true },
  });

  await logAuditEvent('AUTH_MFA_ENABLED', ctx);

  return NextResponse.json({ success: true, data: { message: 'MFA enabled successfully' } });
}
