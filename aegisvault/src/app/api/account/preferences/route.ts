/**
 * GET /api/account/preferences  — Get user preferences
 * PUT /api/account/preferences  — Update user preferences
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';

export async function GET(_req: NextRequest) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  const user = await db.user.findUnique({
    where:  { id: auth.sub },
    select: {
      lockTimeout:      true,
      totpEnabled:      true,
      smsEnabled:       true,
      phoneNumber:      true,
      emailMfaEnabled:  true,
    },
  });

  if (!user) return NextResponse.json({ success: false, error: 'Not found' }, { status: 404 });

  return NextResponse.json({
    success: true,
    data: {
      lockTimeout:     user.lockTimeout,
      totpEnabled:     user.totpEnabled,
      smsEnabled:      user.smsEnabled,
      phoneNumber:     user.phoneNumber,
      emailMfaEnabled: user.emailMfaEnabled,
    },
  });
}

const PrefsSchema = z.object({
  lockTimeout: z.number().int().min(0).max(86400).optional(),
});

export async function PUT(req: NextRequest) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  let body: unknown;
  try { body = await req.json(); }
  catch { return NextResponse.json({ success: false, error: 'Invalid body' }, { status: 400 }); }

  const parsed = PrefsSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ success: false, error: 'Validation failed' }, { status: 400 });

  await db.user.update({
    where: { id: auth.sub },
    data: {
      ...(parsed.data.lockTimeout !== undefined && { lockTimeout: parsed.data.lockTimeout }),
    },
  });

  return NextResponse.json({ success: true, data: { message: 'Preferences updated' } });
}
