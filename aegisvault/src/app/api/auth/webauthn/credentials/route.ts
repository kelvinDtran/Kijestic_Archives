/**
 * GET /api/auth/webauthn/credentials
 *
 * List all WebAuthn credentials (passkeys) for the authenticated user.
 * Returns only safe metadata — never the public key bytes.
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';

export async function GET(_req: NextRequest) {
  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  const credentials = await db.webAuthnCredential.findMany({
    where:   { userId: auth.sub },
    orderBy: { createdAt: 'desc' },
    select: {
      id:           true,
      name:         true,
      deviceType:   true,
      backedUp:     true,
      transports:   true,
      createdAt:    true,
      lastUsedAt:   true,
    },
  });

  return NextResponse.json({ success: true, data: { credentials } });
}
