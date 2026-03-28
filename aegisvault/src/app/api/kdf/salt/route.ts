/**
 * GET /api/kdf/salt
 *
 * Returns the authenticated user's KDF parameters needed for client-side
 * master key derivation.
 *
 * These parameters are NOT secret — they're stored server-side solely to
 * allow the client to reproduce the same derived key on any authenticated device.
 *
 * The KDF salt is analogous to a password hash salt: it prevents pre-computation
 * attacks but is not itself a secret.
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';

export async function GET(_req: NextRequest) {
  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  const user = await db.user.findUnique({
    where:  { id: auth.sub },
    select: {
      kdfSalt:        true,
      kdfVersion:     true,
      kdfMemory:      true,
      kdfIterations:  true,
      kdfParallelism: true,
    },
  });

  if (!user) {
    return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
  }

  return NextResponse.json({
    success: true,
    data: {
      salt:        user.kdfSalt,
      version:     user.kdfVersion,
      memory:      user.kdfMemory,
      iterations:  user.kdfIterations,
      parallelism: user.kdfParallelism,
    },
  });
}
