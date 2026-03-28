/**
 * GET /api/vault/export
 *
 * Returns all encrypted vault items (including archived) for client-side packaging.
 * The client decrypts these, re-packages them with a fresh export key using
 * createExportPackage(), and downloads the result as a .aegisvault file.
 *
 * The server only serves encrypted blobs — it cannot read vault content.
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

export async function GET(req: NextRequest) {
  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  // Fetch ALL items (including archived) for a complete backup
  const items = await db.vaultItem.findMany({
    where:   { userId: auth.sub },
    orderBy: { createdAt: 'asc' },
    select: {
      id:               true,
      itemType:         true,
      isFavorite:       true,
      isArchived:       true,
      isHighRisk:       true,
      encryptedItemKey: true,
      encryptedData:    true,
      createdAt:        true,
      updatedAt:        true,
    },
  });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('VAULT_EXPORTED', {
    ...ctx,
    metadata: { itemCount: items.length },
  });

  return NextResponse.json({ success: true, data: { items } });
}
