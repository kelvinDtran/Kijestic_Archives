/**
 * POST /api/vault/import
 *
 * Bulk-import encrypted vault items. The client is responsible for:
 *   1. Reading the .aegisvault export file
 *   2. Decrypting the export package with the user's vault key
 *   3. Re-encrypting each item with the vault key (fresh DEK per item)
 *   4. POSTing the encrypted items here
 *
 * The server only stores encrypted blobs and enforces a per-request item limit.
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

const MAX_IMPORT_ITEMS = 2000;

const ImportItemSchema = z.object({
  itemType:         z.enum(['PASSWORD','API_KEY','CRYPTO','NOTE','DOCUMENT','RECOVERY_CODE','IMAGE','OTHER']),
  isFavorite:       z.boolean(),
  isArchived:       z.boolean(),
  isHighRisk:       z.boolean(),
  encryptedItemKey: z.string().min(1),
  encryptedData:    z.string().min(1),
});

const ImportBodySchema = z.object({
  items: z.array(ImportItemSchema).min(1).max(MAX_IMPORT_ITEMS),
});

export async function POST(req: NextRequest) {
  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  let body: unknown;
  try { body = await req.json(); }
  catch { return NextResponse.json({ success: false, error: 'Invalid request body' }, { status: 400 }); }

  const parsed = ImportBodySchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { success: false, error: 'Validation failed', details: parsed.error.flatten() },
      { status: 400 },
    );
  }

  const { items } = parsed.data;

  // Bulk-create all items in a single transaction
  await db.$transaction(
    items.map((item) =>
      db.vaultItem.create({
        data: {
          userId:           auth.sub,
          itemType:         item.itemType,
          isFavorite:       item.isFavorite,
          isArchived:       item.isArchived,
          isHighRisk:       item.isHighRisk,
          encryptedItemKey: item.encryptedItemKey,
          encryptedData:    item.encryptedData,
        },
      }),
    ),
  );

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('VAULT_IMPORTED', {
    ...ctx,
    metadata: { itemCount: items.length },
  });

  return NextResponse.json({
    success: true,
    data:    { imported: items.length },
  });
}
