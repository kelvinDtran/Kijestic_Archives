/**
 * GET  /api/vault/items  — List all encrypted vault items for the authenticated user
 * POST /api/vault/items  — Create a new encrypted vault item
 *
 * SECURITY: The server only stores and returns ENCRYPTED data.
 * The server CANNOT read vault item contents.
 * Decryption happens entirely on the client after this API returns data.
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';
import type { ItemType } from '@prisma/client';

// ── GET: List encrypted vault items ──────────────────────────────────────────

export async function GET(req: NextRequest) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  const url = new URL(req.url);
  const includeArchived = url.searchParams.get('archived') === 'true';
  const onlyFavorites   = url.searchParams.get('favorites') === 'true';
  const onlyHighRisk    = url.searchParams.get('highRisk') === 'true';
  const itemType        = url.searchParams.get('type') as ItemType | null;

  // Build filter — server-side filtering only on non-sensitive fields
  const where = {
    userId:     auth.sub,
    isArchived: includeArchived ? undefined : false,
    ...(onlyFavorites && { isFavorite: true }),
    ...(onlyHighRisk  && { isHighRisk: true }),
    ...(itemType      && { itemType }),
  };

  const items = await db.vaultItem.findMany({
    where,
    orderBy: { updatedAt: 'desc' },
    select: {
      id:              true,
      itemType:        true,
      isFavorite:      true,
      isArchived:      true,
      isHighRisk:      true,
      encryptedItemKey: true,
      encryptedData:   true,
      createdAt:       true,
      updatedAt:       true,
    },
  });

  return NextResponse.json({ success: true, data: { items } });
}

// ── POST: Create a new encrypted vault item ───────────────────────────────────

const CreateItemSchema = z.object({
  itemType:         z.enum(['PASSWORD','API_KEY','CRYPTO','NOTE','DOCUMENT','RECOVERY_CODE','IMAGE','OTHER']),
  isFavorite:       z.boolean().default(false),
  isHighRisk:       z.boolean().default(false),
  encryptedItemKey: z.string().min(1, 'encryptedItemKey is required').max(512),
  encryptedData:    z.string().min(1, 'encryptedData is required').max(1048576),
});

export async function POST(req: NextRequest) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  let body: unknown;
  try { body = await req.json(); }
  catch { return NextResponse.json({ success: false, error: 'Invalid request body' }, { status: 400 }); }

  const parsed = CreateItemSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { success: false, error: 'Validation failed', details: parsed.error.flatten() },
      { status: 400 },
    );
  }

  const item = await db.vaultItem.create({
    data: {
      userId:          auth.sub,
      itemType:        parsed.data.itemType,
      isFavorite:      parsed.data.isFavorite,
      isHighRisk:      parsed.data.isHighRisk,
      encryptedItemKey: parsed.data.encryptedItemKey,
      encryptedData:   parsed.data.encryptedData,
    },
    select: {
      id:              true,
      itemType:        true,
      isFavorite:      true,
      isArchived:      true,
      isHighRisk:      true,
      encryptedItemKey: true,
      encryptedData:   true,
      createdAt:       true,
      updatedAt:       true,
    },
  });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('VAULT_ITEM_CREATED', {
    ...ctx,
    // Log ONLY non-sensitive metadata — never the encrypted content
    metadata: { itemType: parsed.data.itemType, isHighRisk: parsed.data.isHighRisk },
  });

  return NextResponse.json({ success: true, data: { item } }, { status: 201 });
}
