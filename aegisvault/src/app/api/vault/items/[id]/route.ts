/**
 * GET    /api/vault/items/[id]  — Get single encrypted item
 * PUT    /api/vault/items/[id]  — Update encrypted item
 * DELETE /api/vault/items/[id]  — Delete item permanently
 * PATCH  /api/vault/items/[id]  — Update non-sensitive flags (favorite, archive)
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';
import { deleteEncryptedFile } from '@/lib/server/storage';

type Params = { params: Promise<{ id: string }> };

// ── GET ───────────────────────────────────────────────────────────────────────

export async function GET(_req: NextRequest, { params }: Params) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const item = await db.vaultItem.findFirst({
    where:  { id, userId: auth.sub },
    include: {
      files: {
        select: {
          id:               true,
          encryptedFileKey: true,
          encryptedMetadata: true,
          storagePath:      true,
          encryptedSize:    true,
          scanStatus:       true,
          scanDetections:   true,
          scanTotalEngines: true,
          scannedAt:        true,
          createdAt:        true,
        },
      },
    },
  });

  if (!item) return NextResponse.json({ success: false, error: 'Not found' }, { status: 404 });

  return NextResponse.json({ success: true, data: { item } });
}

// ── PUT: Full update (re-encrypted data) ──────────────────────────────────────

const UpdateItemSchema = z.object({
  itemType:         z.enum(['PASSWORD','API_KEY','CRYPTO','NOTE','DOCUMENT','RECOVERY_CODE','IMAGE','OTHER']).optional(),
  isFavorite:       z.boolean().optional(),
  isHighRisk:       z.boolean().optional(),
  encryptedItemKey: z.string().min(1).optional(),
  encryptedData:    z.string().min(1).optional(),
});

export async function PUT(req: NextRequest, { params }: Params) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;

  // Verify ownership
  const existing = await db.vaultItem.findFirst({ where: { id, userId: auth.sub } });
  if (!existing) return NextResponse.json({ success: false, error: 'Not found' }, { status: 404 });

  let body: unknown;
  try { body = await req.json(); }
  catch { return NextResponse.json({ success: false, error: 'Invalid body' }, { status: 400 }); }

  const parsed = UpdateItemSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ success: false, error: 'Validation failed' }, { status: 400 });
  }

  const updated = await db.vaultItem.update({
    where: { id },
    data: {
      ...( parsed.data.itemType         !== undefined && { itemType: parsed.data.itemType }),
      ...( parsed.data.isFavorite       !== undefined && { isFavorite: parsed.data.isFavorite }),
      ...( parsed.data.isHighRisk       !== undefined && { isHighRisk: parsed.data.isHighRisk }),
      ...( parsed.data.encryptedItemKey !== undefined && { encryptedItemKey: parsed.data.encryptedItemKey }),
      ...( parsed.data.encryptedData    !== undefined && { encryptedData: parsed.data.encryptedData }),
    },
    select: {
      id: true, itemType: true, isFavorite: true, isArchived: true,
      isHighRisk: true, encryptedItemKey: true, encryptedData: true,
      createdAt: true, updatedAt: true,
    },
  });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('VAULT_ITEM_UPDATED', {
    ...ctx,
    metadata: { itemType: updated.itemType },
  });

  return NextResponse.json({ success: true, data: { item: updated } });
}

// ── PATCH: Update non-sensitive flags only ────────────────────────────────────

const PatchItemSchema = z.object({
  isFavorite: z.boolean().optional(),
  isArchived: z.boolean().optional(),
});

export async function PATCH(req: NextRequest, { params }: Params) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const existing = await db.vaultItem.findFirst({ where: { id, userId: auth.sub } });
  if (!existing) return NextResponse.json({ success: false, error: 'Not found' }, { status: 404 });

  let body: unknown;
  try { body = await req.json(); }
  catch { return NextResponse.json({ success: false, error: 'Invalid body' }, { status: 400 }); }

  const parsed = PatchItemSchema.safeParse(body);
  if (!parsed.success) return NextResponse.json({ success: false, error: 'Validation failed' }, { status: 400 });

  const updated = await db.vaultItem.update({
    where: { id },
    data: {
      ...(parsed.data.isFavorite !== undefined && { isFavorite: parsed.data.isFavorite }),
      ...(parsed.data.isArchived !== undefined && { isArchived: parsed.data.isArchived }),
    },
    select: { id: true, isFavorite: true, isArchived: true, updatedAt: true },
  });

  if (parsed.data.isArchived) {
    const ctx = await buildAuditContext(auth.sub);
    await logAuditEvent('VAULT_ITEM_ARCHIVED', { ...ctx });
  }

  return NextResponse.json({ success: true, data: { item: updated } });
}

// ── DELETE ────────────────────────────────────────────────────────────────────

export async function DELETE(_req: NextRequest, { params }: Params) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const existing = await db.vaultItem.findFirst({
    where:   { id, userId: auth.sub },
    include: { files: { select: { storagePath: true } } },
  });
  if (!existing) return NextResponse.json({ success: false, error: 'Not found' }, { status: 404 });

  // Delete associated files from storage
  for (const file of existing.files) {
    await deleteEncryptedFile(file.storagePath).catch(console.error);
  }

  await db.vaultItem.delete({ where: { id } });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('VAULT_ITEM_DELETED', {
    ...ctx,
    metadata: { itemType: existing.itemType },
  });

  return NextResponse.json({ success: true, data: { message: 'Item deleted' } });
}
