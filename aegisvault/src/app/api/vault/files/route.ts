/**
 * POST /api/vault/files
 *
 * Upload an encrypted file.
 * The client encrypts the file before sending — this endpoint only stores
 * the encrypted blob and encrypted metadata.
 *
 * Multipart form fields:
 *   - file:              encrypted file blob (binary)
 *   - encryptedFileKey:  base64-encoded wrapped file key
 *   - encryptedMetadata: base64-encoded encrypted {name, mimeType, size}
 *   - vaultItemId:       (optional) ID of the vault item to attach to
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { uploadEncryptedFile, generateStoragePath } from '@/lib/server/storage';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE ?? '10485760', 10); // 10 MB

export async function POST(req: NextRequest) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  let formData: FormData;
  try { formData = await req.formData(); }
  catch { return NextResponse.json({ success: false, error: 'Invalid multipart form' }, { status: 400 }); }

  const fileField         = formData.get('file');
  const encryptedFileKey  = formData.get('encryptedFileKey');
  const encryptedMetadata = formData.get('encryptedMetadata');
  const vaultItemId       = formData.get('vaultItemId') ?? null;

  if (!(fileField instanceof Blob) || typeof encryptedFileKey !== 'string' || typeof encryptedMetadata !== 'string') {
    return NextResponse.json({ success: false, error: 'Missing required fields' }, { status: 400 });
  }

  // Validate encrypted blob size (not the original size — we don't know that yet)
  if (fileField.size > MAX_FILE_SIZE + 1024) {  // small overhead for encryption metadata
    return NextResponse.json(
      { success: false, error: `File too large. Maximum: ${MAX_FILE_SIZE / (1024 * 1024)} MB` },
      { status: 413 },
    );
  }

  // Verify vault item ownership if provided
  if (vaultItemId && typeof vaultItemId === 'string') {
    const item = await db.vaultItem.findFirst({ where: { id: vaultItemId, userId: auth.sub } });
    if (!item) return NextResponse.json({ success: false, error: 'Vault item not found' }, { status: 404 });
  }

  // Generate a storage path that reveals nothing about the file
  const storagePath = generateStoragePath(auth.sub);

  // Read the encrypted blob
  const encryptedBytes = new Uint8Array(await fileField.arrayBuffer());

  // Upload to storage (encrypted already)
  await uploadEncryptedFile(storagePath, encryptedBytes);

  // Record in database
  const vaultFile = await db.vaultFile.create({
    data: {
      userId:           auth.sub,
      vaultItemId:      typeof vaultItemId === 'string' ? vaultItemId : null,
      encryptedFileKey,
      encryptedMetadata,
      storagePath,
      encryptedSize:    encryptedBytes.length,
    },
    select: {
      id:               true,
      encryptedFileKey: true,
      encryptedMetadata: true,
      encryptedSize:    true,
      storagePath:      true,
      createdAt:        true,
    },
  });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('VAULT_FILE_UPLOADED', {
    ...ctx,
    metadata: { encryptedSize: encryptedBytes.length },
  });

  return NextResponse.json({ success: true, data: { file: vaultFile } }, { status: 201 });
}
