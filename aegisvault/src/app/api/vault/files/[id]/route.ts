/**
 * GET    /api/vault/files/[id]  — Download encrypted file blob
 * DELETE /api/vault/files/[id]  — Delete file
 */

import { NextRequest, NextResponse } from 'next/server';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { downloadEncryptedFile, deleteEncryptedFile } from '@/lib/server/storage';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

type Params = { params: Promise<{ id: string }> };

export async function GET(_req: NextRequest, { params }: Params) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const file = await db.vaultFile.findFirst({
    where: { id, userId: auth.sub },
    select: { storagePath: true, encryptedFileKey: true, encryptedMetadata: true, encryptedSize: true },
  });

  if (!file) return NextResponse.json({ success: false, error: 'Not found' }, { status: 404 });

  // Download the encrypted blob from storage
  const encryptedBytes = await downloadEncryptedFile(file.storagePath);

  // Return the encrypted blob — the client will decrypt it
  return new NextResponse(encryptedBytes, {
    status: 200,
    headers: {
      'Content-Type':   'application/octet-stream',
      'Content-Length': encryptedBytes.length.toString(),
      // Prevent caching of encrypted files
      'Cache-Control':  'no-store',
      // Return encrypted keys in headers so client can decrypt
      'X-Encrypted-File-Key':  file.encryptedFileKey,
      'X-Encrypted-Metadata':  file.encryptedMetadata,
    },
  });
}

export async function DELETE(_req: NextRequest, { params }: Params) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const file = await db.vaultFile.findFirst({ where: { id, userId: auth.sub } });
  if (!file) return NextResponse.json({ success: false, error: 'Not found' }, { status: 404 });

  await deleteEncryptedFile(file.storagePath).catch(console.error);
  await db.vaultFile.delete({ where: { id } });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('VAULT_FILE_DELETED', ctx);

  return NextResponse.json({ success: true, data: { message: 'File deleted' } });
}
