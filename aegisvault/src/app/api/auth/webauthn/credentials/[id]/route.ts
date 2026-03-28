/**
 * PATCH /api/auth/webauthn/credentials/[id]  — Rename a passkey
 * DELETE /api/auth/webauthn/credentials/[id] — Remove a passkey
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { db } from '@/lib/server/db';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

type Params = { params: Promise<{ id: string }> };

export async function PATCH(req: NextRequest, { params }: Params) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;

  let body: unknown;
  try { body = await req.json(); }
  catch { return NextResponse.json({ success: false, error: 'Invalid request body' }, { status: 400 }); }

  const parsed = z.object({ name: z.string().min(1).max(64) }).safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ success: false, error: 'Validation failed' }, { status: 400 });
  }

  const credential = await db.webAuthnCredential.findFirst({ where: { id, userId: auth.sub } });
  if (!credential) return NextResponse.json({ success: false, error: 'Not found' }, { status: 404 });

  await db.webAuthnCredential.update({ where: { id }, data: { name: parsed.data.name.trim() } });

  return NextResponse.json({ success: true });
}

export async function DELETE(_req: NextRequest, { params }: Params) {
  const auth = await getAuthFromRequest();
  if (!auth) return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  const credential = await db.webAuthnCredential.findFirst({ where: { id, userId: auth.sub } });
  if (!credential) return NextResponse.json({ success: false, error: 'Not found' }, { status: 404 });

  // Prevent removing the last passkey if it's the only auth method
  // (user can still use email+password, so this is just a UX guard — not enforced)

  await db.webAuthnCredential.delete({ where: { id } });

  const ctx = await buildAuditContext(auth.sub);
  await logAuditEvent('AUTH_WEBAUTHN_REMOVED', { ...ctx });

  return NextResponse.json({ success: true });
}
