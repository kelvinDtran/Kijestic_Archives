/**
 * POST /api/auth/webauthn/register/verify
 *
 * Complete WebAuthn passkey registration.
 * Verifies the authenticator response, stores the new credential, and
 * logs an audit event.
 *
 * Requires: valid session + a pending registration challenge in DB.
 *
 * Body: { response: RegistrationResponseJSON, name?: string }
 */

import { NextRequest, NextResponse } from 'next/server';
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import type { RegistrationResponseJSON } from '@simplewebauthn/server';
import { z } from 'zod';
import { db } from '@/lib/server/db';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';

const RP_ID  = process.env.APP_DOMAIN ?? 'localhost';
const ORIGIN = process.env.APP_ORIGIN ?? `https://${RP_ID}`;

const BodySchema = z.object({
  response: z.record(z.unknown()),
  name:     z.string().max(64).optional(),
});

export async function POST(req: NextRequest) {
  // ── Auth ───────────────────────────────────────────────────────────────────
  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  // ── Rate limit ─────────────────────────────────────────────────────────────
  const ip = await getClientIp();
  const limited = await enforceRateLimit('api', ip);
  if (limited) return limited;

  // ── Parse body ─────────────────────────────────────────────────────────────
  let body: unknown;
  try { body = await req.json(); }
  catch { return NextResponse.json({ success: false, error: 'Invalid request body' }, { status: 400 }); }

  const parsed = BodySchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ success: false, error: 'Validation failed' }, { status: 400 });
  }

  const { response, name } = parsed.data;
  const auditCtx = await buildAuditContext(auth.sub);

  // ── Retrieve and consume challenge ─────────────────────────────────────────
  const challenge = await db.webAuthnChallenge.findFirst({
    where: {
      userId:    auth.sub,
      type:      'registration',
      expiresAt: { gt: new Date() },
    },
    orderBy: { expiresAt: 'desc' },
  });

  if (!challenge) {
    return NextResponse.json(
      { success: false, error: 'No pending registration challenge. Please start over.' },
      { status: 400 },
    );
  }

  // Delete the challenge immediately (single-use)
  await db.webAuthnChallenge.delete({ where: { id: challenge.id } }).catch(() => {/* non-critical */});

  // ── Verify the registration response ──────────────────────────────────────
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response:          response as RegistrationResponseJSON,
      expectedChallenge: challenge.challenge,
      expectedOrigin:    ORIGIN,
      expectedRPID:      RP_ID,
    });
  } catch (err) {
    await logAuditEvent('AUTH_WEBAUTHN_REGISTERED', {
      ...auditCtx,
      metadata: { success: false, reason: 'verification_failed' },
    });
    return NextResponse.json(
      { success: false, error: 'WebAuthn verification failed' },
      { status: 400 },
    );
  }

  if (!verification.verified || !verification.registrationInfo) {
    return NextResponse.json(
      { success: false, error: 'WebAuthn verification failed' },
      { status: 400 },
    );
  }

  const {
    credential,
    credentialDeviceType,
    credentialBackedUp,
  } = verification.registrationInfo;

  // ── Store the new credential ───────────────────────────────────────────────
  const newCredential = await db.webAuthnCredential.create({
    data: {
      userId:       auth.sub,
      credentialId: credential.id,
      publicKey:    Buffer.from(credential.publicKey),
      counter:      credential.counter,
      deviceType:   credentialDeviceType,
      backedUp:     credentialBackedUp,
      transports:   (credential.transports ?? []) as string[],
      name:         name?.trim() || 'Passkey',
    },
    select: {
      id:          true,
      credentialId: true,
      name:        true,
      deviceType:  true,
      backedUp:    true,
      createdAt:   true,
    },
  });

  await logAuditEvent('AUTH_WEBAUTHN_REGISTERED', {
    ...auditCtx,
    metadata: { credentialId: credential.id.slice(0, 8) + '…' },
  });

  return NextResponse.json({
    success: true,
    data:    { credential: newCredential },
  });
}
