/**
 * POST /api/auth/webauthn/authenticate/verify
 *
 * Complete WebAuthn passkey authentication.
 * Verifies the authenticator response, updates the credential counter,
 * creates a session, and sets auth cookies.
 *
 * Body: { response: AuthenticationResponseJSON }
 * Response: user info (tokens are in httpOnly cookies)
 */

import { NextRequest, NextResponse } from 'next/server';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import type { AuthenticationResponseJSON, AuthenticatorTransportFuture } from '@simplewebauthn/server';
import { z } from 'zod';
import { db } from '@/lib/server/db';
import { logAuditEvent } from '@/lib/server/audit';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';
import { createSessionAndSetCookies } from '@/lib/server/session';

const RP_ID  = process.env.APP_DOMAIN ?? 'localhost';
const ORIGIN = process.env.APP_ORIGIN ?? `https://${RP_ID}`;

const BodySchema = z.object({
  response: z.record(z.unknown()),
});

export async function POST(req: NextRequest) {
  // ── Rate limit ─────────────────────────────────────────────────────────────
  const ip = await getClientIp();
  const limited = await enforceRateLimit('login', ip);
  if (limited) return limited;

  const userAgent = req.headers.get('user-agent') ?? undefined;

  // ── Parse body ─────────────────────────────────────────────────────────────
  let body: unknown;
  try { body = await req.json(); }
  catch { return NextResponse.json({ success: false, error: 'Invalid request body' }, { status: 400 }); }

  const parsed = BodySchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ success: false, error: 'Validation failed' }, { status: 400 });
  }

  const { response } = parsed.data;
  const authResponse = response as AuthenticationResponseJSON;

  // ── Look up the credential ─────────────────────────────────────────────────
  const storedCredential = await db.webAuthnCredential.findUnique({
    where:   { credentialId: authResponse.id },
    include: { user: { select: { id: true, email: true, lockTimeout: true, totpEnabled: true } } },
  });

  if (!storedCredential) {
    await logAuditEvent('AUTH_WEBAUTHN_CHALLENGE_SUCCESS', {
      ip,
      userAgent,
      metadata: { success: false, reason: 'credential_not_found' },
    });
    return NextResponse.json(
      { success: false, error: 'Passkey not recognized' },
      { status: 401 },
    );
  }

  // ── Retrieve and consume the challenge ────────────────────────────────────
  const challenge = await db.webAuthnChallenge.findFirst({
    where: {
      type:      'authentication',
      expiresAt: { gt: new Date() },
      // Accept challenges scoped to this user or discoverable (userId null)
      OR: [
        { userId: storedCredential.userId },
        { userId: null },
      ],
    },
    orderBy: { expiresAt: 'desc' },
  });

  if (!challenge) {
    return NextResponse.json(
      { success: false, error: 'No pending authentication challenge. Please start over.' },
      { status: 400 },
    );
  }

  // Delete challenge immediately (single-use)
  await db.webAuthnChallenge.delete({ where: { id: challenge.id } }).catch(() => {/* non-critical */});

  // ── Verify the authentication response ────────────────────────────────────
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response:          authResponse,
      expectedChallenge: challenge.challenge,
      expectedOrigin:    ORIGIN,
      expectedRPID:      RP_ID,
      credential: {
        id:         storedCredential.credentialId,
        publicKey:  new Uint8Array(storedCredential.publicKey),
        counter:    Number(storedCredential.counter),
        transports: storedCredential.transports as AuthenticatorTransportFuture[],
      },
    });
  } catch {
    await logAuditEvent('AUTH_WEBAUTHN_CHALLENGE_SUCCESS', {
      ip,
      userAgent,
      userId: storedCredential.userId,
      metadata: { success: false, reason: 'verification_failed' },
    });
    return NextResponse.json(
      { success: false, error: 'Passkey verification failed' },
      { status: 401 },
    );
  }

  if (!verification.verified) {
    return NextResponse.json(
      { success: false, error: 'Passkey verification failed' },
      { status: 401 },
    );
  }

  // ── Update the credential counter (replay attack prevention) ──────────────
  await db.webAuthnCredential.update({
    where: { id: storedCredential.id },
    data: {
      counter:    verification.authenticationInfo.newCounter,
      lastUsedAt: new Date(),
    },
  });

  // ── Create session ─────────────────────────────────────────────────────────
  const user = storedCredential.user;
  await createSessionAndSetCookies({
    userId:    user.id,
    email:     user.email,
    userAgent,
    ip,
  });

  await db.user.update({
    where: { id: user.id },
    data:  { lastLoginAt: new Date() },
  });

  await logAuditEvent('AUTH_WEBAUTHN_CHALLENGE_SUCCESS', {
    ip,
    userAgent,
    userId: user.id,
    metadata: { credentialId: storedCredential.credentialId.slice(0, 8) + '…' },
  });

  return NextResponse.json({
    success: true,
    data: {
      user: {
        id:          user.id,
        email:       user.email,
        totpEnabled: user.totpEnabled,
        lockTimeout: user.lockTimeout,
      },
    },
  });
}
