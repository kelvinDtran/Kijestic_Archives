/**
 * POST /api/auth/webauthn/authenticate/verify
 *
 * Complete WebAuthn passkey authentication.
 * Verifies the authenticator response, updates the credential counter,
 * creates a session, and sets auth cookies.
 *
 * Body: { response: AuthenticationResponseJSON, preAuthToken: string }
 * Response: user info (tokens are in httpOnly cookies)
 */

import { NextRequest, NextResponse } from 'next/server';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import type { AuthenticationResponseJSON, AuthenticatorTransportFuture } from '@simplewebauthn/server';
import { jwtVerify } from 'jose';
import { z } from 'zod';
import { db } from '@/lib/server/db';
import { logAuditEvent } from '@/lib/server/audit';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';
import { createSessionAndSetCookies } from '@/lib/server/session';

const RP_ID  = process.env.APP_DOMAIN ?? 'localhost';
const ORIGIN = process.env.APP_ORIGIN ?? `https://${RP_ID}`;

function loadJwtSecret(): Uint8Array {
  const secret = process.env.JWT_ACCESS_SECRET;
  if (!secret) {
    throw new Error('JWT_ACCESS_SECRET environment variable is not set. Refusing to start.');
  }
  return new TextEncoder().encode(secret);
}

const ACCESS_SECRET = loadJwtSecret();

const BodySchema = z.object({
  response:      z.object({}).passthrough(),
  preAuthToken:  z.string().min(1),
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

  const { response, preAuthToken } = parsed.data;
  const authResponse = response as AuthenticationResponseJSON;

  // ── Verify preAuthToken ────────────────────────────────────────────────────
  let userId: string;

  try {
    const { payload } = await jwtVerify(preAuthToken, ACCESS_SECRET);

    if (payload['purpose'] !== 'pre-auth') {
      return NextResponse.json(
        { success: false, error: 'Invalid pre-auth token' },
        { status: 401 },
      );
    }

    if (typeof payload.sub !== 'string' || !payload.sub) {
      return NextResponse.json(
        { success: false, error: 'Invalid pre-auth token' },
        { status: 401 },
      );
    }

    userId = payload.sub;
  } catch {
    return NextResponse.json(
      { success: false, error: 'Pre-auth token is invalid or has expired' },
      { status: 401 },
    );
  }

  // ── Look up the credential ─────────────────────────────────────────────────
  const storedCredential = await db.webAuthnCredential.findUnique({
    where:   { credentialId: authResponse.id },
    include: { user: { select: { id: true, email: true, lockTimeout: true } } },
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

  // ── Confirm credential belongs to the pre-auth user ───────────────────────
  if (storedCredential.userId !== userId) {
    await logAuditEvent('AUTH_WEBAUTHN_CHALLENGE_SUCCESS', {
      ip,
      userAgent,
      userId,
      metadata: { success: false, reason: 'credential_user_mismatch' },
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
      userId,
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
      userId,
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
        lockTimeout: user.lockTimeout,
      },
    },
  });
}
