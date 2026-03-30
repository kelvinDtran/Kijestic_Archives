/**
 * POST /api/auth/webauthn/register
 *
 * Start WebAuthn passkey registration for the currently authenticated user.
 * Generates a registration challenge and returns PublicKeyCredentialCreationOptions.
 *
 * Requires: valid session (access token cookie)
 * Response: { options } — pass to @simplewebauthn/browser startRegistration()
 */

import { NextRequest, NextResponse } from 'next/server';
import { generateRegistrationOptions } from '@simplewebauthn/server';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';
import { db } from '@/lib/server/db';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';

const RP_ID   = process.env.APP_DOMAIN ?? 'localhost';
const RP_NAME = 'AegisVault';
const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes

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

  // ── Fetch user and existing credentials ───────────────────────────────────
  const user = await db.user.findUnique({
    where:  { id: auth.sub },
    select: { id: true, email: true },
  });
  if (!user) {
    return NextResponse.json({ success: false, error: 'User not found' }, { status: 404 });
  }

  const existingCredentials = await db.webAuthnCredential.findMany({
    where:  { userId: user.id },
    select: { credentialId: true, transports: true },
  });

  // ── Generate registration options ──────────────────────────────────────────
  const options = await generateRegistrationOptions({
    rpName:          RP_NAME,
    rpID:            RP_ID,
    userName:        user.email,
    userDisplayName: user.email,
    userID:          new TextEncoder().encode(user.id),
    attestationType: 'none',
    excludeCredentials: existingCredentials.map((c) => ({
      id:         c.credentialId,
      transports: c.transports as AuthenticatorTransportFuture[],
    })),
    authenticatorSelection: {
      residentKey:      'preferred',
      userVerification: 'preferred',
      // authenticatorAttachment intentionally omitted — allowing both platform
      // (fingerprint / Face ID) and cross-platform (phone via hybrid QR transport)
      // authenticators. The browser will display the QR-code option automatically.
    },
  });

  // ── Store challenge ────────────────────────────────────────────────────────
  // Clean up expired challenges first (best-effort)
  db.webAuthnChallenge
    .deleteMany({ where: { expiresAt: { lt: new Date() } } })
    .catch(() => {/* non-critical */});

  await db.webAuthnChallenge.create({
    data: {
      userId:    user.id,
      challenge: options.challenge,
      type:      'registration',
      expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
    },
  });

  return NextResponse.json({ success: true, data: { options } });
}
