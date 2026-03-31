/**
 * POST /api/auth/webauthn/authenticate
 *
 * Start WebAuthn passkey authentication (login).
 * Generates an authentication challenge.
 *
 * Does NOT require an active session — this initiates a login.
 *
 * Body: { preAuthToken: string }
 *   - The preAuthToken is a short-lived JWT issued by POST /api/auth/login
 *     after successful password verification.
 *
 * Response: { options } — pass to @simplewebauthn/browser startAuthentication()
 */

import { NextRequest, NextResponse } from 'next/server';
import { generateAuthenticationOptions } from '@simplewebauthn/server';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';
import { jwtVerify } from 'jose';
import { z } from 'zod';
import { db } from '@/lib/server/db';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';

const RP_ID = process.env.APP_DOMAIN ?? 'localhost';
const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function loadJwtSecret(): Uint8Array {
  const secret = process.env.JWT_ACCESS_SECRET;
  if (!secret) {
    throw new Error('JWT_ACCESS_SECRET environment variable is not set. Refusing to start.');
  }
  return new TextEncoder().encode(secret);
}

const ACCESS_SECRET = loadJwtSecret();

const BodySchema = z.object({
  preAuthToken: z.string().min(1),
});

export async function POST(req: NextRequest) {
  // ── Rate limit ─────────────────────────────────────────────────────────────
  const ip = await getClientIp();
  const limited = await enforceRateLimit('login', ip);
  if (limited) return limited;

  // ── Parse body ─────────────────────────────────────────────────────────────
  let body: unknown;
  try { body = await req.json(); }
  catch { return NextResponse.json({ success: false, error: 'Invalid request body' }, { status: 400 }); }

  const parsed = BodySchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ success: false, error: 'Validation failed' }, { status: 400 });
  }

  const { preAuthToken } = parsed.data;

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

  // ── Look up credentials for this user ─────────────────────────────────────
  const credentials = await db.webAuthnCredential.findMany({
    where:  { userId },
    select: { credentialId: true, transports: true },
  });

  const allowCredentials: { id: string; transports: AuthenticatorTransportFuture[] }[] =
    credentials.map((c) => ({
      id:         c.credentialId,
      transports: c.transports as AuthenticatorTransportFuture[],
    }));

  // ── Generate authentication options ───────────────────────────────────────
  const options = await generateAuthenticationOptions({
    rpID:             RP_ID,
    userVerification: 'preferred',
    allowCredentials,
  });

  // ── Store challenge ────────────────────────────────────────────────────────
  db.webAuthnChallenge
    .deleteMany({ where: { expiresAt: { lt: new Date() } } })
    .catch(() => {/* non-critical */});

  await db.webAuthnChallenge.create({
    data: {
      userId,
      challenge: options.challenge,
      type:      'authentication',
      expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
    },
  });

  return NextResponse.json({ success: true, data: { options } });
}
