/**
 * POST /api/auth/webauthn/authenticate
 *
 * Start WebAuthn passkey authentication (login).
 * Generates an authentication challenge.
 *
 * Does NOT require an active session — this initiates a login.
 *
 * Body: { email?: string }
 *   - If email is provided, returns credential hints for that user (user-present flow).
 *   - If omitted, returns empty allowCredentials (discoverable credential / passkey flow).
 *
 * Response: { options } — pass to @simplewebauthn/browser startAuthentication()
 */

import { NextRequest, NextResponse } from 'next/server';
import { generateAuthenticationOptions } from '@simplewebauthn/server';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';
import { z } from 'zod';
import { db } from '@/lib/server/db';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';

const RP_ID = process.env.APP_DOMAIN ?? 'localhost';
const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes

const BodySchema = z.object({
  email: z.string().email().max(254).toLowerCase().trim().optional(),
});

export async function POST(req: NextRequest) {
  // ── Rate limit ─────────────────────────────────────────────────────────────
  const ip = await getClientIp();
  const limited = await enforceRateLimit('login', ip);
  if (limited) return limited;

  // ── Parse body ─────────────────────────────────────────────────────────────
  let body: unknown;
  try { body = await req.json(); }
  catch { body = {}; }

  const parsed = BodySchema.safeParse(body);
  const email = parsed.success ? parsed.data.email : undefined;

  // ── Optionally look up credentials for email ───────────────────────────────
  let allowCredentials: { id: string; transports: AuthenticatorTransportFuture[] }[] = [];
  let userId: string | null = null;

  if (email) {
    const user = await db.user.findUnique({
      where:  { email },
      select: { id: true },
    });
    // Only populate allowCredentials if user exists — don't reveal user existence
    // via different response shapes; the browser UX is the same either way
    if (user) {
      userId = user.id;
      const creds = await db.webAuthnCredential.findMany({
        where:  { userId: user.id },
        select: { credentialId: true, transports: true },
      });
      allowCredentials = creds.map((c) => ({
        id:         c.credentialId,
        transports: c.transports as AuthenticatorTransportFuture[],
      }));
    }
  }

  // ── Generate authentication options ───────────────────────────────────────
  const options = await generateAuthenticationOptions({
    rpID:              RP_ID,
    userVerification:  'required',
    allowCredentials,
  });

  // ── Store challenge ────────────────────────────────────────────────────────
  db.webAuthnChallenge
    .deleteMany({ where: { expiresAt: { lt: new Date() } } })
    .catch(() => {/* non-critical */});

  await db.webAuthnChallenge.create({
    data: {
      userId:    userId,
      challenge: options.challenge,
      type:      'authentication',
      expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
    },
  });

  return NextResponse.json({ success: true, data: { options } });
}
