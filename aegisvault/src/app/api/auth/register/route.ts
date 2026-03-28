/**
 * POST /api/auth/register
 *
 * Creates a new user account.
 * The KDF salt is generated and sent by the CLIENT during registration,
 * so the client can immediately derive the vault key without a second round-trip.
 *
 * SECURITY NOTES:
 *   - The master password and derived keys are NEVER sent to this endpoint.
 *   - Only the KDF parameters (salt, version, cost params) are stored.
 *   - The account password is hashed with bcrypt before storage.
 *   - Rate limited to prevent account enumeration.
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { db } from '@/lib/server/db';
import { hashAccountPassword } from '@/lib/auth/password';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';
import { enforceRateLimit, getClientIp } from '@/lib/server/rate-limit';
import { createSessionAndSetCookies } from '@/lib/server/session';

const RegisterSchema = z.object({
  email: z
    .string()
    .email('Invalid email address')
    .max(254, 'Email too long')
    .toLowerCase()
    .trim(),
  password: z
    .string()
    .min(8, 'Account password must be at least 8 characters')
    .max(128, 'Password too long'),
  // KDF parameters — generated client-side
  kdfSalt:        z.string().regex(/^[0-9a-f]{64}$/, 'Invalid KDF salt'),
  kdfVersion:     z.number().int().min(1).max(10),
  kdfMemory:      z.number().int().min(16384).max(1048576),  // 16 MB – 1 GB
  kdfIterations:  z.number().int().min(1).max(100),
  kdfParallelism: z.number().int().min(1).max(16),
});

export async function POST(req: NextRequest) {
  // ── Rate limiting ──────────────────────────────────────────────────────────
  const ip = await getClientIp();
  const limited = await enforceRateLimit('register', ip);
  if (limited) return limited;

  // ── Parse and validate input ───────────────────────────────────────────────
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ success: false, error: 'Invalid request body' }, { status: 400 });
  }

  const parsed = RegisterSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { success: false, error: 'Validation failed', details: parsed.error.flatten() },
      { status: 400 },
    );
  }

  const { email, password, kdfSalt, kdfVersion, kdfMemory, kdfIterations, kdfParallelism } =
    parsed.data;

  // ── Check email uniqueness ─────────────────────────────────────────────────
  // Use a timing-safe approach: always hash the password before checking existence
  // to prevent timing-based email enumeration
  const [passwordHash, existingUser] = await Promise.all([
    hashAccountPassword(password),
    db.user.findUnique({ where: { email }, select: { id: true } }),
  ]);

  if (existingUser) {
    // Don't reveal that the email exists — return a generic message
    // Add artificial delay to match the timing of a successful registration
    await new Promise((r) => setTimeout(r, 200));
    return NextResponse.json(
      { success: false, error: 'Unable to create account. Please try again.' },
      { status: 409 },
    );
  }

  // ── Create user ────────────────────────────────────────────────────────────
  const user = await db.user.create({
    data: {
      email,
      passwordHash,
      kdfSalt,
      kdfVersion,
      kdfMemory,
      kdfIterations,
      kdfParallelism,
    },
    select: { id: true, email: true, createdAt: true },
  });

  // ── Create session ─────────────────────────────────────────────────────────
  const userAgent = req.headers.get('user-agent') ?? undefined;
  await createSessionAndSetCookies({
    userId:    user.id,
    email:     user.email,
    userAgent,
    ip,
  });

  // ── Audit log ──────────────────────────────────────────────────────────────
  const ctx = await buildAuditContext(user.id);
  await logAuditEvent('AUTH_REGISTER', { ...ctx, metadata: { method: 'email' } });

  return NextResponse.json(
    {
      success: true,
      data: {
        user: { id: user.id, email: user.email },
        // Signal to client that they should go through the onboarding flow
        isNewUser: true,
      },
    },
    { status: 201 },
  );
}
