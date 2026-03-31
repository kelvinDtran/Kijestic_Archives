/**
 * AegisVault — Email OTP Utilities (via Resend)
 *
 * Generates a 6-digit OTP, bcrypt-hashes it, stores it in the OtpCode table,
 * and delivers it to the user's account email through Resend.
 *
 * Security notes:
 *   - Codes are generated with crypto.randomInt (CSPRNG)
 *   - Codes are bcrypt-hashed at cost 10 before DB storage — never stored plaintext
 *   - Only one active EMAIL OTP per user at a time (old codes are deleted before insert)
 *   - Codes expire after 10 minutes
 *   - verifyEmailOtp marks the code as usedAt on success (single-use)
 */

import { randomInt } from 'crypto';
import bcrypt from 'bcryptjs';
import { Resend } from 'resend';
import { db } from '../server/db';

// ── Config ────────────────────────────────────────────────────────────────────

const RESEND_FROM_EMAIL =
  process.env.RESEND_FROM_EMAIL ?? 'AegisVault <noreply@aegisvault.app>';

const OTP_EXPIRY_MINUTES = 10;
const BCRYPT_COST = 10;

// ── Email Template ────────────────────────────────────────────────────────────

function buildEmailHtml(code: string): string {
  return `
<div style="font-family: system-ui; max-width: 400px; margin: 0 auto; padding: 24px;">
  <h2 style="color: #1a1a2e;">AegisVault Security Code</h2>
  <p>Your verification code is:</p>
  <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #6366f1; padding: 16px; background: #f5f5ff; border-radius: 8px; text-align: center;">
    ${code}
  </div>
  <p style="color: #666; font-size: 14px;">This code expires in 10 minutes. Never share it with anyone.</p>
  <p style="color: #666; font-size: 14px;">If you didn't request this, your account may be at risk. Change your password immediately.</p>
</div>
  `.trim();
}

// ── Send OTP ──────────────────────────────────────────────────────────────────

/**
 * Generate a 6-digit OTP, hash it, persist it in the OtpCode table,
 * and send it to the user's email via Resend.
 *
 * Any existing active EMAIL OTPs for the user are deleted first so only
 * one code is valid at a time.
 *
 * @param userId - The authenticated user's ID
 * @param email  - The user's account email address (used as the delivery destination)
 */
export async function sendEmailOtp(userId: string, email: string): Promise<void> {
  const RESEND_API_KEY = process.env.RESEND_API_KEY;
  if (!RESEND_API_KEY) {
    throw new Error('Email MFA is not configured (RESEND_API_KEY missing)');
  }

  const resend = new Resend(RESEND_API_KEY);

  const plainCode = String(randomInt(100000, 999999));
  const codeHash  = await bcrypt.hash(plainCode, BCRYPT_COST);
  const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

  // Delete any existing EMAIL OTPs for this user before creating a new one
  await db.otpCode.deleteMany({
    where: {
      userId,
      type: 'EMAIL',
    },
  });

  await db.otpCode.create({
    data: {
      userId,
      codeHash,
      type:      'EMAIL',
      expiresAt,
    },
  });

  const { error } = await resend.emails.send({
    from:    RESEND_FROM_EMAIL,
    to:      email,
    subject: 'Your AegisVault verification code',
    html:    buildEmailHtml(plainCode),
  });

  if (error) {
    throw new Error(`Failed to send email OTP: ${error.message}`);
  }
}

// ── Verify OTP ────────────────────────────────────────────────────────────────

/**
 * Verify a 6-digit email OTP for the given user.
 *
 * Looks up the most recent unused, unexpired EMAIL OTP for the user,
 * compares the plaintext code against the stored hash, and marks it as
 * used on success.
 *
 * @param userId    - The authenticated user's ID
 * @param plainCode - The 6-digit code entered by the user
 * @returns true if the code is valid; false otherwise
 */
export async function verifyEmailOtp(userId: string, plainCode: string): Promise<boolean> {
  const now = new Date();

  const otpRecord = await db.otpCode.findFirst({
    where: {
      userId,
      type:      'EMAIL',
      usedAt:    null,
      expiresAt: { gt: now },
    },
    orderBy: { createdAt: 'desc' },
  });

  if (!otpRecord) {
    return false;
  }

  const isValid = await bcrypt.compare(plainCode, otpRecord.codeHash);

  if (!isValid) {
    return false;
  }

  // Mark as used (single-use)
  await db.otpCode.update({
    where: { id: otpRecord.id },
    data:  { usedAt: now },
  });

  return true;
}
