/**
 * WhatsApp OTP via Meta WhatsApp Cloud API
 *
 * Free tier: 1,000 service conversations/month
 * Setup: developers.facebook.com → create app → WhatsApp product
 * Requires: WHATSAPP_API_TOKEN, WHATSAPP_PHONE_NUMBER_ID
 *
 * Unlike Telegram, no bot/webhook needed for sending OTPs.
 * Just send to the user's WhatsApp-registered phone number.
 */

import { randomInt } from 'crypto';
import bcrypt from 'bcryptjs';
import { db } from '../server/db';

// ── WhatsApp Configuration ────────────────────────────────────────────────────

function loadWhatsAppConfig(): { apiToken: string; phoneNumberId: string } | null {
  const apiToken     = process.env.WHATSAPP_API_TOKEN;
  const phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;

  if (!apiToken || !phoneNumberId) return null;  // Optional — not required to run

  return { apiToken, phoneNumberId };
}

// ── Constants ─────────────────────────────────────────────────────────────────

const OTP_TTL_MS    = 10 * 60 * 1000; // 10 minutes
const BCRYPT_ROUNDS = 10;

// ── Send WhatsApp OTP ─────────────────────────────────────────────────────────

/**
 * Generate a 6-digit OTP, store its bcrypt hash in OtpCode, and send via WhatsApp.
 *
 * Deletes any pre-existing WHATSAPP OTP for this user before creating a new one
 * so there is never more than one active code per user.
 *
 * @param userId      - The authenticated user's ID
 * @param phoneNumber - E.164-formatted phone number (e.g. +16025551234)
 */
export async function sendWhatsAppOtp(userId: string, phoneNumber: string): Promise<void> {
  const config = loadWhatsAppConfig();
  if (!config) {
    throw new Error(
      'WhatsApp MFA is not configured (WHATSAPP_API_TOKEN or WHATSAPP_PHONE_NUMBER_ID missing)',
    );
  }

  const code     = randomInt(100000, 1000000).toString(); // [100000, 999999]
  const codeHash = await bcrypt.hash(code, BCRYPT_ROUNDS);
  const expiresAt = new Date(Date.now() + OTP_TTL_MS);

  // Delete all previous WHATSAPP OTPs for this user (enforce one active code at a time)
  await db.otpCode.deleteMany({
    where: { userId, type: 'WHATSAPP' },
  });

  await db.otpCode.create({
    data: {
      userId,
      codeHash,
      type:      'WHATSAPP',
      expiresAt,
    },
  });

  const url = `https://graph.facebook.com/v18.0/${config.phoneNumberId}/messages`;

  const res = await fetch(url, {
    method:  'POST',
    headers: {
      'Authorization': `Bearer ${config.apiToken}`,
      'Content-Type':  'application/json',
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      to:                phoneNumber,
      type:              'text',
      text: {
        body: `🔐 Your AegisVault recovery code: ${code}\n\nExpires in 10 minutes. Never share this code with anyone.`,
      },
    }),
  });

  if (!res.ok) {
    throw new Error('Failed to send WhatsApp message. Please check your WhatsApp number and try again.');
  }
}

// ── Verify WhatsApp OTP ───────────────────────────────────────────────────────

/**
 * Verify a submitted 6-digit code against the stored bcrypt hash.
 *
 * - Finds the most recent unused, unexpired WHATSAPP OTP for the user.
 * - On success: marks the code as used.
 * - Returns true if the code matches, false otherwise.
 *
 * @param userId    - The authenticated user's ID
 * @param plainCode - The 6-digit code entered by the user
 */
export async function verifyWhatsAppOtp(userId: string, plainCode: string): Promise<boolean> {
  const now = new Date();

  const otpRecord = await db.otpCode.findFirst({
    where: {
      userId,
      type:      'WHATSAPP',
      usedAt:    null,
      expiresAt: { gte: now },
    },
    orderBy: { createdAt: 'desc' },
  });

  if (!otpRecord) return false;

  const isValid = await bcrypt.compare(plainCode, otpRecord.codeHash);

  if (isValid) {
    await db.otpCode.update({
      where: { id: otpRecord.id },
      data:  { usedAt: now },
    });
  }

  return isValid;
}
