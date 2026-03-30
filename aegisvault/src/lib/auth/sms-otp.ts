/**
 * AegisVault — SMS OTP Utilities (Twilio)
 *
 * Sends and verifies 6-digit SMS OTP codes for MFA.
 *
 * Security design:
 *   - Codes are cryptographically random (crypto.randomInt)
 *   - Stored as bcrypt hashes — plaintext is never persisted
 *   - TTL: 10 minutes
 *   - One active OTP per user at a time (previous codes are deleted before creating new)
 *   - Expired codes are cleaned up on every verify call
 */

import { randomInt } from 'crypto';
import bcrypt from 'bcryptjs';
import twilio from 'twilio';
import { db } from '../server/db';

// ── Twilio Configuration ──────────────────────────────────────────────────────

function loadTwilioConfig(): { accountSid: string; authToken: string; phoneNumber: string } {
  const accountSid  = process.env.TWILIO_ACCOUNT_SID;
  const authToken   = process.env.TWILIO_AUTH_TOKEN;
  const phoneNumber = process.env.TWILIO_PHONE_NUMBER;

  if (process.env.NODE_ENV !== 'test') {
    if (!accountSid)  throw new Error('TWILIO_ACCOUNT_SID environment variable is not set.');
    if (!authToken)   throw new Error('TWILIO_AUTH_TOKEN environment variable is not set.');
    if (!phoneNumber) throw new Error('TWILIO_PHONE_NUMBER environment variable is not set.');
  }

  return {
    accountSid:  accountSid  ?? '',
    authToken:   authToken   ?? '',
    phoneNumber: phoneNumber ?? '',
  };
}

const TWILIO_CONFIG = loadTwilioConfig();

// Lazy-init the Twilio client so tests that set NODE_ENV=test can import
// this module without a real Twilio config.
let _twilioClient: ReturnType<typeof twilio> | null = null;

function getTwilioClient(): ReturnType<typeof twilio> {
  if (!_twilioClient) {
    _twilioClient = twilio(TWILIO_CONFIG.accountSid, TWILIO_CONFIG.authToken);
  }
  return _twilioClient;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const OTP_TTL_MS   = 10 * 60 * 1000; // 10 minutes
const BCRYPT_ROUNDS = 10;

// ── Send SMS OTP ──────────────────────────────────────────────────────────────

/**
 * Generate a 6-digit OTP, store its bcrypt hash in OtpCode, and send via Twilio SMS.
 *
 * Deletes any pre-existing SMS OTP for this user before creating a new one
 * so there is never more than one active code per user.
 */
export async function sendSmsOtp(userId: string, phoneNumber: string): Promise<void> {
  const code = randomInt(100000, 1000000).toString(); // [100000, 999999]
  const codeHash = await bcrypt.hash(code, BCRYPT_ROUNDS);
  const expiresAt = new Date(Date.now() + OTP_TTL_MS);

  // Delete all previous SMS OTPs for this user (enforce one active code at a time)
  await db.otpCode.deleteMany({
    where: { userId, type: 'SMS' },
  });

  await db.otpCode.create({
    data: {
      userId,
      codeHash,
      type:      'SMS',
      expiresAt,
    },
  });

  await getTwilioClient().messages.create({
    body: `Your AegisVault verification code is: ${code}. It expires in 10 minutes. Do not share this code.`,
    from: TWILIO_CONFIG.phoneNumber,
    to:   phoneNumber,
  });
}

// ── Verify SMS OTP ────────────────────────────────────────────────────────────

/**
 * Verify a submitted 6-digit code against the stored bcrypt hash.
 *
 * - Finds the most recent unused, unexpired SMS OTP for the user.
 * - On success: marks the code as used.
 * - Always cleans up expired codes for this user.
 * - Returns true if the code matches, false otherwise.
 */
export async function verifySmsOtp(userId: string, code: string): Promise<boolean> {
  const now = new Date();

  // Clean up expired codes (best-effort — do not block on failure)
  db.otpCode
    .deleteMany({ where: { userId, type: 'SMS', expiresAt: { lt: now } } })
    .catch(() => { /* non-critical cleanup */ });

  const otpRecord = await db.otpCode.findFirst({
    where: {
      userId,
      type:      'SMS',
      usedAt:    null,
      expiresAt: { gte: now },
    },
    orderBy: { createdAt: 'desc' },
  });

  if (!otpRecord) return false;

  const isValid = await bcrypt.compare(code, otpRecord.codeHash);

  if (isValid) {
    await db.otpCode.update({
      where: { id: otpRecord.id },
      data:  { usedAt: now },
    });
  }

  return isValid;
}
