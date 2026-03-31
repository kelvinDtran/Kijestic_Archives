/**
 * Telegram Bot MFA
 *
 * Uses the Telegram Bot API to deliver OTP codes.
 * Free, no rate limits, no account verification required.
 *
 * Setup: create a bot via @BotFather → get BOT_TOKEN
 * Users link via: https://t.me/YOUR_BOT_NAME?start=LINK_CODE
 */

import { randomInt } from 'crypto';
import bcrypt from 'bcryptjs';
import { db } from '../server/db';

// ── Telegram Configuration ────────────────────────────────────────────────────

function loadTelegramConfig(): { botToken: string; botName: string } {
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  const botName  = process.env.TELEGRAM_BOT_NAME ?? '';

  if (process.env.NODE_ENV !== 'test') {
    if (!botToken) {
      throw new Error('TELEGRAM_BOT_TOKEN environment variable is not set.');
    }
  }

  return {
    botToken: botToken ?? '',
    botName,
  };
}

const TELEGRAM_CONFIG = loadTelegramConfig();

// ── Constants ─────────────────────────────────────────────────────────────────

const OTP_TTL_MS    = 10 * 60 * 1000; // 10 minutes
const LINK_TTL_MS   = 30 * 60 * 1000; // 30 minutes
const BCRYPT_ROUNDS = 10;

// ── Helpers ───────────────────────────────────────────────────────────────────

async function callTelegramApi(method: string, body: Record<string, unknown>): Promise<void> {
  const url = `https://api.telegram.org/bot${TELEGRAM_CONFIG.botToken}/${method}`;
  const res = await fetch(url, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Telegram API error (${method}): ${res.status} ${text}`);
  }
}

function generateAlphanumericCode(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[randomInt(0, chars.length)];
  }
  return result;
}

// ── Send Telegram OTP ─────────────────────────────────────────────────────────

/**
 * Generate a 6-digit OTP, store its bcrypt hash in OtpCode, and send via Telegram.
 *
 * Deletes any pre-existing TELEGRAM OTP for this user before creating a new one
 * so there is never more than one active code per user.
 */
export async function sendTelegramOtp(userId: string, telegramChatId: bigint): Promise<void> {
  const code     = randomInt(100000, 1000000).toString(); // [100000, 999999]
  const codeHash = await bcrypt.hash(code, BCRYPT_ROUNDS);
  const expiresAt = new Date(Date.now() + OTP_TTL_MS);

  // Delete all previous TELEGRAM OTPs for this user (enforce one active code at a time)
  await db.otpCode.deleteMany({
    where: { userId, type: 'TELEGRAM' },
  });

  await db.otpCode.create({
    data: {
      userId,
      codeHash,
      type:      'TELEGRAM',
      expiresAt,
    },
  });

  await callTelegramApi('sendMessage', {
    chat_id: telegramChatId.toString(),
    text:    `🔐 Your AegisVault login code: ${code}\n\nExpires in 10 minutes. Never share this code.`,
  });
}

// ── Verify Telegram OTP ───────────────────────────────────────────────────────

/**
 * Verify a submitted 6-digit code against the stored bcrypt hash.
 *
 * - Finds the most recent unused, unexpired TELEGRAM OTP for the user.
 * - On success: marks the code as used.
 * - Always cleans up expired codes for this user.
 * - Returns true if the code matches, false otherwise.
 */
export async function verifyTelegramOtp(userId: string, plainCode: string): Promise<boolean> {
  const now = new Date();

  // Clean up expired codes (best-effort — do not block on failure)
  db.otpCode
    .deleteMany({ where: { userId, type: 'TELEGRAM', expiresAt: { lt: now } } })
    .catch(() => { /* non-critical cleanup */ });

  const otpRecord = await db.otpCode.findFirst({
    where: {
      userId,
      type:      'TELEGRAM',
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

// ── Generate Telegram Link Code ───────────────────────────────────────────────

/**
 * Generate a 32-char link code and store it as a TELEGRAM OtpCode in the DB.
 * The link code is stored as plaintext in codeHash for direct equality lookup.
 * Expires in 30 minutes.
 *
 * Returns the deep link URL and the raw link code.
 */
export async function generateTelegramLinkCode(userId: string): Promise<{
  linkCode: string;
  deepLink: string;
}> {
  const linkCode  = generateAlphanumericCode(32);
  const expiresAt = new Date(Date.now() + LINK_TTL_MS);

  // Delete any existing (unused) TELEGRAM link codes for this user
  await db.otpCode.deleteMany({
    where: { userId, type: 'TELEGRAM' },
  });

  // Store the plain link code directly in codeHash — we do equality lookup, not bcrypt
  await db.otpCode.create({
    data: {
      userId,
      codeHash:  linkCode,
      type:      'TELEGRAM',
      expiresAt,
    },
  });

  const deepLink = `https://t.me/${TELEGRAM_CONFIG.botName}?start=${linkCode}`;

  return { linkCode, deepLink };
}

// ── Complete Telegram Link ────────────────────────────────────────────────────

/**
 * Called by the webhook when Telegram sends a /start LINK_CODE message.
 * Looks up the link code, links the chat to the user account, and marks the code used.
 *
 * Returns the userId on success, or null if the code is invalid/expired/used.
 */
export async function completeTelegramLink(
  linkCode: string,
  telegramChatId: bigint,
): Promise<string | null> {
  const now = new Date();

  const otpRecord = await db.otpCode.findFirst({
    where: {
      codeHash:  linkCode,
      type:      'TELEGRAM',
      usedAt:    null,
      expiresAt: { gte: now },
    },
  });

  if (!otpRecord) return null;

  // Link the Telegram account and activate Telegram MFA
  await db.user.update({
    where: { id: otpRecord.userId },
    data:  { telegramChatId, telegramEnabled: true },
  });

  // Mark the link code as used
  await db.otpCode.update({
    where: { id: otpRecord.id },
    data:  { usedAt: now },
  });

  return otpRecord.userId;
}
