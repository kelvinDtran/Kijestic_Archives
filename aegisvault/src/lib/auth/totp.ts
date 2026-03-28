/**
 * AegisVault — TOTP (Time-based One-Time Password) Utilities
 *
 * Implements RFC 6238 TOTP for MFA support.
 * The TOTP secret is stored server-side, encrypted at rest with SERVER_ENCRYPTION_KEY.
 *
 * Security notes:
 *   - TOTP secrets are server-side knowledge, not user-controlled
 *   - They are encrypted at rest in the database
 *   - Backup codes are hashed (bcrypt) before storage, shown once to user
 *   - The encryption here uses AES-256-GCM via Node's built-in crypto
 *     (NOT the vault key — this is server-side storage encryption)
 */

import { TOTP } from 'otpauth';
import QRCode from 'qrcode';
import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'crypto';
import bcrypt from 'bcryptjs';

// ── TOTP Configuration ────────────────────────────────────────────────────────

const APP_NAME = process.env.APP_NAME ?? 'AegisVault';
const TOTP_PERIOD = 30;
const TOTP_DIGITS = 6;
const TOTP_ALGORITHM = 'SHA1';  // Standard for TOTP apps (Authy, Google Authenticator, etc.)
const TOTP_WINDOW = 1;           // Allow 1 period before/after for clock skew

// ── Secret Generation ─────────────────────────────────────────────────────────

/**
 * Generate a new TOTP secret for a user.
 * Returns the raw secret (to display to user via QR code) and
 * the encrypted version (to store in DB).
 */
export async function generateTotpSecret(email: string): Promise<{
  secret: string;          // base32 secret for display/QR
  encryptedSecret: string; // encrypted for DB storage
  qrCodeUrl: string;       // data URL for QR code
}> {
  const totp = new TOTP({
    issuer:    APP_NAME,
    label:     email,
    algorithm: TOTP_ALGORITHM,
    digits:    TOTP_DIGITS,
    period:    TOTP_PERIOD,
  });

  const secret = totp.secret.base32;
  const otpAuthUrl = totp.toString();

  // Generate QR code as data URL (never make external requests for QR codes —
  // that would expose the TOTP secret to a third-party service)
  const qrCodeUrl = await QRCode.toDataURL(otpAuthUrl, {
    errorCorrectionLevel: 'H',
    margin: 2,
    width: 256,
  });

  const encryptedSecret = encryptTotpSecret(secret);

  return { secret, encryptedSecret, qrCodeUrl };
}

// ── TOTP Verification ─────────────────────────────────────────────────────────

/**
 * Verify a TOTP code against the encrypted secret.
 * Allows ±1 period window for clock skew.
 */
export function verifyTotpCode(encryptedSecret: string, code: string): boolean {
  try {
    const secret = decryptTotpSecret(encryptedSecret);
    const totp = new TOTP({
      issuer:    APP_NAME,
      algorithm: TOTP_ALGORITHM,
      digits:    TOTP_DIGITS,
      period:    TOTP_PERIOD,
      secret,
    });

    // delta null means invalid; 0 = current window, ±1 = adjacent windows
    const delta = totp.validate({ token: code, window: TOTP_WINDOW });
    return delta !== null;
  } catch {
    return false;
  }
}

// ── Backup Codes ──────────────────────────────────────────────────────────────

const BACKUP_CODE_COUNT = 8;
const BACKUP_CODE_LENGTH = 10;

/**
 * Generate backup recovery codes.
 * Returns plain codes (shown once to user) and bcrypt hashes (stored in DB).
 */
export async function generateBackupCodes(): Promise<{
  plainCodes: string[];
  hashedCodes: string[];
}> {
  const plainCodes: string[] = [];
  const hashedCodes: string[] = [];

  for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
    const raw = randomBytes(6).toString('hex').slice(0, BACKUP_CODE_LENGTH).toUpperCase();
    const formatted = raw.slice(0, 5) + '-' + raw.slice(5);
    const hash = await bcrypt.hash(formatted, 10);
    plainCodes.push(formatted);
    hashedCodes.push(hash);
  }

  return { plainCodes, hashedCodes };
}

/**
 * Verify a backup code against a list of hashed codes.
 * Returns the index of the matching code (to mark it as used), or -1.
 */
export async function verifyBackupCode(
  code: string,
  hashedCodes: string[],
): Promise<number> {
  for (let i = 0; i < hashedCodes.length; i++) {
    if (await bcrypt.compare(code.toUpperCase(), hashedCodes[i])) {
      return i;
    }
  }
  return -1;
}

// ── TOTP Secret Encryption (Server-Side at Rest) ──────────────────────────────
// This uses AES-256-GCM to encrypt TOTP secrets stored in the database.
// This is separate from vault encryption — it's a server-side key protecting
// a server-side secret.

const SERVER_KEY = (() => {
  const key = process.env.SERVER_ENCRYPTION_KEY;
  if (!key && process.env.NODE_ENV === 'production') {
    throw new Error('SERVER_ENCRYPTION_KEY environment variable is required in production');
  }
  // Derive a 32-byte key from the env var using SHA-256
  return createHash('sha256')
    .update(key ?? 'insecure-dev-key-change-in-production')
    .digest();
})();

function encryptTotpSecret(plaintext: string): string {
  const iv = randomBytes(12);  // 96-bit IV for AES-GCM
  const cipher = createCipheriv('aes-256-gcm', SERVER_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Format: hex(iv) + ':' + hex(tag) + ':' + hex(ciphertext)
  return `${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

function decryptTotpSecret(ciphertext: string): string {
  const parts = ciphertext.split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted TOTP secret format');
  const [ivHex, tagHex, encHex] = parts;
  const iv       = Buffer.from(ivHex,  'hex');
  const tag      = Buffer.from(tagHex, 'hex');
  const enc      = Buffer.from(encHex, 'hex');
  const decipher = createDecipheriv('aes-256-gcm', SERVER_KEY, iv);
  decipher.setAuthTag(tag);
  return decipher.update(enc, undefined, 'utf8') + decipher.final('utf8');
}
