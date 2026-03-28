/**
 * AegisVault — Account Password Hashing (Server-Side Only)
 *
 * This module handles the ACCOUNT password — used for authentication only.
 * It is completely separate from the master password used for vault encryption.
 *
 * Algorithm: bcrypt with cost factor 12
 *   - Industry standard for password hashing
 *   - Cost 12 → ~250ms per hash on modern hardware
 *   - OWASP minimum recommendation is cost 10; we use 12 for extra margin
 *
 * IMPORTANT DISTINCTION:
 *   - Account password → this module → bcrypt hash stored in DB
 *   - Master password  → kdf.ts     → Argon2id → master key (never stored)
 */

import bcrypt from 'bcryptjs';

const BCRYPT_ROUNDS = 12;

/**
 * Hash an account password for storage in the database.
 * This should ONLY be called with the account password, never the master password.
 */
export async function hashAccountPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

/**
 * Verify an account password against a stored bcrypt hash.
 * Returns true if the password matches, false otherwise.
 * bcrypt.compare is timing-safe by design.
 */
export async function verifyAccountPassword(
  password: string,
  hash: string,
): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

/**
 * Validate account password strength requirements.
 * These are UX-level checks — the crypto doesn't depend on them,
 * but weak account passwords weaken the authentication layer.
 */
export function validatePasswordStrength(password: string): {
  valid: boolean;
  score: number;  // 0-4
  feedback: string[];
} {
  const feedback: string[] = [];
  let score = 0;

  if (password.length >= 8)  score++;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  // Normalize to 0-4
  score = Math.min(4, Math.floor(score * 4 / 6));

  if (password.length < 8) {
    feedback.push('At least 8 characters required');
  }
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password)) {
    feedback.push('Use both uppercase and lowercase letters');
  }
  if (!/[0-9]/.test(password)) {
    feedback.push('Add at least one number');
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    feedback.push('Add at least one special character');
  }

  return { valid: password.length >= 8, score, feedback };
}

/**
 * Validate master password strength.
 * Stronger requirements than account password since it protects all vault data.
 */
export function validateMasterPasswordStrength(password: string): {
  valid: boolean;
  score: number;
  feedback: string[];
} {
  const feedback: string[] = [];
  let score = 0;

  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (password.length >= 24) score++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  score = Math.min(4, Math.floor(score * 4 / 6));

  if (password.length < 12) {
    feedback.push('Master password requires at least 12 characters');
  }
  if (password.length < 16) {
    feedback.push('16+ characters strongly recommended for vault master password');
  }
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password)) {
    feedback.push('Use both uppercase and lowercase letters');
  }
  if (!/[0-9]/.test(password)) {
    feedback.push('Include at least one number');
  }

  return { valid: password.length >= 12, score, feedback };
}
