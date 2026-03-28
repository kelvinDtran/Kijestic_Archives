/**
 * AegisVault — Symmetric Authenticated Encryption
 *
 * Algorithm: XChaCha20-Poly1305
 *   - XChaCha20: stream cipher, 256-bit key, 192-bit (24-byte) extended nonce
 *   - Poly1305: authentication tag (128-bit / 16 bytes)
 *   - Together: AEAD (Authenticated Encryption with Associated Data)
 *
 * Why XChaCha20-Poly1305 over AES-256-GCM?
 *   - Nonce is 192-bit (vs 96-bit in AES-GCM) → safe for random nonce generation
 *     even with billions of messages (GCM's 96-bit nonce risks collision at ~2^32 msgs)
 *   - No hardware requirement → consistent performance across all devices
 *   - Side-channel resistant by design (no table lookups)
 *   - Widely used and audited (libsodium uses this for secretbox)
 *
 * Wire format (all stored/transmitted values):
 *   base64( nonce[24] || ciphertext[N] || poly1305_tag[16] )
 *
 * SECURITY INVARIANTS:
 *   1. Each encrypt() call generates a fresh random nonce. NEVER reuse nonces.
 *   2. decrypt() will throw if the authentication tag is invalid (tamper detection).
 *   3. Do NOT catch DecryptionError unless you explicitly handle the failure case.
 *   4. Keys MUST be exactly 32 bytes.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from '@noble/hashes/utils';
import { concatBytes } from '@noble/ciphers/utils';

// ── Constants ─────────────────────────────────────────────────────────────────

const NONCE_SIZE = 24; // XChaCha20 requires 24-byte nonce
const TAG_SIZE   = 16; // Poly1305 authentication tag size
const KEY_SIZE   = 32; // 256-bit key

// ── Core Encrypt/Decrypt ──────────────────────────────────────────────────────

/**
 * Encrypt plaintext bytes with XChaCha20-Poly1305.
 *
 * Returns: Uint8Array of nonce[24] || ciphertext[N] || tag[16]
 * A new random nonce is generated for every call.
 *
 * @param key - 32-byte encryption key (item DEK or vault VEK)
 * @param plaintext - arbitrary bytes to encrypt
 */
export function encrypt(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (key.length !== KEY_SIZE) {
    throw new Error(`Encryption key must be ${KEY_SIZE} bytes, got ${key.length}`);
  }

  // Generate a cryptographically random 192-bit nonce.
  // With 192-bit nonces, random generation is safe even for 2^80 messages
  // (birthday bound is 2^96, effectively infinite for practical use).
  const nonce = randomBytes(NONCE_SIZE);

  const cipher = xchacha20poly1305(key, nonce);
  // cipher.encrypt returns ciphertext concatenated with 16-byte Poly1305 tag
  const ciphertext = cipher.encrypt(plaintext);

  // Prepend nonce so the recipient can extract it for decryption
  return concatBytes(nonce, ciphertext);
}

/**
 * Decrypt data produced by encrypt().
 *
 * Expects: nonce[24] || ciphertext[N] || tag[16]
 * Throws DecryptionError if the authentication tag is invalid (data tampered or wrong key).
 *
 * @param key - 32-byte encryption key (must match key used for encryption)
 * @param data - raw encrypted bytes (output of encrypt())
 */
export function decrypt(key: Uint8Array, data: Uint8Array): Uint8Array {
  if (key.length !== KEY_SIZE) {
    throw new Error(`Decryption key must be ${KEY_SIZE} bytes, got ${key.length}`);
  }
  if (data.length < NONCE_SIZE + TAG_SIZE) {
    throw new Error(
      `Ciphertext too short: ${data.length} bytes. Minimum is ${NONCE_SIZE + TAG_SIZE}.`,
    );
  }

  const nonce = data.subarray(0, NONCE_SIZE);
  const ciphertextWithTag = data.subarray(NONCE_SIZE);

  const cipher = xchacha20poly1305(key, nonce);
  // This throws if the Poly1305 tag verification fails (authentication failure)
  // Do NOT silently ignore this error — it means the data was tampered with
  // or the wrong key was used.
  return cipher.decrypt(ciphertextWithTag);
}

// ── String Helpers ────────────────────────────────────────────────────────────

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Encrypt a UTF-8 string. Returns base64-encoded result.
 * Suitable for storing in database TEXT columns.
 */
export function encryptString(key: Uint8Array, plaintext: string): string {
  const bytes = encoder.encode(plaintext);
  const encrypted = encrypt(key, bytes);
  return Buffer.from(encrypted).toString('base64');
}

/**
 * Decrypt a base64-encoded ciphertext string.
 * Inverse of encryptString().
 */
export function decryptString(key: Uint8Array, ciphertextB64: string): string {
  const data = Buffer.from(ciphertextB64, 'base64');
  const decrypted = decrypt(key, new Uint8Array(data));
  return decoder.decode(decrypted);
}

/**
 * Encrypt a JSON-serializable value. Returns base64-encoded ciphertext.
 * Used for encrypting vault item data blobs.
 */
export function encryptJSON<T>(key: Uint8Array, value: T): string {
  return encryptString(key, JSON.stringify(value));
}

/**
 * Decrypt and JSON-parse a ciphertext. Inverse of encryptJSON().
 */
export function decryptJSON<T>(key: Uint8Array, ciphertextB64: string): T {
  const json = decryptString(key, ciphertextB64);
  return JSON.parse(json) as T;
}

// ── Key Generation ────────────────────────────────────────────────────────────

/**
 * Generate a random 32-byte Data Encryption Key (DEK).
 * Call this once per vault item at creation time.
 * The DEK must then be wrapped (encrypted) with the VEK before storage.
 */
export function generateItemKey(): Uint8Array {
  return randomBytes(KEY_SIZE);
}

/**
 * Generate a random 32-byte file encryption key.
 * Same as generateItemKey() but named for clarity.
 */
export function generateFileKey(): Uint8Array {
  return randomBytes(KEY_SIZE);
}

// ── Timing-Safe Comparison ────────────────────────────────────────────────────

/**
 * Compare two byte arrays in constant time to prevent timing attacks.
 * Use this when comparing MACs, tokens, or other security-critical values.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
