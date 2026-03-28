/**
 * AegisVault — Key Derivation (KDF)
 *
 * SECURITY CONTRACT:
 * - The master password is ONLY used here, client-side.
 * - The derived masterKey MUST NEVER be sent to the server.
 * - The KDF salt is NOT secret — it's a uniqueness parameter stored server-side
 *   to allow key derivation on any authenticated device.
 *
 * Algorithm: Argon2id
 *   - Memory-hard (64 MB) → defeats GPU/ASIC brute force attacks
 *   - Side-channel resistant (id variant combines i + d modes)
 *   - Recommended by OWASP, RFC 9106, and most modern security guidance
 *
 * Key hierarchy produced here:
 *   masterPassword + kdfSalt → Argon2id → masterKey (256-bit)
 *                                         ↓ HKDF("vault-key")
 *                                     vaultKey (256-bit)
 *                                         Used to encrypt per-item DEKs
 */

import { argon2id } from 'hash-wasm';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { randomBytes } from '@noble/hashes/utils';

// ── Constants ─────────────────────────────────────────────────────────────────

/** Current KDF scheme version — increment when parameters change */
export const KDF_VERSION = 1 as const;

/** Argon2id parameters.
 *  These are deliberately high — expect ~0.5–2s on modern hardware.
 *  IMPORTANT: Changing these breaks existing key derivation for all users.
 *  Use kdfVersion to manage parameter migrations.
 */
export const KDF_PARAMS = {
  parallelism: 4,       // threads (matches CPU core count)
  iterations: 3,        // time cost
  memorySize: 65536,    // 64 MB — main defense against GPU brute-force
  hashLength: 32,       // 256-bit output
} as const;

/** HKDF domain separation label for vault key derivation */
const VAULT_KEY_INFO = 'aegisvault-v1-vault-key';
/** HKDF salt for key derivation (fixed per-application label) */
const HKDF_SALT = 'aegisvault-v1-hkdf-salt';

// ── KDF Salt ──────────────────────────────────────────────────────────────────

export interface KdfSalt {
  version: number;
  salt: string;       // hex-encoded 32-byte random value
  memory: number;
  iterations: number;
  parallelism: number;
}

/**
 * Generate a new random KDF salt.
 * Called ONCE at registration time, stored server-side.
 * Safe to store unencrypted — it is not secret.
 */
export function generateKdfSalt(): KdfSalt {
  const saltBytes = randomBytes(32);
  return {
    version: KDF_VERSION,
    salt: Buffer.from(saltBytes).toString('hex'),
    ...KDF_PARAMS,
  };
}

// ── Master Key Derivation ─────────────────────────────────────────────────────

/**
 * Derive the master encryption key from the master password and per-user salt.
 *
 * This is the CRYPTOGRAPHIC ROOT of the vault.
 * The result MUST NEVER be:
 *   - Sent to the server
 *   - Written to localStorage, sessionStorage, or any disk-backed storage
 *   - Logged or included in error messages
 *
 * @param masterPassword - The user's vault master password (not account password)
 * @param kdfSalt - Per-user salt parameters fetched from the server
 * @returns 32-byte master key as Uint8Array
 */
export async function deriveMasterKey(
  masterPassword: string,
  kdfSalt: KdfSalt,
): Promise<Uint8Array> {
  if (!masterPassword || masterPassword.length === 0) {
    throw new Error('Master password cannot be empty');
  }
  if (kdfSalt.version !== KDF_VERSION) {
    throw new Error(
      `Unsupported KDF version ${kdfSalt.version}. Expected ${KDF_VERSION}.`,
    );
  }

  const saltBytes = Buffer.from(kdfSalt.salt, 'hex');
  if (saltBytes.length !== 32) {
    throw new Error('Invalid KDF salt length — expected 32 bytes');
  }

  // Argon2id is the main line of defense against offline brute-force attacks
  // on the encrypted vault if the database is ever compromised.
  const masterKey = await argon2id({
    password: masterPassword,
    salt: saltBytes,
    parallelism: kdfSalt.parallelism,
    iterations: kdfSalt.iterations,
    memorySize: kdfSalt.memory,
    hashLength: KDF_PARAMS.hashLength,
    outputType: 'binary',
  });

  return new Uint8Array(masterKey);
}

// ── Vault Key Derivation ──────────────────────────────────────────────────────

/**
 * Derive the Vault Encryption Key (VEK) from the master key.
 *
 * The VEK is used to encrypt/decrypt per-item Data Encryption Keys (DEKs).
 * Using HKDF provides domain separation — the raw masterKey is never directly
 * used for encryption, reducing the blast radius if there's ever a weakness
 * in the key usage.
 *
 * @param masterKey - The 32-byte master key from deriveMasterKey()
 * @returns 32-byte vault encryption key
 */
export function deriveVaultKey(masterKey: Uint8Array): Uint8Array {
  if (masterKey.length !== 32) {
    throw new Error('Master key must be 32 bytes');
  }
  return hkdf(
    sha256,
    masterKey,
    HKDF_SALT,
    VAULT_KEY_INFO,
    32,
  );
}

// ── Memory Safety ─────────────────────────────────────────────────────────────

/**
 * Best-effort zero-out of a key buffer.
 *
 * NOTE: JavaScript's garbage collector means this is NOT a guarantee.
 * The bytes may be copied to other memory locations before being collected.
 * However, explicitly zeroing the buffer reduces the window in which the key
 * data is accessible at a known address.
 *
 * For robust security, the vault auto-locks on inactivity to reduce the
 * time window the key is in memory.
 */
export function zeroKey(key: Uint8Array): void {
  key.fill(0);
}

/**
 * Estimate the time (ms) Argon2id derivation will take on this device.
 * Useful for showing a loading indicator with accurate timing.
 */
export async function benchmarkKdf(samplePassword = 'benchmark'): Promise<number> {
  const salt = generateKdfSalt();
  const start = performance.now();
  await deriveMasterKey(samplePassword, salt);
  return performance.now() - start;
}
