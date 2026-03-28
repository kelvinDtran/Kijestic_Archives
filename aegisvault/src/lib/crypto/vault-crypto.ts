/**
 * AegisVault — Vault-Level Crypto Operations
 *
 * This module provides high-level operations for:
 *   1. Wrapping/unwrapping per-item Data Encryption Keys (DEKs)
 *   2. Encrypting/decrypting vault item data blobs
 *   3. Preparing items for server storage and restoring them on the client
 *
 * KEY HIERARCHY REMINDER:
 *   masterPassword → Argon2id → masterKey → HKDF → vaultKey (VEK)
 *                                                       ↓
 *                                              encryptedItemKey = Enc(VEK, DEK)
 *                                                       ↓
 *                                              encryptedData = Enc(DEK, plaintext)
 *
 * The VEK and DEKs MUST NEVER leave the client or be logged.
 */

import {
  encrypt,
  decrypt,
  encryptJSON,
  decryptJSON,
  generateItemKey,
  generateFileKey,
} from './encryption';
import type { VaultItemData, EncryptedVaultItem, DecryptedVaultItem, ItemType } from '@/types/vault';

// ── Item Key Wrapping ──────────────────────────────────────────────────────────

/**
 * Wrap (encrypt) a Data Encryption Key with the Vault Encryption Key.
 * The result is safe to store on the server.
 *
 * @param vaultKey - The 32-byte VEK derived from the master key
 * @param itemKey  - The 32-byte DEK to be wrapped
 * @returns base64-encoded wrapped key: nonce[24] || Enc(VEK, DEK)[32] || tag[16]
 */
export function wrapItemKey(vaultKey: Uint8Array, itemKey: Uint8Array): string {
  const wrapped = encrypt(vaultKey, itemKey);
  return Buffer.from(wrapped).toString('base64');
}

/**
 * Unwrap (decrypt) a Data Encryption Key using the Vault Encryption Key.
 * Throws if the vault key is wrong or the ciphertext is tampered.
 *
 * @param vaultKey          - The 32-byte VEK
 * @param encryptedItemKey  - base64-encoded wrapped key from wrapItemKey()
 * @returns 32-byte DEK
 */
export function unwrapItemKey(vaultKey: Uint8Array, encryptedItemKey: string): Uint8Array {
  const data = Buffer.from(encryptedItemKey, 'base64');
  return decrypt(vaultKey, new Uint8Array(data));
}

// ── Item Encryption/Decryption ─────────────────────────────────────────────────

/**
 * Encrypt all sensitive fields of a vault item.
 *
 * Generates a fresh DEK, wraps it with the VEK, encrypts the data,
 * and returns everything ready to send to the server.
 *
 * @param vaultKey - VEK (32 bytes)
 * @param itemType - Non-sensitive type enum (stored in plaintext for filtering)
 * @param data     - The sensitive payload to encrypt
 * @param isHighRisk - Whether this item triggers extra friction on access
 */
export function encryptVaultItem(
  vaultKey: Uint8Array,
  itemType: ItemType,
  isFavorite: boolean,
  isHighRisk: boolean,
  data: VaultItemData,
): Omit<EncryptedVaultItem, 'id' | 'userId' | 'isArchived' | 'createdAt' | 'updatedAt'> {
  // Generate a fresh random DEK for this item
  const itemKey = generateItemKey();

  try {
    return {
      itemType,
      isFavorite,
      isHighRisk,
      encryptedItemKey: wrapItemKey(vaultKey, itemKey),
      encryptedData:    encryptJSON(itemKey, data),
    };
  } finally {
    // Best-effort zero out the item key from memory
    // (The GC may have copies elsewhere, but we clear the explicit reference)
    itemKey.fill(0);
  }
}

/**
 * Decrypt a vault item's sensitive data.
 *
 * @param vaultKey - VEK (32 bytes)
 * @param item     - Encrypted item from the server
 * @returns Decrypted vault item (NEVER send this to the server)
 */
export function decryptVaultItem(
  vaultKey: Uint8Array,
  item: EncryptedVaultItem,
): DecryptedVaultItem {
  // Step 1: Unwrap the item's DEK using the VEK
  const itemKey = unwrapItemKey(vaultKey, item.encryptedItemKey);

  try {
    // Step 2: Decrypt the sensitive data blob with the DEK
    const data = decryptJSON<VaultItemData>(itemKey, item.encryptedData);

    return {
      id:         item.id,
      itemType:   item.itemType,
      isFavorite: item.isFavorite,
      isArchived: item.isArchived,
      isHighRisk: item.isHighRisk,
      data,
      createdAt:  new Date(item.createdAt),
      updatedAt:  new Date(item.updatedAt),
    };
  } finally {
    itemKey.fill(0);
  }
}

/**
 * Re-encrypt a vault item's data (for edits).
 * Generates a new DEK but preserves the item's identity fields.
 * The old DEK becomes inaccessible after this operation.
 */
export function reEncryptVaultItem(
  vaultKey: Uint8Array,
  existing: EncryptedVaultItem,
  newData: VaultItemData,
  updates: {
    itemType?: ItemType;
    isFavorite?: boolean;
    isHighRisk?: boolean;
  } = {},
): Pick<EncryptedVaultItem, 'encryptedItemKey' | 'encryptedData' | 'itemType' | 'isFavorite' | 'isHighRisk'> {
  // Generate a new DEK for the updated item (key rotation on every edit)
  const newItemKey = generateItemKey();

  try {
    return {
      itemType:         updates.itemType   ?? existing.itemType,
      isFavorite:       updates.isFavorite ?? existing.isFavorite,
      isHighRisk:       updates.isHighRisk ?? existing.isHighRisk,
      encryptedItemKey: wrapItemKey(vaultKey, newItemKey), // wrap new DEK with VEK
      encryptedData:    encryptJSON(newItemKey, newData),
    };
  } finally {
    newItemKey.fill(0);
  }
}

// ── File Key Handling ──────────────────────────────────────────────────────────

/**
 * Generate and wrap a file encryption key.
 * Returns the base64-encoded wrapped key for server storage.
 */
export function createFileKey(vaultKey: Uint8Array): {
  fileKey: Uint8Array;
  encryptedFileKey: string;
} {
  const fileKey = generateFileKey();
  const encryptedFileKey = wrapItemKey(vaultKey, fileKey);
  return { fileKey, encryptedFileKey };
}

/**
 * Unwrap a file encryption key.
 */
export function unwrapFileKey(vaultKey: Uint8Array, encryptedFileKey: string): Uint8Array {
  return unwrapItemKey(vaultKey, encryptedFileKey);
}

// ── Vault Export ───────────────────────────────────────────────────────────────

export interface VaultExportPackage {
  version: number;
  createdAt: string;
  // All items are re-encrypted with a fresh export key
  // The export key itself is encrypted with the vault key
  encryptedExportKey: string;
  items: Array<{
    encryptedData: string;  // re-encrypted with exportKey
  }>;
}

/**
 * Create an encrypted export package.
 * The entire vault is re-encrypted with a fresh export key.
 * The export key is then encrypted with the vault key.
 *
 * To import, the user needs:
 *   1. Their master password (to derive the vault key)
 *   2. This export file
 */
export function createExportPackage(
  vaultKey: Uint8Array,
  decryptedItems: DecryptedVaultItem[],
): VaultExportPackage {
  const exportKey = generateItemKey();

  try {
    const items = decryptedItems.map((item) => ({
      encryptedData: encryptJSON(exportKey, {
        itemType:   item.itemType,
        isFavorite: item.isFavorite,
        isArchived: item.isArchived,
        isHighRisk: item.isHighRisk,
        data:       item.data,
        createdAt:  item.createdAt.toISOString(),
        updatedAt:  item.updatedAt.toISOString(),
      }),
    }));

    return {
      version:            1,
      createdAt:          new Date().toISOString(),
      encryptedExportKey: wrapItemKey(vaultKey, exportKey),
      items,
    };
  } finally {
    exportKey.fill(0);
  }
}

/**
 * Decrypt an export package.
 */
export function decryptExportPackage(
  vaultKey: Uint8Array,
  pkg: VaultExportPackage,
): Omit<DecryptedVaultItem, 'id'>[] {
  if (pkg.version !== 1) {
    throw new Error(`Unsupported export version: ${pkg.version}`);
  }

  const exportKey = unwrapItemKey(vaultKey, pkg.encryptedExportKey);

  try {
    return pkg.items.map((item) => decryptJSON(exportKey, item.encryptedData));
  } finally {
    exportKey.fill(0);
  }
}
