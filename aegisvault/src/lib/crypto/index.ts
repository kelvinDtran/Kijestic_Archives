/**
 * AegisVault — Crypto Module Public API
 *
 * SECURITY NOTE: All exports from this module operate on the CLIENT SIDE ONLY.
 * No crypto operations should ever happen server-side with actual user keys.
 * The server handles only: encrypted blobs, KDF parameters, session tokens.
 */

// Key derivation (Argon2id)
export {
  KDF_VERSION,
  KDF_PARAMS,
  generateKdfSalt,
  deriveMasterKey,
  deriveVaultKey,
  zeroKey,
  benchmarkKdf,
  type KdfSalt,
} from './kdf';

// Symmetric encryption (XChaCha20-Poly1305)
export {
  encrypt,
  decrypt,
  encryptString,
  decryptString,
  encryptJSON,
  decryptJSON,
  generateItemKey,
  generateFileKey,
  constantTimeEqual,
} from './encryption';

// Vault-level operations
export {
  wrapItemKey,
  unwrapItemKey,
  encryptVaultItem,
  decryptVaultItem,
  reEncryptVaultItem,
  createFileKey,
  unwrapFileKey,
  createExportPackage,
  decryptExportPackage,
  type VaultExportPackage,
} from './vault-crypto';

// File encryption
export {
  encryptFile,
  decryptFile,
  encryptFileMetadata,
  decryptFileMetadata,
  validateFileForUpload,
  formatFileSize,
} from './file-crypto';
