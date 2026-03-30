// AegisVault — Vault Types
// These types represent the decrypted (client-side) view of vault items.
// The server only ever sees the encrypted versions of these structures.

export type ItemType =
  | 'PASSWORD'
  | 'API_KEY'
  | 'CRYPTO'
  | 'NOTE'
  | 'DOCUMENT'
  | 'RECOVERY_CODE'
  | 'IMAGE'
  | 'OTHER';

export type RiskLevel = 'normal' | 'high-risk';

// Custom key-value field (e.g., "Account Number", "Security PIN")
export interface CustomField {
  id: string;
  key: string;
  value: string;
  isSecret: boolean;  // whether to mask this field by default
}

// The decrypted sensitive payload stored inside encryptedData
export interface VaultItemData {
  title: string;
  website?: string;
  username?: string;
  email?: string;
  password?: string;
  customFields: CustomField[];
  notes?: string;
  tags: string[];
  url?: string;
  // For API keys
  apiKeyValue?: string;
  apiKeyName?: string;
  // For crypto items
  seedPhrase?: string;           // EXTREME HIGH RISK — extra warnings required
  privateKey?: string;           // HIGH RISK
  walletAddress?: string;
  networkChain?: string;
  // For recovery codes
  recoveryCodes?: string[];
  // Risk classification (set by user during creation)
  riskLevel: RiskLevel;
  // Acknowledgement for high-risk items
  highRiskWarningAcknowledged?: boolean;
}

// A vault item as stored in the database (encrypted view — what the server sees)
export interface EncryptedVaultItem {
  id: string;
  userId: string;
  itemType: ItemType;
  isFavorite: boolean;
  isArchived: boolean;
  isHighRisk: boolean;
  encryptedItemKey: string;  // base64(nonce || xchacha20(vaultKey, itemKey))
  encryptedData: string;     // base64(nonce || xchacha20(itemKey, JSON(VaultItemData)))
  createdAt: string;
  updatedAt: string;
}

// A fully decrypted vault item (client-side only, NEVER sent to server)
export interface DecryptedVaultItem {
  id: string;
  itemType: ItemType;
  isFavorite: boolean;
  isArchived: boolean;
  isHighRisk: boolean;
  data: VaultItemData;
  createdAt: Date;
  updatedAt: Date;
  files?: VaultFileInfo[];
}

// File info as stored in database (encrypted)
export interface EncryptedVaultFile {
  id: string;
  userId: string;
  vaultItemId?: string;
  encryptedFileKey: string;
  encryptedMetadata: string;
  storagePath: string;
  encryptedSize: number;
  scanStatus: ScanStatus;
  scanDetections: number;
  scanTotalEngines: number;
  scannedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

// Decrypted file metadata (client-side only)
export interface VaultFileMetadata {
  originalName: string;
  mimeType: string;
  originalSize: number;
}

// Client-side view of a file with decrypted metadata
export interface VaultFileInfo {
  id: string;
  metadata: VaultFileMetadata;
  encryptedSize: number;
  scanStatus: ScanStatus;
  scanDetections: number;
  scanTotalEngines: number;
  createdAt: Date;
}

// Create/edit form data (before encryption)
export interface VaultItemFormData {
  itemType: ItemType;
  isFavorite: boolean;
  isHighRisk: boolean;
  data: Partial<VaultItemData>;
}

// Search/filter options for vault list
export interface VaultFilter {
  query?: string;           // searched against decrypted title, website, username, tags
  itemType?: ItemType;
  isFavorite?: boolean;
  isArchived?: boolean;
  isHighRisk?: boolean;
  tags?: string[];
}

// ── Malware scan ─────────────────────────────────────────────────────────────

export type ScanStatus = 'PENDING' | 'CLEAN' | 'INFECTED' | 'UNKNOWN' | 'SKIPPED';

export interface ScanResult {
  status: ScanStatus;
  detections: number;
  totalEngines: number;
  permalink?: string;
}

// KDF parameters (fetched from server, used for client-side key derivation)
export interface KdfParams {
  salt: string;       // hex-encoded 32-byte salt
  version: number;
  memory: number;
  iterations: number;
  parallelism: number;
}
