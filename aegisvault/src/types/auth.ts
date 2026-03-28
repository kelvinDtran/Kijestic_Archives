// AegisVault — Auth Types

export interface User {
  id: string;
  email: string;
  emailVerified: boolean;
  totpEnabled: boolean;
  lockTimeout: number;
  createdAt: string;
  lastLoginAt?: string;
}

export interface Session {
  id: string;
  userId: string;
  userAgent?: string;
  // IP is hashed on server — we return a partial indicator for display
  ipHint?: string;
  lastUsedAt: string;
  createdAt: string;
  isCurrent: boolean;
}

export interface AuthTokens {
  // Access token is short-lived (15 min) — set in httpOnly cookie by server
  // We don't expose it to JS directly; only the server reads it from cookies
  expiresAt: number;  // unix timestamp
}

// Login request payload
export interface LoginRequest {
  email: string;
  password: string;
  totpCode?: string;   // if MFA is enabled
  rememberDevice?: boolean;
}

// Registration request payload
export interface RegisterRequest {
  email: string;
  password: string;
  // KDF params are generated client-side and sent to server for storage
  kdfSalt: string;
  kdfVersion: number;
  kdfMemory: number;
  kdfIterations: number;
  kdfParallelism: number;
}

// TOTP setup response from server
export interface TotpSetupData {
  secret: string;        // base32-encoded TOTP secret
  qrCodeUrl: string;     // data URL for QR code display
  backupCodes: string[]; // one-time backup codes (show once, hash on server)
}

// WebAuthn registration challenge
export interface WebAuthnRegChallenge {
  challenge: string;
  rp: { name: string; id: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: PublicKeyCredentialParameters[];
  authenticatorSelection: AuthenticatorSelectionCriteria;
  timeout: number;
  attestation: AttestationConveyancePreference;
}

// Audit log entry (safe fields only)
export interface AuditEntry {
  id: string;
  event: string;
  createdAt: string;
  metadata?: Record<string, unknown>;
  // IP/userAgent displayed in redacted form for user's own audit log
  ipHint?: string;
  userAgentHint?: string;
}
