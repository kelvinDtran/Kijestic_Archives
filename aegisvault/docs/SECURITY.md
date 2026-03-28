# AegisVault — Security Architecture

## Threat Model

### Assets being protected
- Vault secrets (passwords, API keys, seed phrases, private keys)
- Vault metadata (website names, usernames, tags)
- Session tokens (access/refresh)
- TOTP secrets (stored server-side)

### Threats considered

| Threat | Mitigation |
|---|---|
| **Database breach** | All sensitive fields encrypted client-side. Attacker gets only ciphertexts. Decryption requires master password + Argon2id brute force (64 MB memory-hard). |
| **Server/API compromise** | Server never holds the master key, VEK, or DEKs. Attacker cannot decrypt vault contents. |
| **Storage provider breach** | All file blobs are client-encrypted before upload. Provider sees only ciphertexts. |
| **Network interception** | HTTPS + HSTS header. Cookies are Secure + HttpOnly. |
| **XSS attack** | CSP policy. HttpOnly cookies prevent JS cookie theft. Vault key in memory (not localStorage). |
| **CSRF attack** | SameSite=Strict cookies. CSRF origin checking. |
| **Session hijacking** | Short-lived access tokens (15 min). Refresh token rotation. Session revocation. |
| **Brute force login** | Rate limiting on all auth endpoints. bcrypt cost 12 for account passwords. |
| **Brute force master key** | Argon2id: 64 MB, 3 iterations, 4 parallelism. Makes GPU/ASIC attacks prohibitively expensive. |
| **Clipboard theft** | Auto-clear clipboard after 30 seconds. |
| **Screen recording while unlocked** | Auto-lock on inactivity (default 5 min). Manual lock button. |
| **Malicious browser extension** | No mitigation possible — fundamental browser limitation. |
| **Keylogger** | No mitigation possible — OS-level threat. |

### Non-goals / Out of scope

- Protection against malware or keyloggers on the client device
- Protection against a malicious OS or browser
- Anonymous usage (email address required)
- Zero-knowledge *server-side search* (search is client-side only)
- Hardware-level memory security in JavaScript

---

## Encryption Architecture

### Algorithm choices

| Purpose | Algorithm | Reason |
|---|---|---|
| Master key derivation | **Argon2id** | Memory-hard KDF. Defeats GPU/ASIC brute force. RFC 9106 recommended. |
| Vault key derivation | **HKDF-SHA256** | Domain separation from master key. Standard KDF for key expansion. |
| Data encryption | **XChaCha20-Poly1305** | 192-bit nonce (safe for random generation). Authenticated (AEAD). Side-channel resistant. |
| Account password | **bcrypt (cost 12)** | Server-side hashing. Authentication only. |
| TOTP secret at rest | **AES-256-GCM** | Server-side encryption with SERVER_ENCRYPTION_KEY. |
| Refresh tokens | **SHA-256 hash** | Opaque tokens stored as hashes in DB. |

### Argon2id Parameters

```
Memory:      64 MB (65536 KiB)
Iterations:  3
Parallelism: 4
Output:      32 bytes (256-bit master key)
```

These parameters target ~0.5–2 seconds on modern hardware. This is:
- Fast enough to be usable (acceptable UX)
- Slow enough to make offline brute-force attacks expensive
- Memory-hard enough to defeat GPU/ASIC parallelization

### Wire format for encrypted values

```
base64( nonce[24 bytes] || ciphertext[N bytes] || tag[16 bytes] )
```

All encrypted values stored in the database use this format.
The nonce is randomly generated for every encryption call — no reuse.

### Key hierarchy

```
masterPassword (string, never leaves browser)
    ↓ Argon2id(memory=65536, iter=3, par=4, salt=kdfSalt)
masterKey (32 bytes, never sent to server)
    ↓ HKDF-SHA256(info="aegisvault-v1-vault-key")
vaultKey (32 bytes, in-memory only, cleared on lock)
    ↓ XChaCha20-Poly1305(vaultKey, random DEK)
encryptedItemKey (stored in DB)
    ↓ XChaCha20-Poly1305(DEK, JSON.stringify(itemData))
encryptedData (stored in DB)
```

### Per-item key rotation

Every time a vault item is edited, a new DEK is generated. This means:
- Old DEKs are never reused after an edit
- Compromise of one item's key does not affect others
- Key rotation happens transparently on every save

---

## Authentication Architecture

### Session lifecycle

1. User logs in → server creates session with hashed refresh token
2. Access token (15 min JWT) + refresh token (opaque, 30 days) set as httpOnly cookies
3. On access token expiry → browser calls `/api/auth/refresh`
4. Refresh token is exchanged for a new pair (rotation)
5. Old refresh token is immediately invalidated
6. On logout → current session revoked, cookies cleared

### Refresh token security

- Token is 48 bytes of cryptographically random data (base64url)
- Only the SHA-256 hash is stored in the database
- Cookie scope: `path=/api/auth/refresh` — limits exposure
- Rotation on every use prevents replay attacks from past logs

### Cookie security

```
HttpOnly:   true   — prevents JavaScript access
Secure:     true   — HTTPS only (production)
SameSite:   Strict — prevents CSRF
Path:       /      — (access token); /api/auth/refresh (refresh token)
```

---

## Server-Side Data

### What the database contains

```
users table:
  - email (needed for auth)
  - passwordHash (bcrypt of account password)
  - kdfSalt, kdfVersion, kdfMemory, kdfIterations, kdfParallelism
    (KDF parameters — NOT secret, needed for client key derivation)
  - totpSecret (AES-256-GCM encrypted with SERVER_ENCRYPTION_KEY)

vault_items table:
  - itemType (enum: PASSWORD, API_KEY, etc.) — plaintext for filtering
  - isFavorite, isArchived, isHighRisk (booleans) — plaintext for filtering
  - encryptedItemKey (wrapped DEK)
  - encryptedData (all sensitive fields as encrypted JSON blob)
  - timestamps

sessions table:
  - refreshTokenHash (SHA-256 of opaque token)
  - ipHash (SHA-256 of IP — privacy-preserving)
  - userAgent (for device display)
  - expiresAt, lastUsedAt

audit_logs table:
  - event type (enum)
  - userId
  - ipHash
  - userAgent
  - metadata (SAFE fields only — no secrets)
```

### What the database does NOT contain

- Master passwords (never)
- Master keys or VEKs (never)
- Item titles, passwords, usernames, emails (all encrypted)
- Raw IP addresses (stored as SHA-256 hashes)
- Raw refresh tokens (stored as SHA-256 hashes)
- Decryptable TOTP secrets without SERVER_ENCRYPTION_KEY

---

## File Storage Security

- Files are encrypted client-side with a random 32-byte file key
- The file key is wrapped with the VEK (same as item keys)
- Encrypted file key and encrypted metadata are stored in the DB
- The encrypted blob is stored in object storage (local or S3)
- Storage paths are UUID-based — no original filename in path
- The storage provider sees only encrypted blobs and opaque paths

---

## Audit Logging

The audit log records security events WITHOUT sensitive data:

**Logged (safe):**
- Event type (login, logout, item created, etc.)
- Timestamp
- SHA-256 of client IP
- User agent string (first 500 chars)
- Non-sensitive metadata (e.g., itemType enum)

**Never logged:**
- Secret values
- Decrypted vault content
- Master password or keys
- Raw IPs

---

## Security Headers

Configured in `next.config.ts`:

```
Content-Security-Policy  default-src 'self'; script-src 'self'; ...
Strict-Transport-Security  max-age=63072000; includeSubDomains; preload (prod)
X-Frame-Options  DENY
X-Content-Type-Options  nosniff
Referrer-Policy  strict-origin-when-cross-origin
Permissions-Policy  camera=(), microphone=(), ...
Cross-Origin-Embedder-Policy  require-corp
Cross-Origin-Opener-Policy  same-origin
Cross-Origin-Resource-Policy  same-origin
Cache-Control  no-store (on vault pages)
```

---

## Crypto-Specific Item Handling

For items classified as high-risk (seed phrases, private keys):

1. **Warning screen** — shown before saving, requires explicit acknowledgement
2. **High-risk flag** — stored in plaintext for server-side filtering (no secret revealed)
3. **Extra friction** — re-confirmation required in the UI
4. **Short auto-hide** — secret fields auto-hide after 15 seconds (vs 30 for normal secrets)
5. **No auto-fill** — `autocomplete="off"` on all high-risk fields
6. **Warning in list view** — `AlertTriangle` icon shown without revealing the secret

Recommendation displayed to user: use hardware wallets (Ledger, Trezor) or air-gapped storage for seed phrases and private keys.

---

## Known Attack Vectors (Accepted Risks)

1. **JavaScript heap inspection** — The vault key is in plaintext in the JS heap while the vault is unlocked. A sufficiently privileged attacker (malware, browser DevTools with full access) could extract it. Mitigation: inactivity auto-lock limits the exposure window.

2. **Browser storage** — We do NOT use localStorage or sessionStorage for secrets. However, the browser itself may cache data in various ways beyond our control.

3. **Server log injection** — Carefully reviewed all logging to ensure no secrets appear. Zod validation errors are sanitized before logging.

4. **Clipboard** — We auto-clear after 30 seconds, but clipboard managers and OS-level access may have captured the data before clearing.

5. **Screen recording** — No reliable defense in a web app. Auto-lock minimizes exposure time.
