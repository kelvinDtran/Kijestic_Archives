# AegisVault

**Zero-knowledge personal secret vault** — a production-grade, security-first application for storing passwords, API keys, crypto credentials, recovery codes, and sensitive documents.

> "Designed as if the server is already compromised."

---

## Security Model

AegisVault operates on a **zero-knowledge** (or as-close-as-practical) principle:

| What the server sees | What the server never sees |
|---|---|
| Encrypted blobs | Plaintext of any secret |
| Item type (enum), timestamps, flags | Secret titles, websites, usernames, passwords |
| Hashed refresh tokens | Master password or derived keys |
| Session metadata (hashed IP) | Vault encryption key |

### Key Hierarchy

```
Master Password + KDF Salt
        │
        ▼ Argon2id (64 MB / 3 iter / 4 par)
   Master Key (256-bit)
        │
        ▼ HKDF-SHA256("vault-key")
  Vault Encryption Key (VEK)
        │
        ▼ XChaCha20-Poly1305(VEK, random DEK)  ─per item─
  Item Data Key (DEK)
        │
        ▼ XChaCha20-Poly1305(DEK, JSON payload)
  Encrypted Sensitive Data (stored in DB)
```

### Two-Password Design

- **Account password** → authentication only, `bcrypt` hash on server
- **Vault master password** → encryption only, **never sent to server**, derives keys via Argon2id

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Next.js 15 (App Router) + TypeScript |
| Styling | Tailwind CSS (dark premium theme) |
| Database | PostgreSQL via Prisma ORM |
| KDF | Argon2id (`hash-wasm` WASM) |
| Encryption | XChaCha20-Poly1305 (`@noble/ciphers`) |
| Key derivation | HKDF-SHA256 (`@noble/hashes`) |
| Auth tokens | JWT via `jose` + opaque refresh tokens |
| Account password | bcrypt via `bcryptjs` |
| MFA | TOTP via `otpauth`, SMS via Twilio, Email OTP via Resend |
| WebAuthn | `@simplewebauthn` (platform + cross-device QR) |
| File storage | Local (dev) / S3-compatible (prod) |

---

## Quick Start

### Prerequisites

- Node.js 20+
- PostgreSQL 15+
- npm or pnpm

### Setup

```bash
# 1. Install dependencies
cd aegisvault
npm install

# 2. Configure environment
cp .env.example .env.local
# Edit .env.local with your values

# 3. Generate secrets
node -e "console.log(require('crypto').randomBytes(64).toString('base64'))"
# Run twice — once for JWT_ACCESS_SECRET, once for JWT_REFRESH_SECRET

# 4. Set up database
npm run db:migrate

# 5. Generate Prisma client
npm run db:generate

# 6. Start development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

### First Use

1. Register an account (email + account password)
2. Complete security onboarding (read it — it matters)
3. Set your vault master password (write it down safely)
4. Your vault is ready — add your first secret

---

## Development

```bash
npm run dev          # Start dev server (hot reload)
npm run build        # Production build
npm run test         # Run tests
npm run test:coverage # Tests with coverage
npm run db:studio    # Open Prisma Studio (DB GUI)
npm run lint         # ESLint
```

---

## Project Structure

```
src/
├── app/
│   ├── api/          # API routes (server-side only)
│   ├── (auth)/       # Login, register, onboarding
│   └── (vault)/      # Dashboard, vault, settings, sessions
├── components/
│   ├── layout/       # Sidebar, header, unlock modal
│   └── vault/        # Vault-specific components
├── contexts/
│   └── VaultContext  # Vault key memory store (CRITICAL)
├── hooks/            # useVaultItems, useClipboard, useVaultLock
├── lib/
│   ├── crypto/       # Argon2id, XChaCha20, vault-crypto
│   ├── auth/         # JWT, bcrypt, TOTP
│   └── server/       # DB, rate-limit, audit, storage, session
└── types/            # TypeScript type definitions
```

---

## Security Notes

- All secrets are encrypted **before** leaving your browser
- The vault key lives only in JavaScript memory — it's cleared on lock/logout
- Auto-lock on inactivity (configurable, default 5 minutes)
- Clipboard auto-clears after 30 seconds
- Refresh tokens are rotated on every use
- Rate limiting on all auth endpoints
- CSP, HSTS, and security headers enforced
- Audit log captures security events (never secret values)

See [docs/SECURITY.md](docs/SECURITY.md) for the full security architecture.

### Required Environment Variables

All of these must be set — the app throws at startup if any are missing:

```bash
# Core (required)
DATABASE_URL=postgresql://...
JWT_ACCESS_SECRET=<64-byte random base64>
SERVER_ENCRYPTION_KEY=<32-byte random base64>
NEXT_PUBLIC_APP_URL=https://yourdomain.com

# SMS MFA (required if SMS MFA is used)
TWILIO_ACCOUNT_SID=ACxxxxxxxx
TWILIO_AUTH_TOKEN=...
TWILIO_PHONE_NUMBER=+1...

# Email MFA (required if Email MFA is used)
RESEND_API_KEY=re_...
RESEND_FROM_EMAIL=AegisVault <noreply@yourdomain.com>
```

Generate secrets with:
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('base64'))"  # JWT_ACCESS_SECRET
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"  # SERVER_ENCRYPTION_KEY
```

---

## MFA Options

AegisVault supports three MFA methods, configurable per-account in Settings:

| Method | How it works | Setup |
|--------|-------------|-------|
| **TOTP (Authenticator App)** | Time-based 6-digit codes via any TOTP app (Google Authenticator, Authy, etc.) | Settings → Security → Enable Authenticator |
| **SMS OTP** | 6-digit code sent to your phone number via Twilio | Settings → Security → Add Phone Number |
| **Email OTP** | 6-digit code sent to your account email via Resend | Settings → Security → Enable Email MFA |
| **Passkey (WebAuthn)** | Biometric or hardware key. Scan a QR code in the browser to register a passkey from your phone | Settings → Passkeys → Add Passkey |

Priority order if multiple methods enabled: TOTP > SMS > Email.

Backup codes (8 per account, 128-bit entropy) are generated when TOTP is enabled and can be used if your primary MFA device is unavailable.

---

## Known Limitations

See [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) for a complete list.

Key ones:
- JavaScript has no memory encryption — vault key is plaintext in JS heap while unlocked
- No zero-knowledge search of secret *values* (search is client-side on decrypted data)
- Browser extensions and keyloggers defeat client-side security
- No anonymous usage — email required for account creation
- File size limit: 50 MB per file

---

## Deployment

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
