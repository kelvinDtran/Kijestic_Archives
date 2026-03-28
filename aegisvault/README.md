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
| MFA | TOTP via `otpauth` |
| WebAuthn | `@simplewebauthn` |
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
