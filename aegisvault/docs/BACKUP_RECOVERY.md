# AegisVault — Backup & Recovery Guide

## What Needs Backing Up

| Data | Location | Sensitivity | Backup Needed? |
|---|---|---|---|
| Encrypted vault items | PostgreSQL | Low (encrypted) | Yes |
| Encrypted files | Object storage | Low (encrypted) | Yes |
| KDF salt | PostgreSQL | Not secret | Yes |
| Master password | Your memory only | **CRITICAL** | Yes — store safely offline |
| Account password | PostgreSQL (hashed) | N/A | Optional |
| SERVER_ENCRYPTION_KEY | Environment | **HIGH** | Yes — needed to decrypt TOTP secrets |
| JWT secrets | Environment | Medium | Yes |

## Encrypted Vault Export

AegisVault includes a built-in vault export:

1. Unlock your vault
2. Go to Settings → Export Encrypted Vault
3. Download the `.aegisvault` backup file
4. Store it safely (it's encrypted with your vault key)

To restore:
1. Create a new account or log into existing account
2. Settings → Import → select `.aegisvault` file
3. Enter your master password

**The export file is encrypted.** Without your master password, it cannot be decrypted.

## Database Backup

```bash
# PostgreSQL backup
pg_dump -h localhost -U aegisvault -d aegisvault -F c -f aegisvault_$(date +%Y%m%d).dump

# Restore
pg_restore -h localhost -U aegisvault -d aegisvault aegisvault_20250101.dump
```

## Emergency Recovery

If you lose access to your account but still know your master password:

1. Export the raw database records for your user
2. The `encryptedData` field in `vault_items` is decryptable with your master password
3. Use the vault export functionality if the app is still accessible

**If you forget your master password:**
- Your vault data is unrecoverable. This is by design.
- This is the tradeoff of zero-knowledge encryption.
- There is no "forgot master password" flow.

## Recovery Kit (Recommended)

Print and store in a secure physical location:
- Your email address
- A hint for your master password (NOT the password itself)
- Instructions to access the vault
- `SERVER_ENCRYPTION_KEY` (needed if self-hosting and losing the server)

**Do NOT print your actual master password in a location accessible to others.**

## Self-Hosted Disaster Recovery

If the entire server is lost:

1. Restore from database backup
2. Re-configure environment variables (especially `SERVER_ENCRYPTION_KEY`, `JWT_ACCESS_SECRET`)
3. Restore file storage contents to new S3 bucket
4. Update `S3_BUCKET_NAME` in environment
5. Run `npm run db:migrate:prod`

If `SERVER_ENCRYPTION_KEY` is lost, TOTP secrets in the database become unreadable. Users will need to disable and re-enable MFA.
