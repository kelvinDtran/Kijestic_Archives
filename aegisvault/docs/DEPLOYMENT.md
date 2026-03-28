# AegisVault — Deployment Guide

## Production Checklist

Before going live, verify:

- [ ] All `CHANGE_ME` values in `.env` replaced with secure random values
- [ ] `NODE_ENV=production`
- [ ] `FORCE_HTTPS=true`
- [ ] `STORAGE_PROVIDER=s3` (or local with proper backups)
- [ ] PostgreSQL with SSL enabled (`?sslmode=require` in DATABASE_URL)
- [ ] HTTPS with a valid TLS certificate
- [ ] Domain set in `APP_DOMAIN` (for WebAuthn and CSP)

## Environment Variables

```bash
# Generate JWT secrets (run each command separately for different values)
openssl rand -base64 64    # JWT_ACCESS_SECRET
openssl rand -base64 64    # JWT_REFRESH_SECRET
openssl rand -base64 32    # SERVER_ENCRYPTION_KEY
```

## Database Setup

```bash
# Run migrations in production (never use db:push in prod)
npm run db:migrate:prod
# or
npx prisma migrate deploy
```

## Vercel Deployment

```bash
npm install -g vercel
vercel --prod
```

Set all environment variables in Vercel dashboard.

## Docker Deployment

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV production
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/package*.json ./
RUN npm ci --production
EXPOSE 3000
CMD ["npm", "start"]
```

## PostgreSQL Setup

```sql
CREATE USER aegisvault WITH ENCRYPTED PASSWORD 'strong-password-here';
CREATE DATABASE aegisvault OWNER aegisvault;
GRANT ALL PRIVILEGES ON DATABASE aegisvault TO aegisvault;
```

## S3/R2 Storage Setup

For Cloudflare R2:
```
S3_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com
S3_BUCKET_NAME=aegisvault-files
S3_REGION=auto
AWS_ACCESS_KEY_ID=<R2 Access Key ID>
AWS_SECRET_ACCESS_KEY=<R2 Secret Access Key>
```

Bucket policy: **private** — no public access. Pre-signed URLs are not currently used (files are proxied through the API).

## Security Hardening for Production

1. **Database**: Enable SSL, restrict network access (VPC/firewall)
2. **Secrets**: Use a secrets manager (AWS Secrets Manager, Vault) instead of env files
3. **Logging**: Ensure logs are not stored in a way that captures HTTP request bodies
4. **Monitoring**: Set up alerts for failed login spikes, unusual session activity
5. **Backups**: Automate encrypted database backups (see BACKUP_RECOVERY.md)
6. **Rate limiting**: Consider Redis-backed rate limiting (e.g., @upstash/ratelimit) for production scale
7. **WAF**: Deploy behind Cloudflare or similar WAF for DDoS protection
