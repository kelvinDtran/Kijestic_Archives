-- Migration: add_file_scan_status
-- Adds malware scan result fields to VaultFile
-- and new scan-related AuditEvent values.

-- Create the ScanStatus enum
CREATE TYPE "ScanStatus" AS ENUM ('PENDING', 'CLEAN', 'INFECTED', 'UNKNOWN', 'SKIPPED');

-- Add scan columns to VaultFile
ALTER TABLE "VaultFile"
  ADD COLUMN "scanStatus"       "ScanStatus" NOT NULL DEFAULT 'PENDING',
  ADD COLUMN "scanDetections"   INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "scanTotalEngines" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "scannedAt"        TIMESTAMP(3);

-- Extend the AuditEvent enum with scan events
ALTER TYPE "AuditEvent" ADD VALUE IF NOT EXISTS 'VAULT_FILE_SCAN_CLEAN';
ALTER TYPE "AuditEvent" ADD VALUE IF NOT EXISTS 'VAULT_FILE_SCAN_INFECTED';
ALTER TYPE "AuditEvent" ADD VALUE IF NOT EXISTS 'VAULT_FILE_SCAN_UNKNOWN';
