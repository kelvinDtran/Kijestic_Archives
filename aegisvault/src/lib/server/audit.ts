/**
 * AegisVault — Audit Logging
 *
 * CRITICAL SECURITY RULE: This module MUST NEVER log:
 *   - Plaintext secrets or passwords
 *   - Master keys or derived keys
 *   - Decrypted vault content
 *   - Raw IP addresses (use hashed versions)
 *
 * Logs only: event type, timestamp, user ID, hashed IP, user agent,
 * and non-sensitive metadata (e.g., item type category, not the secret value).
 */

import { createHash } from 'crypto';
import { db } from './db';
import type { AuditEvent } from '@prisma/client';
import { headers } from 'next/headers';

export type { AuditEvent };

// ── Audit Event Logging ────────────────────────────────────────────────────────

export interface AuditContext {
  userId?: string;
  ip?: string;
  userAgent?: string;
  // Safe, non-sensitive metadata only
  metadata?: Record<string, string | number | boolean | null>;
}

/**
 * Log a security event to the audit trail.
 * This is a best-effort operation — failures do not block the main flow.
 *
 * @param event   - The audit event type
 * @param context - Non-sensitive context (userId, hashed IP, etc.)
 */
export async function logAuditEvent(
  event: AuditEvent,
  context: AuditContext = {},
): Promise<void> {
  try {
    const ipHash = context.ip ? hashIp(context.ip) : undefined;

    await db.auditLog.create({
      data: {
        event,
        userId:    context.userId ?? null,
        ipHash:    ipHash ?? null,
        userAgent: context.userAgent ? truncate(context.userAgent, 500) : null,
        metadata:  context.metadata ?? null,
      },
    });
  } catch (err) {
    // Audit logging must never crash the application
    console.error('[Audit] Failed to log event:', event, err);
  }
}

/**
 * Build an AuditContext from the current request headers.
 * Automatically hashes IP.
 */
export async function buildAuditContext(userId?: string): Promise<AuditContext> {
  const headerList = await headers();
  const ip =
    headerList.get('cf-connecting-ip') ??
    headerList.get('x-real-ip') ??
    headerList.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    undefined;
  const userAgent = headerList.get('user-agent') ?? undefined;

  return { userId, ip, userAgent };
}

/**
 * Retrieve audit logs for a user (for the user's own security dashboard).
 * Returns safe fields only — no raw IPs.
 */
export async function getUserAuditLogs(
  userId: string,
  limit = 50,
): Promise<Array<{
  id: string;
  event: AuditEvent;
  createdAt: Date;
  metadata: Record<string, unknown> | null;
  userAgentHint: string | null;
}>> {
  const logs = await db.auditLog.findMany({
    where:   { userId },
    orderBy: { createdAt: 'desc' },
    take:    limit,
    select: {
      id:        true,
      event:     true,
      createdAt: true,
      metadata:  true,
      userAgent: true,
    },
  });

  return logs.map((log) => ({
    id:          log.id,
    event:       log.event,
    createdAt:   log.createdAt,
    metadata:    log.metadata as Record<string, unknown> | null,
    // Return only first 60 chars of user agent — enough for device hint, not fingerprinting
    userAgentHint: log.userAgent ? log.userAgent.slice(0, 60) : null,
  }));
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Hash an IP address for privacy-preserving storage.
 * SHA-256 of the raw IP — prevents exact IP lookup but still allows
 * grouping by IP for anomaly detection.
 */
function hashIp(ip: string): string {
  return createHash('sha256').update(ip).digest('hex');
}

function truncate(str: string, maxLen: number): string {
  return str.length > maxLen ? str.slice(0, maxLen) + '...' : str;
}
