/**
 * POST /api/scan
 *
 * Server-side proxy for VirusTotal hash lookups.
 * Keeps the VIRUSTOTAL_API_KEY secret on the server.
 *
 * Request body:
 *   { hash: string }   — SHA-256 hex string of the plaintext file
 *
 * Response:
 *   { success: true, data: { status, detections, totalEngines, permalink? } }
 *
 * Requires authentication — unauthenticated requests return 401.
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getAuthFromRequest } from '@/lib/auth/jwt';
import { scanFileHash } from '@/lib/server/virustotal';
import { logAuditEvent, buildAuditContext } from '@/lib/server/audit';

const scanBodySchema = z.object({
  hash: z
    .string()
    .regex(/^[a-fA-F0-9]{64}$/, 'Must be a valid SHA-256 hex string'),
});

export async function POST(req: NextRequest) {
  const auth = await getAuthFromRequest();
  if (!auth) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ success: false, error: 'Invalid JSON body' }, { status: 400 });
  }

  const parsed = scanBodySchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { success: false, error: parsed.error.errors[0]?.message ?? 'Invalid request' },
      { status: 400 },
    );
  }

  const result = await scanFileHash(parsed.data.hash);

  // Log infected file attempts to the audit trail
  if (result.status === 'INFECTED') {
    const ctx = await buildAuditContext(auth.sub);
    await logAuditEvent('VAULT_FILE_SCAN_INFECTED', {
      ...ctx,
      metadata: { detections: result.detections, totalEngines: result.totalEngines },
    });
  }

  return NextResponse.json({ success: true, data: result });
}
