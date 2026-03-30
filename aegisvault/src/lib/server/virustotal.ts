/**
 * AegisVault — VirusTotal API Client
 *
 * Uses hash-based file lookup (v3 API) — privacy-preserving:
 * only the SHA-256 hash is sent to VirusTotal, never the plaintext file.
 *
 * Rate limits (free tier): 4 requests/min, 500/day.
 * Configure via VIRUSTOTAL_API_KEY environment variable.
 *
 * If no API key is set, all scan calls return status "SKIPPED".
 */

const VT_BASE = 'https://www.virustotal.com/api/v3';

export interface VirusTotalScanResult {
  status: 'CLEAN' | 'INFECTED' | 'UNKNOWN' | 'SKIPPED';
  detections: number;
  totalEngines: number;
  permalink?: string;
}

/**
 * Look up a file by its SHA-256 hash in the VirusTotal database.
 *
 * Returns:
 *  - CLEAN     — file is known and no engine flagged it
 *  - INFECTED  — one or more engines flagged it as malicious
 *  - UNKNOWN   — file hash not in VirusTotal database (never seen before)
 *  - SKIPPED   — VIRUSTOTAL_API_KEY not configured
 *
 * Never throws — errors return UNKNOWN so uploads are not blocked on VT outages.
 */
export async function scanFileHash(sha256: string): Promise<VirusTotalScanResult> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey) {
    return { status: 'SKIPPED', detections: 0, totalEngines: 0 };
  }

  // Normalize hash to lowercase
  const hash = sha256.toLowerCase().trim();

  try {
    const res = await fetch(`${VT_BASE}/files/${hash}`, {
      headers: {
        'x-apikey': apiKey,
        'Accept':   'application/json',
      },
      // Hard timeout so a slow VT response never blocks an upload indefinitely
      signal: AbortSignal.timeout(10_000),
    });

    // 404 = file hash not in VT database (never analyzed)
    if (res.status === 404) {
      return { status: 'UNKNOWN', detections: 0, totalEngines: 0 };
    }

    if (!res.ok) {
      console.error('[VirusTotal] Unexpected status:', res.status);
      return { status: 'UNKNOWN', detections: 0, totalEngines: 0 };
    }

    const body = await res.json() as VirusTotalFileResponse;
    const stats = body?.data?.attributes?.last_analysis_stats;

    if (!stats) {
      return { status: 'UNKNOWN', detections: 0, totalEngines: 0 };
    }

    const detections   = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
    const totalEngines = Object.values(stats).reduce<number>((sum, n) => sum + (n ?? 0), 0);
    const permalink    = body?.data?.attributes?.permalink;

    return {
      status:       detections > 0 ? 'INFECTED' : 'CLEAN',
      detections,
      totalEngines,
      permalink,
    };
  } catch (err) {
    // Network error, timeout, etc. — fail open (don't block upload)
    console.error('[VirusTotal] Scan error:', err);
    return { status: 'UNKNOWN', detections: 0, totalEngines: 0 };
  }
}

// ── VirusTotal v3 response shape (relevant fields only) ───────────────────────

interface VirusTotalFileResponse {
  data?: {
    attributes?: {
      last_analysis_stats?: {
        malicious?:  number;
        suspicious?: number;
        undetected?: number;
        harmless?:   number;
        timeout?:    number;
        failure?:    number;
        'type-unsupported'?: number;
      };
      permalink?: string;
    };
  };
}
