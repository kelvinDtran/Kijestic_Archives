/**
 * AegisVault — File Storage Abstraction
 *
 * Supports two backends:
 *   - "local": filesystem storage (development / self-hosted)
 *   - "s3":    S3-compatible object storage (AWS S3, Cloudflare R2, MinIO)
 *
 * ALL files stored here are pre-encrypted by the client.
 * The storage layer has NO knowledge of file content or metadata.
 * Storage paths are UUID-based and reveal nothing sensitive.
 *
 * SECURITY NOTE: Presigned URLs for S3 should use short TTLs (5 minutes max)
 * and require authentication before generation.
 */

import { randomUUID } from 'crypto';
import path from 'path';
import fs from 'fs/promises';

// S3 client is lazy-loaded only when STORAGE_PROVIDER=s3
let s3Client: import('@aws-sdk/client-s3').S3Client | null = null;

const STORAGE_PROVIDER = process.env.STORAGE_PROVIDER ?? 'local';
const LOCAL_PATH       = path.resolve(
  process.env.LOCAL_STORAGE_PATH ?? path.join(process.cwd(), 'uploads')
);
const S3_BUCKET        = process.env.S3_BUCKET_NAME ?? '';

// ── Storage Path Generation ────────────────────────────────────────────────────

/**
 * Generate a random, unpredictable storage path.
 * Using UUIDs ensures:
 *   - No collision with other files
 *   - No leakage of original filename in the path
 *   - No enumerable pattern (attackers can't guess file paths)
 */
export function generateStoragePath(userId: string): string {
  // Shard by userId prefix for performance at scale
  const shard = userId.slice(0, 8);
  return `vault/${shard}/${randomUUID()}`;
}

// ── Storage Interface ──────────────────────────────────────────────────────────

export interface StoredFileInfo {
  storagePath: string;
  encryptedSize: number;
}

/**
 * Upload an encrypted file blob to storage.
 * The blob must already be encrypted before calling this function.
 */
export async function uploadEncryptedFile(
  storagePath: string,
  encryptedBlob: Buffer | Uint8Array,
): Promise<void> {
  if (STORAGE_PROVIDER === 's3') {
    await uploadToS3(storagePath, encryptedBlob);
  } else {
    await uploadToLocal(storagePath, encryptedBlob);
  }
}

/**
 * Download an encrypted file blob from storage.
 * The returned buffer is encrypted — the client decrypts it.
 */
export async function downloadEncryptedFile(storagePath: string): Promise<Buffer> {
  if (STORAGE_PROVIDER === 's3') {
    return downloadFromS3(storagePath);
  }
  return downloadFromLocal(storagePath);
}

/**
 * Delete an encrypted file from storage.
 */
export async function deleteEncryptedFile(storagePath: string): Promise<void> {
  if (STORAGE_PROVIDER === 's3') {
    await deleteFromS3(storagePath);
  } else {
    await deleteFromLocal(storagePath);
  }
}

// ── Local Storage Backend ──────────────────────────────────────────────────────

async function uploadToLocal(storagePath: string, data: Buffer | Uint8Array): Promise<void> {
  const fullPath = path.join(LOCAL_PATH, storagePath);
  const resolvedFull = path.resolve(fullPath);
  const resolvedBase = path.resolve(LOCAL_PATH);
  if (!resolvedFull.startsWith(resolvedBase + path.sep) && resolvedFull !== resolvedBase) {
    throw new Error('Invalid storage path: path traversal attempt detected');
  }
  await fs.mkdir(path.dirname(fullPath), { recursive: true });
  await fs.writeFile(fullPath, data);
}

async function downloadFromLocal(storagePath: string): Promise<Buffer> {
  const fullPath = path.join(LOCAL_PATH, storagePath);
  const resolvedFull = path.resolve(fullPath);
  const resolvedBase = path.resolve(LOCAL_PATH);
  if (!resolvedFull.startsWith(resolvedBase + path.sep) && resolvedFull !== resolvedBase) {
    throw new Error('Invalid storage path: path traversal attempt detected');
  }
  return fs.readFile(fullPath);
}

async function deleteFromLocal(storagePath: string): Promise<void> {
  const fullPath = path.join(LOCAL_PATH, storagePath);
  const resolvedFull = path.resolve(fullPath);
  const resolvedBase = path.resolve(LOCAL_PATH);
  if (!resolvedFull.startsWith(resolvedBase + path.sep) && resolvedFull !== resolvedBase) {
    throw new Error('Invalid storage path: path traversal attempt detected');
  }
  await fs.unlink(fullPath).catch(() => {/* ignore missing file */});
}

// ── S3 Storage Backend ─────────────────────────────────────────────────────────

async function getS3Client() {
  if (!s3Client) {
    const { S3Client } = await import('@aws-sdk/client-s3');
    s3Client = new S3Client({
      region:   process.env.S3_REGION ?? 'us-east-1',
      endpoint: process.env.S3_ENDPOINT ?? undefined,
      credentials: process.env.AWS_ACCESS_KEY_ID
        ? {
            accessKeyId:     process.env.AWS_ACCESS_KEY_ID,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ?? '',
          }
        : undefined,
    });
  }
  return s3Client;
}

async function uploadToS3(storagePath: string, data: Buffer | Uint8Array): Promise<void> {
  const { PutObjectCommand } = await import('@aws-sdk/client-s3');
  const client = await getS3Client();
  await client.send(new PutObjectCommand({
    Bucket:      S3_BUCKET,
    Key:         storagePath,
    Body:        Buffer.from(data),
    ContentType: 'application/octet-stream', // no revealing content type
    // Server-side encryption at rest (belt-and-suspenders; content is already client-encrypted)
    ServerSideEncryption: 'AES256',
  }));
}

async function downloadFromS3(storagePath: string): Promise<Buffer> {
  const { GetObjectCommand } = await import('@aws-sdk/client-s3');
  const client = await getS3Client();
  const response = await client.send(new GetObjectCommand({
    Bucket: S3_BUCKET,
    Key:    storagePath,
  }));

  if (!response.Body) throw new Error('Empty response from S3');

  // Read stream to buffer
  const chunks: Uint8Array[] = [];
  for await (const chunk of response.Body as AsyncIterable<Uint8Array>) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function deleteFromS3(storagePath: string): Promise<void> {
  const { DeleteObjectCommand } = await import('@aws-sdk/client-s3');
  const client = await getS3Client();
  await client.send(new DeleteObjectCommand({
    Bucket: S3_BUCKET,
    Key:    storagePath,
  }));
}
