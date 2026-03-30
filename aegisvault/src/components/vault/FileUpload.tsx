'use client';

/**
 * FileUpload — Client-side encrypted file upload component
 *
 * Files are scanned for malware THEN encrypted with XChaCha20-Poly1305 BEFORE upload.
 * The server receives only encrypted bytes and never sees the plaintext file,
 * original filename, or MIME type.
 *
 * Upload flow:
 *   1. User selects a file
 *   2. Client validates size/extension
 *   3. Client computes SHA-256 hash of plaintext bytes (Web Crypto API)
 *   4. Client sends hash to /api/scan — VirusTotal hash lookup (privacy-preserving)
 *   5. If INFECTED → block upload, show warning
 *   6. If CLEAN / UNKNOWN / SKIPPED → proceed
 *   7. Client generates a random file key (DEK)
 *   8. Client encrypts the file + metadata
 *   9. Uploads encrypted blob + wrapped key + encrypted metadata + scan result
 *
 * Download flow:
 *   1. Fetch encrypted blob from /api/vault/files/[id]
 *   2. Unwrap file key from X-Encrypted-File-Key header using vault key
 *   3. Decrypt blob to recover original file
 *   4. Trigger browser download
 */

import { useState, useRef } from 'react';
import { Upload, Download, Trash2, FileText, Loader2, AlertTriangle, ShieldCheck } from 'lucide-react';
import { useVault } from '@/contexts/VaultContext';
import { createFileKey, unwrapFileKey } from '@/lib/crypto/vault-crypto';
import { encryptFile, decryptFile, validateFileForUpload, formatFileSize } from '@/lib/crypto/file-crypto';
import { ScanBadge } from '@/components/vault/ScanBadge';
import type { VaultFileInfo, ScanStatus, ScanResult } from '@/types/vault';

interface FileUploadProps {
  vaultItemId?: string;
  existingFiles?: VaultFileInfo[];
  onFileUploaded?: (file: VaultFileInfo) => void;
  onFileDeleted?: (fileId: string) => void;
}

// ── Hash helper ───────────────────────────────────────────────────────────────

async function computeSha256(buffer: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ── Scan helper ───────────────────────────────────────────────────────────────

async function scanFile(hash: string): Promise<ScanResult> {
  const res = await fetch('/api/scan', {
    method:      'POST',
    headers:     { 'Content-Type': 'application/json' },
    body:        JSON.stringify({ hash }),
    credentials: 'include',
  });

  if (!res.ok) {
    // Scan endpoint unavailable — fail open (don't block upload)
    return { status: 'UNKNOWN', detections: 0, totalEngines: 0 };
  }

  const body = await res.json();
  return (body.data as ScanResult) ?? { status: 'UNKNOWN', detections: 0, totalEngines: 0 };
}

// ── Component ─────────────────────────────────────────────────────────────────

export function FileUpload({
  vaultItemId,
  existingFiles = [],
  onFileUploaded,
  onFileDeleted,
}: FileUploadProps) {
  const { getVaultKey } = useVault();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [isUploading, setIsUploading]     = useState(false);
  const [uploadStage, setUploadStage]     = useState<'scanning' | 'encrypting' | null>(null);
  const [uploadError, setUploadError]     = useState<string | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [deletingId, setDeletingId]       = useState<string | null>(null);
  const [dragOver, setDragOver]           = useState(false);

  // ── Upload ──────────────────────────────────────────────────────────────────

  const uploadFile = async (file: File) => {
    setUploadError(null);

    const validation = validateFileForUpload(file);
    if (!validation.valid) {
      setUploadError(validation.reason ?? 'File not allowed');
      return;
    }

    setIsUploading(true);
    try {
      const vaultKey = getVaultKey();

      // Step 1: compute SHA-256 hash of the raw plaintext bytes
      const rawBuffer = await file.arrayBuffer();
      const hash      = await computeSha256(rawBuffer);

      // Step 2: scan the hash against VirusTotal (hash only — never sends file)
      setUploadStage('scanning');
      const scanResult = await scanFile(hash);

      if (scanResult.status === 'INFECTED') {
        setUploadError(
          `Malware detected: ${scanResult.detections} / ${scanResult.totalEngines} ` +
          `security engines flagged this file. Upload blocked.`,
        );
        return;
      }

      // Step 3: encrypt and upload
      setUploadStage('encrypting');
      const { fileKey, encryptedFileKey } = createFileKey(vaultKey);

      let encryptedBlob: Blob;
      let encryptedMetadata: string;
      try {
        const result  = await encryptFile(fileKey, file);
        encryptedBlob     = result.encryptedBlob;
        encryptedMetadata = result.encryptedMetadata;
      } finally {
        fileKey.fill(0);
      }

      const form = new FormData();
      form.append('file',              encryptedBlob, 'encrypted');
      form.append('encryptedFileKey',  encryptedFileKey);
      form.append('encryptedMetadata', encryptedMetadata);
      form.append('scanStatus',        scanResult.status);
      form.append('scanDetections',    String(scanResult.detections));
      form.append('scanTotalEngines',  String(scanResult.totalEngines));
      if (vaultItemId) form.append('vaultItemId', vaultItemId);

      const res = await fetch('/api/vault/files', {
        method:      'POST',
        body:        form,
        credentials: 'include',
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error((err as { error?: string }).error ?? 'Upload failed');
      }

      const { data } = await res.json();

      const fileInfo: VaultFileInfo = {
        id:            data.file.id,
        metadata: {
          originalName: file.name,
          mimeType:     file.type || 'application/octet-stream',
          originalSize: file.size,
        },
        encryptedSize:    data.file.encryptedSize,
        scanStatus:       (data.file.scanStatus as ScanStatus) ?? scanResult.status,
        scanDetections:   data.file.scanDetections ?? scanResult.detections,
        scanTotalEngines: data.file.scanTotalEngines ?? scanResult.totalEngines,
        createdAt:        new Date(data.file.createdAt),
      };

      onFileUploaded?.(fileInfo);
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Upload failed');
    } finally {
      setIsUploading(false);
      setUploadStage(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) uploadFile(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) uploadFile(file);
  };

  // ── Download ────────────────────────────────────────────────────────────────

  const downloadFile = async (fileId: string, displayName: string) => {
    setDownloadingId(fileId);
    try {
      const vaultKey = getVaultKey();

      const res = await fetch(`/api/vault/files/${fileId}`, { credentials: 'include' });
      if (!res.ok) throw new Error('Download failed');

      const encryptedFileKey  = res.headers.get('X-Encrypted-File-Key');
      const encryptedMetadata = res.headers.get('X-Encrypted-Metadata');
      if (!encryptedFileKey || !encryptedMetadata) throw new Error('Missing encryption headers');

      const fileKey = unwrapFileKey(vaultKey, encryptedFileKey);
      const encryptedData = await res.arrayBuffer();

      let decryptedFile: File;
      try {
        decryptedFile = await decryptFile(fileKey, encryptedData, encryptedMetadata);
      } finally {
        fileKey.fill(0);
      }

      const url = URL.createObjectURL(decryptedFile);
      const a   = document.createElement('a');
      a.href     = url;
      a.download = decryptedFile.name || displayName;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      // Surface download failures visibly
      setUploadError(err instanceof Error ? err.message : 'Download failed');
    } finally {
      setDownloadingId(null);
    }
  };

  // ── Delete ──────────────────────────────────────────────────────────────────

  const deleteFile = async (fileId: string) => {
    if (!confirm('Delete this file? This cannot be undone.')) return;
    setDeletingId(fileId);
    try {
      const res = await fetch(`/api/vault/files/${fileId}`, {
        method:      'DELETE',
        credentials: 'include',
      });
      if (!res.ok) throw new Error('Delete failed');
      onFileDeleted?.(fileId);
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Delete failed');
    } finally {
      setDeletingId(null);
    }
  };

  // ── Upload stage label ─────────────────────────────────────────────────────

  const stageLabel =
    uploadStage === 'scanning'   ? 'Scanning for malware…' :
    uploadStage === 'encrypting' ? 'Encrypting and uploading…' :
    'Processing…';

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-3">
      {/* Existing files */}
      {existingFiles.length > 0 && (
        <ul className="space-y-1.5">
          {existingFiles.map((file) => (
            <li
              key={file.id}
              className="flex items-center justify-between gap-2 bg-aegis-elevated border border-aegis-border rounded-lg px-3 py-2"
            >
              <div className="flex items-center gap-2 min-w-0">
                <FileText className="w-4 h-4 text-aegis-muted flex-shrink-0" />
                <span className="text-sm text-aegis-text truncate">
                  {file.metadata.originalName}
                </span>
                <span className="text-xs text-aegis-muted flex-shrink-0">
                  {formatFileSize(file.metadata.originalSize)}
                </span>
                <ScanBadge
                  status={file.scanStatus}
                  detections={file.scanDetections}
                  totalEngines={file.scanTotalEngines}
                />
              </div>
              <div className="flex items-center gap-1 flex-shrink-0">
                <button
                  onClick={() => downloadFile(file.id, file.metadata.originalName)}
                  disabled={downloadingId === file.id}
                  className="p-1.5 rounded hover:bg-aegis-surface text-aegis-muted hover:text-aegis-text transition-colors"
                  title="Download (decrypted)"
                >
                  {downloadingId === file.id
                    ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    : <Download className="w-3.5 h-3.5" />}
                </button>
                <button
                  onClick={() => deleteFile(file.id)}
                  disabled={deletingId === file.id}
                  className="p-1.5 rounded hover:bg-aegis-danger-muted text-aegis-muted hover:text-aegis-danger transition-colors"
                  title="Delete file"
                >
                  {deletingId === file.id
                    ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    : <Trash2 className="w-3.5 h-3.5" />}
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}

      {/* Upload drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        className={`relative border-2 border-dashed rounded-lg p-4 text-center transition-colors ${
          dragOver
            ? 'border-aegis-accent bg-aegis-accent/5'
            : 'border-aegis-border hover:border-aegis-accent/50'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          onChange={handleFileInput}
          disabled={isUploading}
          className="absolute inset-0 opacity-0 cursor-pointer disabled:cursor-not-allowed"
          aria-label="Upload file"
        />
        <div className="flex flex-col items-center gap-1.5 pointer-events-none">
          {isUploading ? (
            <>
              <Loader2 className="w-5 h-5 text-aegis-accent animate-spin" />
              <p className="text-xs text-aegis-muted">{stageLabel}</p>
            </>
          ) : (
            <>
              <Upload className="w-5 h-5 text-aegis-muted" />
              <p className="text-xs text-aegis-subtle">
                Drop a file or <span className="text-aegis-accent">browse</span>
              </p>
              <div className="flex items-center gap-1 text-xs text-aegis-muted">
                <ShieldCheck className="w-3 h-3" />
                <span>Scanned · Encrypted before upload · Max 50 MB</span>
              </div>
            </>
          )}
        </div>
      </div>

      {uploadError && (
        <div className="flex items-center gap-1.5 text-xs text-aegis-danger bg-aegis-danger-muted border border-aegis-danger/30 rounded-lg px-3 py-2">
          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
          {uploadError}
        </div>
      )}
    </div>
  );
}
