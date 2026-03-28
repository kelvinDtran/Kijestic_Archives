'use client';

/**
 * FileUpload — Client-side encrypted file upload component
 *
 * Files are encrypted with XChaCha20-Poly1305 BEFORE upload.
 * The server receives only encrypted bytes and never sees the plaintext file,
 * original filename, or MIME type.
 *
 * Upload flow:
 *   1. User selects a file
 *   2. Client validates size/extension
 *   3. Client generates a random file key (DEK)
 *   4. Client encrypts the file + metadata
 *   5. Uploads encrypted blob + wrapped key + encrypted metadata
 *
 * Download flow:
 *   1. Fetch encrypted blob from /api/vault/files/[id]
 *   2. Unwrap file key from X-Encrypted-File-Key header using vault key
 *   3. Decrypt blob to recover original file
 *   4. Trigger browser download
 */

import { useState, useRef } from 'react';
import { Upload, Download, Trash2, FileText, Loader2, AlertTriangle } from 'lucide-react';
import { useVault } from '@/contexts/VaultContext';
import { createFileKey, unwrapFileKey } from '@/lib/crypto/vault-crypto';
import { encryptFile, decryptFile, validateFileForUpload, formatFileSize } from '@/lib/crypto/file-crypto';
import type { VaultFileInfo } from '@/types/vault';

interface FileUploadProps {
  vaultItemId?: string;
  existingFiles?: VaultFileInfo[];
  onFileUploaded?: (file: VaultFileInfo) => void;
  onFileDeleted?: (fileId: string) => void;
}

export function FileUpload({
  vaultItemId,
  existingFiles = [],
  onFileUploaded,
  onFileDeleted,
}: FileUploadProps) {
  const { getVaultKey } = useVault();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [isUploading, setIsUploading]           = useState(false);
  const [uploadError, setUploadError]           = useState<string | null>(null);
  const [downloadingId, setDownloadingId]       = useState<string | null>(null);
  const [deletingId, setDeletingId]             = useState<string | null>(null);
  const [dragOver, setDragOver]                 = useState(false);

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

      // Generate a fresh file key, wrapped with the vault key
      const { fileKey, encryptedFileKey } = createFileKey(vaultKey);

      let encryptedBlob: Blob;
      let encryptedMetadata: string;
      try {
        const result = await encryptFile(fileKey, file);
        encryptedBlob     = result.encryptedBlob;
        encryptedMetadata = result.encryptedMetadata;
      } finally {
        fileKey.fill(0);
      }

      const form = new FormData();
      form.append('file',              encryptedBlob, 'encrypted');
      form.append('encryptedFileKey',  encryptedFileKey);
      form.append('encryptedMetadata', encryptedMetadata);
      if (vaultItemId) form.append('vaultItemId', vaultItemId);

      const res = await fetch('/api/vault/files', {
        method:      'POST',
        body:        form,
        credentials: 'include',
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error ?? 'Upload failed');
      }

      const { data } = await res.json();

      // Build a VaultFileInfo by decrypting the metadata for display
      const fileInfo: VaultFileInfo = {
        id:            data.file.id,
        metadata: {
          originalName: file.name,
          mimeType:     file.type || 'application/octet-stream',
          originalSize: file.size,
        },
        encryptedSize: data.file.encryptedSize,
        createdAt:     new Date(data.file.createdAt),
      };

      onFileUploaded?.(fileInfo);
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Upload failed');
    } finally {
      setIsUploading(false);
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

      // Encrypted keys come back in response headers
      const encryptedFileKey  = res.headers.get('X-Encrypted-File-Key');
      const encryptedMetadata = res.headers.get('X-Encrypted-Metadata');
      if (!encryptedFileKey || !encryptedMetadata) throw new Error('Missing encryption headers');

      // Unwrap the file key and decrypt the content
      const fileKey = unwrapFileKey(vaultKey, encryptedFileKey);
      const encryptedData = await res.arrayBuffer();

      let decryptedFile: File;
      try {
        decryptedFile = await decryptFile(fileKey, encryptedData, encryptedMetadata);
      } finally {
        fileKey.fill(0);
      }

      // Trigger browser download
      const url = URL.createObjectURL(decryptedFile);
      const a   = document.createElement('a');
      a.href     = url;
      a.download = decryptedFile.name || displayName;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('[FileUpload] Download failed:', err);
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
      console.error('[FileUpload] Delete failed:', err);
    } finally {
      setDeletingId(null);
    }
  };

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
              <p className="text-xs text-aegis-muted">Encrypting and uploading…</p>
            </>
          ) : (
            <>
              <Upload className="w-5 h-5 text-aegis-muted" />
              <p className="text-xs text-aegis-subtle">
                Drop a file or <span className="text-aegis-accent">browse</span>
              </p>
              <p className="text-xs text-aegis-muted">Encrypted before upload · Max 50 MB</p>
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
