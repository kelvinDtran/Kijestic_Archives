'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { Shield, Clock, Key, Download, Upload, Trash2, CheckCircle2, AlertTriangle, Loader2, Fingerprint, Plus, Pencil, Smartphone, Mail, Send } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { useVault } from '@/contexts/VaultContext';
import {
  createExportPackage,
  decryptExportPackage,
  decryptVaultItem,
  encryptVaultItem,
  type VaultExportPackage,
} from '@/lib/crypto/vault-crypto';
import type { DecryptedVaultItem, EncryptedVaultItem } from '@/types/vault';

export default function SettingsPage() {
  const { isLocked, getVaultKey } = useVault();
  const [lockTimeout, setLockTimeout] = useState(300);
  const [saved, setSaved] = useState(false);
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Export state
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  // Import state
  const [isImporting, setIsImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [importSuccess, setImportSuccess] = useState<string | null>(null);
  const importFileRef = useRef<HTMLInputElement>(null);

  // Passkey state
  interface PasskeyCredential { id: string; name: string; deviceType: string; backedUp: boolean; transports: string[]; createdAt: string; lastUsedAt: string | null; }
  const [passkeys, setPasskeys] = useState<PasskeyCredential[]>([]);
  const [isRegisteringPasskey, setIsRegisteringPasskey] = useState(false);
  const [passkeyError, setPasskeyError] = useState<string | null>(null);
  const [deletingPasskeyId, setDeletingPasskeyId] = useState<string | null>(null);

  // Rename state
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const [isSavingRename, setIsSavingRename] = useState(false);

  // Telegram MFA state
  const [telegramEnabled, setTelegramEnabled] = useState(false);
  const [telegramStep, setTelegramStep] = useState<'idle' | 'linking' | 'linked'>('idle');
  const [telegramDeepLink, setTelegramDeepLink] = useState<string | null>(null);
  const [telegramLinkCode, setTelegramLinkCode] = useState<string | null>(null);
  const [isRequestingLink, setIsRequestingLink] = useState(false);
  const [isDisablingTelegram, setIsDisablingTelegram] = useState(false);
  const [telegramDisableCode, setTelegramDisableCode] = useState('');
  const [showTelegramDisableForm, setShowTelegramDisableForm] = useState(false);
  const [telegramError, setTelegramError] = useState<string | null>(null);
  const [telegramSuccess, setTelegramSuccess] = useState<string | null>(null);
  const telegramPollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Email MFA state
  const [emailMfaEnabled, setEmailMfaEnabled] = useState(false);
  const [emailMfaStep, setEmailMfaStep] = useState<'idle' | 'verify'>('idle');
  const [emailMfaCode, setEmailMfaCode] = useState('');
  const [isEnablingEmail, setIsEnablingEmail] = useState(false);
  const [isVerifyingEmail, setIsVerifyingEmail] = useState(false);
  const [isDisablingEmail, setIsDisablingEmail] = useState(false);
  const [emailDisableCode, setEmailDisableCode] = useState('');
  const [showEmailDisableForm, setShowEmailDisableForm] = useState(false);
  const [emailMfaError, setEmailMfaError] = useState<string | null>(null);
  const [emailMfaSuccess, setEmailMfaSuccess] = useState<string | null>(null);

  const fetchPasskeys = useCallback(async () => {
    const res = await fetch('/api/auth/webauthn/credentials', { credentials: 'include' });
    if (res.ok) {
      const { data } = await res.json();
      setPasskeys(data.credentials);
    }
  }, []);

  useEffect(() => {
    fetchPasskeys();
  }, [fetchPasskeys]);

  const registerPasskey = async () => {
    setPasskeyError(null);
    setIsRegisteringPasskey(true);
    try {
      const { startRegistration } = await import('@simplewebauthn/browser');

      // 1. Get registration options
      const optRes = await fetch('/api/auth/webauthn/register', { method: 'POST', credentials: 'include' });
      if (!optRes.ok) throw new Error('Failed to start passkey registration');
      const { data: optData } = await optRes.json();

      // 2. Trigger browser passkey creation
      const registrationResponse = await startRegistration({ optionsJSON: optData.options });

      // 3. Verify and store
      const verifyRes = await fetch('/api/auth/webauthn/register/verify', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ response: registrationResponse }),
        credentials: 'include',
      });
      if (!verifyRes.ok) {
        const err = await verifyRes.json().catch(() => ({}));
        throw new Error(err.error ?? 'Passkey registration failed');
      }

      await fetchPasskeys();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Registration failed';
      if (!message.includes('cancelled') && !message.includes('abort')) {
        setPasskeyError(message);
      }
    } finally {
      setIsRegisteringPasskey(false);
    }
  };

  const deletePasskey = async (id: string) => {
    if (!confirm('Remove this passkey? You won\'t be able to sign in with it anymore.')) return;
    setDeletingPasskeyId(id);
    try {
      await fetch(`/api/auth/webauthn/credentials/${id}`, { method: 'DELETE', credentials: 'include' });
      setPasskeys((prev) => prev.filter((p) => p.id !== id));
    } finally {
      setDeletingPasskeyId(null);
    }
  };

  const startRename = (pk: PasskeyCredential) => {
    setRenamingId(pk.id);
    setRenameValue(pk.name);
  };

  const cancelRename = () => {
    setRenamingId(null);
    setRenameValue('');
  };

  const saveRename = async (id: string) => {
    const trimmed = renameValue.trim();
    if (!trimmed) return;
    setIsSavingRename(true);
    try {
      const res = await fetch(`/api/auth/webauthn/credentials/${id}`, {
        method:  'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ name: trimmed }),
        credentials: 'include',
      });
      if (res.ok) {
        setPasskeys((prev) => prev.map((p) => p.id === id ? { ...p, name: trimmed } : p));
        cancelRename();
      }
    } finally {
      setIsSavingRename(false);
    }
  };

  useEffect(() => {
    fetch('/api/account/preferences', { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => {
        if (d.success) {
          setLockTimeout(d.data.lockTimeout ?? 300);
          setMfaEnabled(d.data.totpEnabled ?? false);
          setTelegramEnabled(d.data.telegramEnabled ?? false);
          setEmailMfaEnabled(d.data.emailMfaEnabled ?? false);
        }
      })
      .catch(() => {})
      .finally(() => setIsLoading(false));
  }, []);

  const savePreferences = async () => {
    await fetch('/api/account/preferences', {
      method:  'PUT',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ lockTimeout }),
      credentials: 'include',
    });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  // ── Export ────────────────────────────────────────────────────────────────

  const handleExport = async () => {
    setIsExporting(true);
    setExportError(null);
    try {
      const vaultKey = getVaultKey();

      // 1. Fetch all encrypted items from server
      const res = await fetch('/api/vault/export', { credentials: 'include' });
      if (!res.ok) throw new Error('Failed to fetch vault items');
      const { data } = await res.json();
      const encryptedItems: EncryptedVaultItem[] = data.items;

      // 2. Decrypt all items client-side
      const decryptedItems: DecryptedVaultItem[] = encryptedItems.map((item) =>
        decryptVaultItem(vaultKey, item),
      );

      // 3. Re-package with a fresh export key
      const exportPackage: VaultExportPackage = createExportPackage(vaultKey, decryptedItems);

      // 4. Trigger download
      const blob = new Blob([JSON.stringify(exportPackage, null, 2)], { type: 'application/json' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `aegisvault-backup-${new Date().toISOString().slice(0, 10)}.aegisvault`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : 'Export failed');
    } finally {
      setIsExporting(false);
    }
  };

  // ── Import ────────────────────────────────────────────────────────────────

  const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsImporting(true);
    setImportError(null);
    setImportSuccess(null);

    try {
      const vaultKey = getVaultKey();

      // 1. Read the file
      const text = await file.text();
      const pkg: VaultExportPackage = JSON.parse(text);

      // 2. Decrypt the export package client-side
      const decryptedItems = decryptExportPackage(vaultKey, pkg);

      // 3. Re-encrypt each item with the current vault key (fresh DEK per item)
      const reEncryptedItems = decryptedItems.map((item) => {
        const encrypted = encryptVaultItem(
          vaultKey,
          item.itemType,
          item.isFavorite,
          item.isHighRisk,
          item.data,
        );
        return {
          ...encrypted,
          isArchived: item.isArchived,
        };
      });

      // 4. Send to import API
      const res = await fetch('/api/vault/import', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ items: reEncryptedItems }),
        credentials: 'include',
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error ?? 'Import failed');
      }

      const { data } = await res.json();
      setImportSuccess(`Successfully imported ${data.imported} item${data.imported !== 1 ? 's' : ''}.`);
    } catch (err) {
      setImportError(err instanceof Error ? err.message : 'Import failed. The file may be corrupted or from a different vault.');
    } finally {
      setIsImporting(false);
      // Reset the file input so the same file can be re-selected if needed
      if (importFileRef.current) importFileRef.current.value = '';
    }
  };

  // ── Telegram MFA ──────────────────────────────────────────────────────────

  const startTelegramLink = async () => {
    setTelegramError(null);
    setIsRequestingLink(true);
    try {
      const res = await fetch('/api/auth/mfa/telegram/link', {
        method:      'POST',
        credentials: 'include',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Failed to generate link code');
      setTelegramDeepLink(json.data.deepLink);
      setTelegramLinkCode(json.data.linkCode);
      setTelegramStep('linking');

      // Start polling for link completion
      telegramPollingRef.current = setInterval(async () => {
        try {
          const statusRes = await fetch('/api/auth/mfa/telegram/status', { credentials: 'include' });
          const statusJson = await statusRes.json();
          if (statusJson.data?.linked) {
            if (telegramPollingRef.current) {
              clearInterval(telegramPollingRef.current);
              telegramPollingRef.current = null;
            }
            setTelegramEnabled(true);
            setTelegramStep('linked');
            setTelegramSuccess('Telegram MFA enabled successfully');
            setTimeout(() => setTelegramSuccess(null), 3000);
          }
        } catch {
          // Non-critical polling error — keep trying
        }
      }, 2000);
    } catch (err) {
      setTelegramError(err instanceof Error ? err.message : 'Failed to generate link code');
    } finally {
      setIsRequestingLink(false);
    }
  };

  const cancelTelegramLink = () => {
    if (telegramPollingRef.current) {
      clearInterval(telegramPollingRef.current);
      telegramPollingRef.current = null;
    }
    setTelegramStep('idle');
    setTelegramDeepLink(null);
    setTelegramLinkCode(null);
    setTelegramError(null);
  };

  const disableTelegram = async () => {
    setTelegramError(null);
    if (!telegramDisableCode.trim()) {
      setTelegramError('Please enter your current Telegram code or password to disable');
      return;
    }
    setIsDisablingTelegram(true);
    try {
      const res = await fetch('/api/auth/mfa/telegram/setup', {
        method:  'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ code: telegramDisableCode.trim() }),
        credentials: 'include',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Failed to disable Telegram MFA');
      setTelegramEnabled(false);
      setTelegramStep('idle');
      setShowTelegramDisableForm(false);
      setTelegramDisableCode('');
      setTelegramSuccess('Telegram MFA disabled');
      setTimeout(() => setTelegramSuccess(null), 3000);
    } catch (err) {
      setTelegramError(err instanceof Error ? err.message : 'Failed to disable Telegram MFA');
    } finally {
      setIsDisablingTelegram(false);
    }
  };

  // Clean up polling interval on unmount
  useEffect(() => {
    return () => {
      if (telegramPollingRef.current) {
        clearInterval(telegramPollingRef.current);
      }
    };
  }, []);

  // ── Email MFA ─────────────────────────────────────────────────────────────

  const enableEmailMfa = async () => {
    setEmailMfaError(null);
    setIsEnablingEmail(true);
    try {
      const res = await fetch('/api/auth/mfa/email/setup', {
        method: 'POST',
        credentials: 'include',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Failed to send verification code');
      setEmailMfaStep('verify');
    } catch (err) {
      setEmailMfaError(err instanceof Error ? err.message : 'Failed to send verification code');
    } finally {
      setIsEnablingEmail(false);
    }
  };

  const verifyEmailMfa = async () => {
    setEmailMfaError(null);
    if (!emailMfaCode.trim()) {
      setEmailMfaError('Please enter the 6-digit code');
      return;
    }
    setIsVerifyingEmail(true);
    try {
      const res = await fetch('/api/auth/mfa/email/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: emailMfaCode.trim() }),
        credentials: 'include',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Verification failed');
      setEmailMfaEnabled(true);
      setEmailMfaStep('idle');
      setEmailMfaCode('');
      setEmailMfaSuccess('Email MFA enabled successfully');
      setTimeout(() => setEmailMfaSuccess(null), 3000);
    } catch (err) {
      setEmailMfaError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setIsVerifyingEmail(false);
    }
  };

  const disableEmailMfa = async () => {
    setEmailMfaError(null);
    if (!emailDisableCode.trim()) {
      setEmailMfaError('Please enter your current email code or password to disable');
      return;
    }
    setIsDisablingEmail(true);
    try {
      const res = await fetch('/api/auth/mfa/email/setup', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: emailDisableCode.trim() }),
        credentials: 'include',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Failed to disable Email MFA');
      setEmailMfaEnabled(false);
      setShowEmailDisableForm(false);
      setEmailDisableCode('');
      setEmailMfaSuccess('Email MFA disabled');
      setTimeout(() => setEmailMfaSuccess(null), 3000);
    } catch (err) {
      setEmailMfaError(err instanceof Error ? err.message : 'Failed to disable Email MFA');
    } finally {
      setIsDisablingEmail(false);
    }
  };

  const timeoutOptions = [
    { label: '1 minute',   value: 60 },
    { label: '5 minutes',  value: 300 },
    { label: '15 minutes', value: 900 },
    { label: '30 minutes', value: 1800 },
    { label: '1 hour',     value: 3600 },
    { label: 'Never',      value: 0 },
  ];

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-aegis-text">Settings</h1>
        <p className="text-sm text-aegis-muted">Vault and security preferences</p>
      </div>

      {/* Vault lock settings */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Clock className="w-4 h-4 text-aegis-muted" /> Auto-Lock
        </h2>
        <div>
          <label className="block text-sm text-aegis-subtle mb-2">
            Lock vault after inactivity
          </label>
          <select
            value={lockTimeout}
            onChange={(e) => setLockTimeout(Number(e.target.value))}
            className="aegis-input w-auto"
          >
            {timeoutOptions.map(({ label, value }) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
          {lockTimeout === 0 && (
            <p className="text-xs text-aegis-warning mt-1.5">
              ⚠️ Disabling auto-lock reduces security. Not recommended.
            </p>
          )}
        </div>
        <button onClick={savePreferences} className="aegis-btn-primary flex items-center gap-2 text-sm">
          {saved ? <><CheckCircle2 className="w-4 h-4" /> Saved</> : 'Save Changes'}
        </button>
      </section>

      {/* MFA */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Shield className="w-4 h-4 text-aegis-muted" /> Two-Factor Authentication
        </h2>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-aegis-subtle">Authenticator App (TOTP)</p>
            <p className="text-xs text-aegis-muted mt-0.5">
              {mfaEnabled ? 'MFA is enabled on your account' : 'Add an extra layer of login security'}
            </p>
          </div>
          <div className={`text-xs px-2 py-1 rounded-full border ${mfaEnabled ? 'bg-aegis-success-muted border-aegis-success text-aegis-success' : 'bg-aegis-elevated border-aegis-border text-aegis-muted'}`}>
            {mfaEnabled ? 'Enabled' : 'Disabled'}
          </div>
        </div>
        {mfaEnabled ? (
          <button className="aegis-btn-ghost text-sm text-aegis-danger hover:bg-aegis-danger-muted">
            Disable MFA
          </button>
        ) : (
          <a href="/api/auth/mfa/setup" className="aegis-btn-primary inline-flex items-center gap-2 text-sm">
            <Key className="w-4 h-4" /> Enable MFA
          </a>
        )}
      </section>

      {/* Telegram MFA */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Send className="w-4 h-4 text-aegis-muted" /> Telegram Two-Factor Authentication
        </h2>

        {telegramError && (
          <div className="flex items-center gap-2 text-xs text-aegis-danger bg-aegis-danger-muted border border-aegis-danger/30 rounded-lg px-3 py-2">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" /> {telegramError}
          </div>
        )}
        {telegramSuccess && (
          <div className="flex items-center gap-2 text-xs text-aegis-success bg-aegis-success-muted border border-aegis-success/30 rounded-lg px-3 py-2">
            <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" /> {telegramSuccess}
          </div>
        )}

        {telegramEnabled ? (
          <>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-aegis-subtle">Telegram MFA: Enabled</p>
                <p className="text-xs text-aegis-muted mt-0.5">
                  Login codes will be delivered to your Telegram
                </p>
              </div>
              <div className="text-xs px-2 py-1 rounded-full border bg-aegis-success-muted border-aegis-success text-aegis-success">
                Enabled
              </div>
            </div>

            {showTelegramDisableForm ? (
              <div className="space-y-2">
                <p className="text-xs text-aegis-muted">
                  Enter your current Telegram code or account password to disable Telegram MFA:
                </p>
                <input
                  type="text"
                  value={telegramDisableCode}
                  onChange={(e) => setTelegramDisableCode(e.target.value)}
                  placeholder="Code or password"
                  maxLength={128}
                  className="aegis-input text-sm w-full max-w-xs"
                />
                <div className="flex items-center gap-2">
                  <button
                    onClick={disableTelegram}
                    disabled={isDisablingTelegram}
                    className="aegis-btn-ghost text-sm text-aegis-danger hover:bg-aegis-danger-muted flex items-center gap-2"
                  >
                    {isDisablingTelegram ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                    Confirm Disable
                  </button>
                  <button
                    onClick={() => { setShowTelegramDisableForm(false); setTelegramDisableCode(''); setTelegramError(null); }}
                    className="text-xs text-aegis-muted hover:text-aegis-text"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <button
                onClick={() => setShowTelegramDisableForm(true)}
                className="aegis-btn-ghost text-sm text-aegis-danger hover:bg-aegis-danger-muted"
              >
                Disable Telegram MFA
              </button>
            )}
          </>
        ) : telegramStep === 'linking' && telegramDeepLink ? (
          <div className="space-y-3">
            <p className="text-sm text-aegis-subtle">
              Complete the setup in Telegram:
            </p>
            <ol className="space-y-2 text-sm text-aegis-muted list-decimal list-inside">
              <li>Tap the button below to open Telegram:</li>
            </ol>
            <a
              href={telegramDeepLink}
              target="_blank"
              rel="noopener noreferrer"
              className="aegis-btn-primary text-sm inline-flex items-center gap-2"
            >
              <Send className="w-4 h-4" /> Open in Telegram
            </a>
            <p className="text-xs text-aegis-muted">2. Send the message and return here.</p>
            <div className="flex items-center gap-2 text-xs text-aegis-muted">
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              <span>Checking for confirmation…</span>
            </div>
            {telegramLinkCode && (
              <p className="text-xs text-aegis-muted">
                Or copy the link code:{' '}
                <code className="font-mono bg-aegis-elevated px-1 py-0.5 rounded text-aegis-subtle">
                  {telegramLinkCode}
                </code>
              </p>
            )}
            <button
              onClick={cancelTelegramLink}
              className="text-xs text-aegis-muted hover:text-aegis-text"
            >
              Cancel
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            <div>
              <p className="text-sm text-aegis-subtle">Enable via Telegram</p>
              <p className="text-xs text-aegis-muted mt-0.5">
                Receive login codes via Telegram — free, instant, no phone number needed.
              </p>
            </div>
            <button
              onClick={startTelegramLink}
              disabled={isRequestingLink}
              className="aegis-btn-primary text-sm flex items-center gap-2 disabled:opacity-50"
            >
              {isRequestingLink
                ? <><Loader2 className="w-4 h-4 animate-spin" /> Generating link…</>
                : <><Send className="w-4 h-4" /> Enable via Telegram</>}
            </button>
          </div>
        )}
      </section>

      {/* Email MFA */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Mail className="w-4 h-4 text-aegis-muted" /> Email Two-Factor Authentication
        </h2>

        {emailMfaError && (
          <div className="flex items-center gap-2 text-xs text-aegis-danger bg-aegis-danger-muted border border-aegis-danger/30 rounded-lg px-3 py-2">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" /> {emailMfaError}
          </div>
        )}
        {emailMfaSuccess && (
          <div className="flex items-center gap-2 text-xs text-aegis-success bg-aegis-success-muted border border-aegis-success/30 rounded-lg px-3 py-2">
            <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" /> {emailMfaSuccess}
          </div>
        )}

        {emailMfaEnabled ? (
          <>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-aegis-subtle">Email MFA: Enabled</p>
                <p className="text-xs text-aegis-muted mt-0.5">
                  A one-time code is sent to your account email during login
                </p>
              </div>
              <div className="text-xs px-2 py-1 rounded-full border bg-aegis-success-muted border-aegis-success text-aegis-success">
                Enabled
              </div>
            </div>

            {showEmailDisableForm ? (
              <div className="space-y-2">
                <p className="text-xs text-aegis-muted">
                  Enter your current email code or account password to disable Email MFA:
                </p>
                <input
                  type="text"
                  value={emailDisableCode}
                  onChange={(e) => setEmailDisableCode(e.target.value)}
                  placeholder="Code or password"
                  maxLength={128}
                  className="aegis-input text-sm w-full max-w-xs"
                />
                <div className="flex items-center gap-2">
                  <button
                    onClick={disableEmailMfa}
                    disabled={isDisablingEmail}
                    className="aegis-btn-ghost text-sm text-aegis-danger hover:bg-aegis-danger-muted flex items-center gap-2"
                  >
                    {isDisablingEmail ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                    Confirm Disable
                  </button>
                  <button
                    onClick={() => { setShowEmailDisableForm(false); setEmailDisableCode(''); setEmailMfaError(null); }}
                    className="text-xs text-aegis-muted hover:text-aegis-text"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <button
                onClick={() => setShowEmailDisableForm(true)}
                className="aegis-btn-ghost text-sm text-aegis-danger hover:bg-aegis-danger-muted"
              >
                Disable Email MFA
              </button>
            )}
          </>
        ) : emailMfaStep === 'verify' ? (
          <div className="space-y-3">
            <p className="text-sm text-aegis-subtle">
              A 6-digit code was sent to your account email. Enter it below to activate Email MFA.
            </p>
            <input
              type="text"
              value={emailMfaCode}
              onChange={(e) => setEmailMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="123456"
              maxLength={6}
              className="aegis-input text-sm w-40 tracking-widest text-center"
            />
            <div className="flex items-center gap-2">
              <button
                onClick={verifyEmailMfa}
                disabled={isVerifyingEmail || emailMfaCode.length !== 6}
                className="aegis-btn-primary text-sm flex items-center gap-2 disabled:opacity-50"
              >
                {isVerifyingEmail ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
                Verify
              </button>
              <button
                onClick={() => { setEmailMfaStep('idle'); setEmailMfaCode(''); setEmailMfaError(null); }}
                className="text-xs text-aegis-muted hover:text-aegis-text"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div>
              <p className="text-sm text-aegis-subtle">Enable Email MFA</p>
              <p className="text-xs text-aegis-muted mt-0.5">
                Receive a one-time code at your account email during login
              </p>
            </div>
            <button
              onClick={enableEmailMfa}
              disabled={isEnablingEmail}
              className="aegis-btn-primary text-sm flex items-center gap-2 disabled:opacity-50"
            >
              {isEnablingEmail
                ? <><Loader2 className="w-4 h-4 animate-spin" /> Sending code…</>
                : <><Mail className="w-4 h-4" /> Enable Email MFA</>}
            </button>
          </div>
        )}
      </section>

      {/* Passkeys */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Fingerprint className="w-4 h-4 text-aegis-muted" /> Passkeys
        </h2>
        <p className="text-sm text-aegis-subtle">
          Sign in with your device biometrics or hardware security key — no password required.
        </p>

        {/* Cross-device info banner */}
        <div className="flex gap-2.5 bg-aegis-elevated border border-aegis-border rounded-lg px-3 py-2.5">
          <Smartphone className="w-4 h-4 text-aegis-muted flex-shrink-0 mt-0.5" />
          <p className="text-xs text-aegis-muted leading-relaxed">
            When adding a passkey, your browser will offer options including scanning a QR code
            with your phone. This allows you to authenticate from your phone even on a shared
            computer. You can add a passkey from this device (fingerprint / Face ID) or from
            your phone — the browser will show both options automatically.
          </p>
        </div>

        {passkeyError && (
          <div className="flex items-center gap-2 text-xs text-aegis-danger bg-aegis-danger-muted border border-aegis-danger/30 rounded-lg px-3 py-2">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" /> {passkeyError}
          </div>
        )}

        {passkeys.length > 0 && (
          <ul className="space-y-2">
            {passkeys.map((pk) => (
              <li key={pk.id} className="bg-aegis-elevated border border-aegis-border rounded-lg px-3 py-2">
                {renamingId === pk.id ? (
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      value={renameValue}
                      onChange={(e) => setRenameValue(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') saveRename(pk.id);
                        if (e.key === 'Escape') cancelRename();
                      }}
                      maxLength={64}
                      autoFocus
                      className="aegis-input text-sm flex-1 h-7 py-0"
                    />
                    <button
                      onClick={() => saveRename(pk.id)}
                      disabled={isSavingRename || !renameValue.trim()}
                      className="text-xs text-aegis-accent hover:text-aegis-accent/80 disabled:opacity-50 flex-shrink-0"
                    >
                      {isSavingRename ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Save'}
                    </button>
                    <button
                      onClick={cancelRename}
                      className="text-xs text-aegis-muted hover:text-aegis-text flex-shrink-0"
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <p className="text-sm text-aegis-text truncate">{pk.name}</p>
                      <p className="text-xs text-aegis-muted">
                        {pk.transports?.includes('hybrid')
                          ? 'Phone / Cross-Device'
                          : pk.deviceType === 'multiDevice'
                            ? 'Synced passkey'
                            : 'Device-bound key'}
                        {pk.backedUp && ' · backed up'}
                        {' · '}
                        {pk.lastUsedAt
                          ? `used ${formatDistanceToNow(new Date(pk.lastUsedAt), { addSuffix: true })}`
                          : `added ${formatDistanceToNow(new Date(pk.createdAt), { addSuffix: true })}`}
                      </p>
                    </div>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <button
                        onClick={() => startRename(pk)}
                        className="p-1.5 text-aegis-muted hover:text-aegis-text transition-colors"
                        title="Rename passkey"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => deletePasskey(pk.id)}
                        disabled={deletingPasskeyId === pk.id}
                        className="p-1.5 text-aegis-muted hover:text-aegis-danger transition-colors"
                        title="Remove passkey"
                      >
                        {deletingPasskeyId === pk.id
                          ? <Loader2 className="w-4 h-4 animate-spin" />
                          : <Trash2 className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}

        <div className="space-y-1.5">
          <button
            onClick={registerPasskey}
            disabled={isRegisteringPasskey}
            className="aegis-btn-secondary text-sm flex items-center gap-2"
          >
            {isRegisteringPasskey
              ? <><Loader2 className="w-4 h-4 animate-spin" /> Waiting for passkey…</>
              : <><Plus className="w-4 h-4" /> Add Passkey</>}
          </button>
          {isRegisteringPasskey && (
            <p className="text-xs text-aegis-muted">
              Follow the browser prompt — you can use this device or scan the QR code with your phone.
            </p>
          )}
        </div>
      </section>

      {/* Backup & Export */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Download className="w-4 h-4 text-aegis-muted" /> Backup & Export
        </h2>
        <p className="text-sm text-aegis-subtle">
          Export an encrypted backup of your entire vault. The file is protected by
          your master password — without it, the file cannot be decrypted.
        </p>

        {exportError && (
          <div className="flex items-center gap-2 text-xs text-aegis-danger bg-aegis-danger-muted border border-aegis-danger/30 rounded-lg px-3 py-2">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
            {exportError}
          </div>
        )}

        <div className="flex items-center gap-3">
          <button
            onClick={handleExport}
            disabled={isLocked || isExporting}
            className="aegis-btn-primary text-sm flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            title={isLocked ? 'Unlock vault to export' : 'Export encrypted vault'}
          >
            {isExporting
              ? <><Loader2 className="w-4 h-4 animate-spin" /> Exporting…</>
              : <><Download className="w-4 h-4" /> Export Encrypted Vault</>}
          </button>
          {isLocked && <p className="text-xs text-aegis-muted">Unlock vault to export</p>}
        </div>
      </section>

      {/* Import */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Upload className="w-4 h-4 text-aegis-muted" /> Import
        </h2>
        <p className="text-sm text-aegis-subtle">
          Import a <code className="text-xs font-mono bg-aegis-elevated px-1 py-0.5 rounded">.aegisvault</code> backup
          file. Items are decrypted and re-encrypted with your current vault key before storage.
        </p>

        {importError && (
          <div className="flex items-center gap-2 text-xs text-aegis-danger bg-aegis-danger-muted border border-aegis-danger/30 rounded-lg px-3 py-2">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
            {importError}
          </div>
        )}
        {importSuccess && (
          <div className="flex items-center gap-2 text-xs text-aegis-success bg-aegis-success-muted border border-aegis-success/30 rounded-lg px-3 py-2">
            <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" />
            {importSuccess}
          </div>
        )}

        <div className="flex items-center gap-3">
          <input
            ref={importFileRef}
            type="file"
            accept=".aegisvault,application/json"
            onChange={handleImportFile}
            disabled={isLocked || isImporting}
            className="hidden"
            id="import-file-input"
          />
          <label
            htmlFor="import-file-input"
            className={`aegis-btn-secondary text-sm flex items-center gap-2 cursor-pointer ${isLocked || isImporting ? 'opacity-50 cursor-not-allowed pointer-events-none' : ''}`}
            title={isLocked ? 'Unlock vault to import' : 'Select .aegisvault file'}
          >
            {isImporting
              ? <><Loader2 className="w-4 h-4 animate-spin" /> Importing…</>
              : <><Upload className="w-4 h-4" /> Select .aegisvault File</>}
          </label>
          {isLocked && <p className="text-xs text-aegis-muted">Unlock vault to import</p>}
        </div>
      </section>

      {/* Danger zone */}
      <section className="aegis-card border-aegis-danger/30 space-y-4">
        <h2 className="text-sm font-semibold text-aegis-danger flex items-center gap-2">
          <Trash2 className="w-4 h-4" /> Danger Zone
        </h2>
        <div>
          <p className="text-sm text-aegis-subtle mb-2">Delete Account</p>
          <p className="text-xs text-aegis-muted mb-3">
            Permanently deletes your account and all encrypted vault data. This cannot be undone.
          </p>
          <button className="aegis-btn-ghost text-aegis-danger hover:bg-aegis-danger-muted text-sm border border-aegis-danger/30">
            Delete Account Permanently
          </button>
        </div>
      </section>
    </div>
  );
}
