'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Shield, Clock, Key, Download, Upload, Trash2, CheckCircle2,
  AlertTriangle, Loader2, Fingerprint, Plus, Pencil, Smartphone,
  Send, Phone, Copy,
} from 'lucide-react';
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
  const [isLoading, setIsLoading] = useState(true);

  // Export state
  const [isExporting, setIsExporting]   = useState(false);
  const [exportError, setExportError]   = useState<string | null>(null);

  // Import state
  const [isImporting, setIsImporting]     = useState(false);
  const [importError, setImportError]     = useState<string | null>(null);
  const [importSuccess, setImportSuccess] = useState<string | null>(null);
  const importFileRef = useRef<HTMLInputElement>(null);

  // Passkey state
  interface PasskeyCredential {
    id: string;
    name: string;
    deviceType: string;
    backedUp: boolean;
    transports: string[];
    createdAt: string;
    lastUsedAt: string | null;
  }
  const [passkeys, setPasskeys]                     = useState<PasskeyCredential[]>([]);
  const [isRegisteringPasskey, setIsRegisteringPasskey] = useState(false);
  const [passkeyError, setPasskeyError]             = useState<string | null>(null);
  const [deletingPasskeyId, setDeletingPasskeyId]   = useState<string | null>(null);

  // Rename state
  const [renamingId, setRenamingId]       = useState<string | null>(null);
  const [renameValue, setRenameValue]     = useState('');
  const [isSavingRename, setIsSavingRename] = useState(false);

  // Backup Codes state
  const [backupCodesRemaining, setBackupCodesRemaining] = useState<number | null>(null);
  const [isGeneratingCodes, setIsGeneratingCodes]       = useState(false);
  const [newBackupCodes, setNewBackupCodes]             = useState<string[] | null>(null);

  // Telegram state (renamed heading: "Telegram (Optional Recovery)")
  const [telegramEnabled, setTelegramEnabled]               = useState(false);
  const [telegramStep, setTelegramStep]                     = useState<'idle' | 'linking' | 'linked'>('idle');
  const [telegramDeepLink, setTelegramDeepLink]             = useState<string | null>(null);
  const [telegramLinkCode, setTelegramLinkCode]             = useState<string | null>(null);
  const [isRequestingLink, setIsRequestingLink]             = useState(false);
  const [isDisablingTelegram, setIsDisablingTelegram]       = useState(false);
  const [telegramDisableCode, setTelegramDisableCode]       = useState('');
  const [showTelegramDisableForm, setShowTelegramDisableForm] = useState(false);
  const [telegramError, setTelegramError]                   = useState<string | null>(null);
  const [telegramSuccess, setTelegramSuccess]               = useState<string | null>(null);
  const telegramPollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // WhatsApp state
  const [whatsappEnabled, setWhatsappEnabled]                   = useState(false);
  const [whatsappStep, setWhatsappStep]                         = useState<'idle' | 'verify'>('idle');
  const [whatsappPhone, setWhatsappPhone]                       = useState('');
  const [whatsappVerifyCode, setWhatsappVerifyCode]             = useState('');
  const [isWhatsappLoading, setIsWhatsappLoading]               = useState(false);
  const [whatsappError, setWhatsappError]                       = useState<string | null>(null);
  const [whatsappSuccess, setWhatsappSuccess]                   = useState<string | null>(null);
  const [showWhatsappDisableForm, setShowWhatsappDisableForm]   = useState(false);
  const [whatsappDisableCode, setWhatsappDisableCode]           = useState('');
  const [whatsappMaskedPhone, setWhatsappMaskedPhone]           = useState<string | null>(null);

  // ── Data fetching ─────────────────────────────────────────────────────────

  const fetchPasskeys = useCallback(async () => {
    const res = await fetch('/api/auth/webauthn/credentials', { credentials: 'include' });
    if (res.ok) {
      const { data } = await res.json();
      setPasskeys(data.credentials);
    }
  }, []);

  const fetchBackupCodeCount = useCallback(async () => {
    const res = await fetch('/api/auth/backup-codes', { credentials: 'include' });
    if (res.ok) {
      const { data } = await res.json();
      setBackupCodesRemaining(data.remaining ?? null);
    }
  }, []);

  useEffect(() => {
    fetchPasskeys();
    fetchBackupCodeCount();
  }, [fetchPasskeys, fetchBackupCodeCount]);

  useEffect(() => {
    fetch('/api/account/preferences', { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => {
        if (d.success) {
          setLockTimeout(d.data.lockTimeout ?? 300);
          setTelegramEnabled(d.data.telegramEnabled ?? false);
          setWhatsappEnabled(d.data.whatsappEnabled ?? false);
          if (d.data.whatsappMaskedPhone) setWhatsappMaskedPhone(d.data.whatsappMaskedPhone);
        }
      })
      .catch(() => {})
      .finally(() => setIsLoading(false));
  }, []);

  // ── Preferences ──────────────────────────────────────────────────────────

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

      const res = await fetch('/api/vault/export', { credentials: 'include' });
      if (!res.ok) throw new Error('Failed to fetch vault items');
      const { data } = await res.json();
      const encryptedItems: EncryptedVaultItem[] = data.items;

      const decryptedItems: DecryptedVaultItem[] = encryptedItems.map((item) =>
        decryptVaultItem(vaultKey, item),
      );

      const exportPackage: VaultExportPackage = createExportPackage(vaultKey, decryptedItems);

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

      const text = await file.text();
      const pkg: VaultExportPackage = JSON.parse(text);

      const decryptedItems = decryptExportPackage(vaultKey, pkg);

      const reEncryptedItems = decryptedItems.map((item) => {
        const encrypted = encryptVaultItem(
          vaultKey,
          item.itemType,
          item.isFavorite,
          item.isHighRisk,
          item.data,
        );
        return { ...encrypted, isArchived: item.isArchived };
      });

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
      setImportError(
        err instanceof Error
          ? err.message
          : 'Import failed. The file may be corrupted or from a different vault.',
      );
    } finally {
      setIsImporting(false);
      if (importFileRef.current) importFileRef.current.value = '';
    }
  };

  // ── Backup Codes ──────────────────────────────────────────────────────────

  const generateBackupCodes = async () => {
    setIsGeneratingCodes(true);
    try {
      const res = await fetch('/api/auth/backup-codes', {
        method:      'POST',
        credentials: 'include',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Failed to generate backup codes');
      setNewBackupCodes(json.data.codes);
      setBackupCodesRemaining(json.data.remaining ?? 8);
    } catch (err) {
      // Surface error in passkeyError area for simplicity — backup codes live in same security section
      setPasskeyError(err instanceof Error ? err.message : 'Failed to generate backup codes');
    } finally {
      setIsGeneratingCodes(false);
    }
  };

  const copyBackupCodes = () => {
    if (!newBackupCodes) return;
    navigator.clipboard.writeText(newBackupCodes.join('\n')).catch(() => {});
  };

  // ── Passkey management ────────────────────────────────────────────────────

  const registerPasskey = async () => {
    setPasskeyError(null);
    setIsRegisteringPasskey(true);
    try {
      const { startRegistration } = await import('@simplewebauthn/browser');

      const optRes = await fetch('/api/auth/webauthn/register', { method: 'POST', credentials: 'include' });
      if (!optRes.ok) throw new Error('Failed to start passkey registration');
      const { data: optData } = await optRes.json();

      const registrationResponse = await startRegistration({ optionsJSON: optData.options });

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
    if (!confirm("Remove this passkey? You won't be able to sign in with it anymore.")) return;
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
        setPasskeys((prev) => prev.map((p) => (p.id === id ? { ...p, name: trimmed } : p)));
        cancelRename();
      }
    } finally {
      setIsSavingRename(false);
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

      telegramPollingRef.current = setInterval(async () => {
        try {
          const statusRes  = await fetch('/api/auth/mfa/telegram/status', { credentials: 'include' });
          const statusJson = await statusRes.json();
          if (statusJson.data?.linked) {
            if (telegramPollingRef.current) {
              clearInterval(telegramPollingRef.current);
              telegramPollingRef.current = null;
            }
            setTelegramEnabled(true);
            setTelegramStep('linked');
            setTelegramSuccess('Telegram recovery enabled successfully');
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
      if (!res.ok) throw new Error(json.error ?? 'Failed to disable Telegram');
      setTelegramEnabled(false);
      setTelegramStep('idle');
      setShowTelegramDisableForm(false);
      setTelegramDisableCode('');
      setTelegramSuccess('Telegram recovery disabled');
      setTimeout(() => setTelegramSuccess(null), 3000);
    } catch (err) {
      setTelegramError(err instanceof Error ? err.message : 'Failed to disable Telegram');
    } finally {
      setIsDisablingTelegram(false);
    }
  };

  useEffect(() => {
    return () => {
      if (telegramPollingRef.current) clearInterval(telegramPollingRef.current);
    };
  }, []);

  // ── WhatsApp MFA ──────────────────────────────────────────────────────────

  const sendWhatsappCode = async () => {
    setWhatsappError(null);
    if (!whatsappPhone.trim()) {
      setWhatsappError('Please enter your phone number');
      return;
    }
    setIsWhatsappLoading(true);
    try {
      const res = await fetch('/api/auth/mfa/whatsapp/setup', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ phone: whatsappPhone.trim() }),
        credentials: 'include',
      });
      const json = await res.json();
      if (res.status === 503) {
        throw new Error('WhatsApp is not configured on this server');
      }
      if (!res.ok) throw new Error(json.error ?? 'Failed to send verification code');
      setWhatsappStep('verify');
    } catch (err) {
      setWhatsappError(err instanceof Error ? err.message : 'Failed to send verification code');
    } finally {
      setIsWhatsappLoading(false);
    }
  };

  const verifyWhatsappCode = async () => {
    setWhatsappError(null);
    if (!whatsappVerifyCode.trim()) {
      setWhatsappError('Please enter the 6-digit verification code');
      return;
    }
    setIsWhatsappLoading(true);
    try {
      const res = await fetch('/api/auth/mfa/whatsapp/verify', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ code: whatsappVerifyCode.trim() }),
        credentials: 'include',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Verification failed');
      setWhatsappEnabled(true);
      setWhatsappStep('idle');
      setWhatsappVerifyCode('');
      if (json.data?.maskedPhone) setWhatsappMaskedPhone(json.data.maskedPhone);
      setWhatsappSuccess('WhatsApp recovery enabled successfully');
      setTimeout(() => setWhatsappSuccess(null), 3000);
    } catch (err) {
      setWhatsappError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setIsWhatsappLoading(false);
    }
  };

  const disableWhatsapp = async () => {
    setWhatsappError(null);
    if (!whatsappDisableCode.trim()) {
      setWhatsappError('Please enter your current WhatsApp code or password to disable');
      return;
    }
    setIsWhatsappLoading(true);
    try {
      const res = await fetch('/api/auth/mfa/whatsapp/setup', {
        method:  'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ code: whatsappDisableCode.trim() }),
        credentials: 'include',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Failed to disable WhatsApp');
      setWhatsappEnabled(false);
      setShowWhatsappDisableForm(false);
      setWhatsappDisableCode('');
      setWhatsappMaskedPhone(null);
      setWhatsappSuccess('WhatsApp recovery disabled');
      setTimeout(() => setWhatsappSuccess(null), 3000);
    } catch (err) {
      setWhatsappError(err instanceof Error ? err.message : 'Failed to disable WhatsApp');
    } finally {
      setIsWhatsappLoading(false);
    }
  };

  // ── Timeout options ───────────────────────────────────────────────────────

  const timeoutOptions = [
    { label: '1 minute',   value: 60 },
    { label: '5 minutes',  value: 300 },
    { label: '15 minutes', value: 900 },
    { label: '30 minutes', value: 1800 },
    { label: '1 hour',     value: 3600 },
    { label: 'Never',      value: 0 },
  ];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-5 h-5 animate-spin text-aegis-muted" />
      </div>
    );
  }

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-aegis-text">Settings</h1>
        <p className="text-sm text-aegis-muted">Vault and security preferences</p>
      </div>

      {/* ── Auto-Lock ──────────────────────────────────────────────────────── */}
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
              Disabling auto-lock reduces security. Not recommended.
            </p>
          )}
        </div>
        <button onClick={savePreferences} className="aegis-btn-primary flex items-center gap-2 text-sm">
          {saved ? <><CheckCircle2 className="w-4 h-4" /> Saved</> : 'Save Changes'}
        </button>
      </section>

      {/* ── Backup Codes ───────────────────────────────────────────────────── */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Shield className="w-4 h-4 text-aegis-muted" /> Backup Codes
        </h2>
        <p className="text-sm text-aegis-subtle">
          Keep these safe. Use one to regain access if you can&apos;t use your passkey.
        </p>

        {backupCodesRemaining !== null && (
          <p className="text-sm text-aegis-muted">
            {backupCodesRemaining === 0
              ? <span className="text-aegis-warning font-medium">All used — regenerate now</span>
              : <><span className="text-aegis-text font-medium">{backupCodesRemaining}</span> of 8 codes remaining</>}
          </p>
        )}

        {newBackupCodes ? (
          <div className="bg-aegis-elevated border border-aegis-border rounded-lg p-4 space-y-3">
            <div className="grid grid-cols-2 gap-1.5">
              {newBackupCodes.map((code) => (
                <code key={code} className="font-mono text-xs text-aegis-text bg-aegis-surface px-2 py-1 rounded border border-aegis-border tracking-wider">
                  {code}
                </code>
              ))}
            </div>
            <div className="flex items-start gap-2 text-xs text-aegis-warning">
              <AlertTriangle className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
              <span>Save these now — they will not be shown again</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={copyBackupCodes}
                className="aegis-btn-secondary text-sm flex items-center gap-2"
              >
                <Copy className="w-4 h-4" /> Copy all
              </button>
              <button
                type="button"
                onClick={() => setNewBackupCodes(null)}
                className="aegis-btn-primary text-sm"
              >
                I&apos;ve saved my codes
              </button>
            </div>
          </div>
        ) : (
          <button
            type="button"
            onClick={generateBackupCodes}
            disabled={isGeneratingCodes}
            className="aegis-btn-secondary text-sm flex items-center gap-2 disabled:opacity-50"
          >
            {isGeneratingCodes
              ? <><Loader2 className="w-4 h-4 animate-spin" /> Generating…</>
              : <><Key className="w-4 h-4" /> Generate New Codes</>}
          </button>
        )}
      </section>

      {/* ── Passkeys (Primary Authentication) ─────────────────────────────── */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Fingerprint className="w-4 h-4 text-aegis-muted" /> Passkeys (Primary Authentication)
        </h2>
        <p className="text-sm text-aegis-subtle">
          Add a passkey from this device or scan a QR code to register from your phone. Passkeys
          replace the need for codes — they&apos;re faster and more secure.
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

      {/* ── Telegram (Optional Recovery) ──────────────────────────────────── */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Send className="w-4 h-4 text-aegis-muted" /> Telegram (Optional Recovery)
        </h2>
        <p className="text-xs text-aegis-muted">
          Only appears as a recovery option during login if enabled.
        </p>

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
                <p className="text-sm text-aegis-subtle">Telegram Recovery: Enabled</p>
                <p className="text-xs text-aegis-muted mt-0.5">
                  Recovery codes will be delivered to your Telegram
                </p>
              </div>
              <div className="text-xs px-2 py-1 rounded-full border bg-aegis-success-muted border-aegis-success text-aegis-success">
                Enabled
              </div>
            </div>

            {showTelegramDisableForm ? (
              <div className="space-y-2">
                <p className="text-xs text-aegis-muted">
                  Enter your current Telegram code or account password to disable:
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
                Disable Telegram Recovery
              </button>
            )}
          </>
        ) : telegramStep === 'linking' && telegramDeepLink ? (
          <div className="space-y-3">
            <p className="text-sm text-aegis-subtle">Complete the setup in Telegram:</p>
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
            <button onClick={cancelTelegramLink} className="text-xs text-aegis-muted hover:text-aegis-text">
              Cancel
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            <div>
              <p className="text-sm text-aegis-subtle">Enable via Telegram</p>
              <p className="text-xs text-aegis-muted mt-0.5">
                Receive recovery codes via Telegram — free, instant, no phone number needed.
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

      {/* ── WhatsApp (Optional Recovery) ──────────────────────────────────── */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Phone className="w-4 h-4 text-aegis-muted" /> WhatsApp (Optional Recovery)
        </h2>
        <p className="text-xs text-aegis-muted">
          Only appears as a recovery option during login if enabled.
        </p>

        {whatsappError && (
          <div className="flex items-center gap-2 text-xs text-aegis-danger bg-aegis-danger-muted border border-aegis-danger/30 rounded-lg px-3 py-2">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" /> {whatsappError}
          </div>
        )}
        {whatsappSuccess && (
          <div className="flex items-center gap-2 text-xs text-aegis-success bg-aegis-success-muted border border-aegis-success/30 rounded-lg px-3 py-2">
            <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" /> {whatsappSuccess}
          </div>
        )}

        {whatsappEnabled ? (
          <>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-aegis-subtle">WhatsApp Recovery: Enabled</p>
                {whatsappMaskedPhone && (
                  <p className="text-xs text-aegis-muted mt-0.5">Phone: {whatsappMaskedPhone}</p>
                )}
              </div>
              <div className="text-xs px-2 py-1 rounded-full border bg-aegis-success-muted border-aegis-success text-aegis-success">
                Enabled
              </div>
            </div>

            {showWhatsappDisableForm ? (
              <div className="space-y-2">
                <p className="text-xs text-aegis-muted">
                  Enter your current WhatsApp code or account password to disable:
                </p>
                <input
                  type="text"
                  value={whatsappDisableCode}
                  onChange={(e) => setWhatsappDisableCode(e.target.value)}
                  placeholder="Code or password"
                  maxLength={128}
                  className="aegis-input text-sm w-full max-w-xs"
                />
                <div className="flex items-center gap-2">
                  <button
                    onClick={disableWhatsapp}
                    disabled={isWhatsappLoading}
                    className="aegis-btn-ghost text-sm text-aegis-danger hover:bg-aegis-danger-muted flex items-center gap-2"
                  >
                    {isWhatsappLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                    Confirm Disable
                  </button>
                  <button
                    onClick={() => { setShowWhatsappDisableForm(false); setWhatsappDisableCode(''); setWhatsappError(null); }}
                    className="text-xs text-aegis-muted hover:text-aegis-text"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <button
                onClick={() => setShowWhatsappDisableForm(true)}
                className="aegis-btn-ghost text-sm text-aegis-danger hover:bg-aegis-danger-muted"
              >
                Disable WhatsApp Recovery
              </button>
            )}
          </>
        ) : whatsappStep === 'verify' ? (
          <div className="space-y-3">
            <p className="text-sm text-aegis-subtle">
              A 6-digit code was sent to your WhatsApp. Enter it below to activate.
            </p>
            <input
              type="text"
              inputMode="numeric"
              value={whatsappVerifyCode}
              onChange={(e) => setWhatsappVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="000000"
              maxLength={6}
              className="aegis-input text-sm w-40 tracking-widest text-center"
            />
            <div className="flex items-center gap-2">
              <button
                onClick={verifyWhatsappCode}
                disabled={isWhatsappLoading || whatsappVerifyCode.length !== 6}
                className="aegis-btn-primary text-sm flex items-center gap-2 disabled:opacity-50"
              >
                {isWhatsappLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
                Verify
              </button>
              <button
                onClick={() => { setWhatsappStep('idle'); setWhatsappVerifyCode(''); setWhatsappError(null); }}
                className="text-xs text-aegis-muted hover:text-aegis-text"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div>
              <p className="text-sm text-aegis-subtle">Enable via WhatsApp</p>
              <p className="text-xs text-aegis-muted mt-0.5">
                Receive recovery codes via WhatsApp — uses Meta&apos;s free Cloud API.
              </p>
            </div>
            <div className="space-y-2">
              <input
                type="tel"
                value={whatsappPhone}
                onChange={(e) => setWhatsappPhone(e.target.value)}
                placeholder="+1 602 555 1234"
                className="aegis-input text-sm w-full max-w-xs"
              />
              <button
                onClick={sendWhatsappCode}
                disabled={isWhatsappLoading || !whatsappPhone.trim()}
                className="aegis-btn-primary text-sm flex items-center gap-2 disabled:opacity-50"
              >
                {isWhatsappLoading
                  ? <><Loader2 className="w-4 h-4 animate-spin" /> Sending code…</>
                  : <><Phone className="w-4 h-4" /> Send Verification Code</>}
              </button>
            </div>
          </div>
        )}
      </section>

      {/* ── Backup & Export ────────────────────────────────────────────────── */}
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

      {/* ── Import ────────────────────────────────────────────────────────── */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Upload className="w-4 h-4 text-aegis-muted" /> Import
        </h2>
        <p className="text-sm text-aegis-subtle">
          Import a{' '}
          <code className="text-xs font-mono bg-aegis-elevated px-1 py-0.5 rounded">.aegisvault</code>{' '}
          backup file. Items are decrypted and re-encrypted with your current vault key before storage.
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

      {/* ── Danger Zone ────────────────────────────────────────────────────── */}
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
